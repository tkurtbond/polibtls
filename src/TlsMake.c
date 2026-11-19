/* TlsMake.c -- the C part of module TlsMake (polibtls).

   Private keys and certificates made with libcrypto, the one libtls
   itself uses, which the makefile links by its path (PLAN.md, "Making
   keys and certificates"). Only calls that OpenSSL 3 and LibreSSL both
   have: EVP_PKEY_Q_keygen, for one, is OpenSSL 3's alone.

   Every libcrypto object lives within one call, so nothing outlives
   it, and a private key goes from libcrypto to a file and never through
   Oberon memory. A call returns 1, or 0 with a message in err (errlen
   bytes, 0X-terminated): what failed, then libcrypto's reason or the
   system's. Strings come from Oberon 0X-terminated and are only read.
   Every function takes and returns only int32_t, int64_t and intptr_t.

   The functions are labelled TlsMake.-<name>, so they can't collide
   with C names. */

#include <errno.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/objects.h>
#include <openssl/opensslv.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#define NAME(n) __asm__("TlsMake.-" n)

int32_t tlsmake_key(intptr_t file, int32_t bits, intptr_t err, int64_t errlen) NAME("key");
int32_t tlsmake_cert(intptr_t keyfile, intptr_t certfile, intptr_t cn, intptr_t names,
	int32_t ca, int64_t notbefore, int64_t notafter, intptr_t cacertfile,
	intptr_t cakeyfile, intptr_t err, int64_t errlen) NAME("cert");

/* Where a call's message goes. */
struct out {
	char *buf;
	size_t len;
};

static void vsay(struct out *o, const char *why, const char *fmt, va_list ap)
{
	size_t n;

	if (o->len == 0)
		return;
	vsnprintf(o->buf, o->len, fmt, ap);
	n = strlen(o->buf);
	if (why != NULL && n < o->len)
		snprintf(o->buf + n, o->len - n, ": %s", why);
}

/* A message alone. */
static int say(struct out *o, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsay(o, NULL, fmt, ap);
	va_end(ap);
	return 0;
}

/* A message and errno's reason. */
static int sys(struct out *o, const char *fmt, ...)
{
	va_list ap;
	int e = errno;

	va_start(ap, fmt);
	vsay(o, strerror(e), fmt, ap);
	va_end(ap);
	return 0;
}

/* A message and libcrypto's reason: the first error queued, which is
   where the failure began, as "library: reason". */
static int crypto(struct out *o, const char *fmt, ...)
{
	va_list ap;
	unsigned long e = ERR_peek_error();
	const char *lib, *reason;
	char why[256];

	if (e == 0)
		snprintf(why, sizeof why, "no reason given");
	else {
		lib = ERR_lib_error_string(e);
		reason = ERR_reason_error_string(e);
		if (reason == NULL)
			ERR_error_string_n(e, why, sizeof why);
		else if (lib == NULL)
			snprintf(why, sizeof why, "%s", reason);
		else
			snprintf(why, sizeof why, "%s: %s", lib, reason);
	}
	va_start(ap, fmt);
	vsay(o, why, fmt, ap);
	va_end(ap);
	return 0;
}

/* Whether the libcrypto loaded is the one the headers describe, by name
   and major version ("OpenSSL 3", "LibreSSL 4"): libtls's -I could
   have found another's headers (PLAN.md, "Making keys and
   certificates"). A patch release, after a system update, is the same. */
static int same_library(struct out *o)
{
	const char *built = OPENSSL_VERSION_TEXT;
	const char *running = OpenSSL_version(OPENSSL_VERSION);
	size_t n = strcspn(built, ".");

	if (running == NULL || strncmp(built, running, n) != 0 || running[n] != '.')
		return say(o, "libcrypto is %s, but polibtls was built with the headers of %s",
		    running == NULL ? "unknown" : running, built);
	return 1;
}

/* A passphrase callback giving none, so that an encrypted key fails
   instead of libcrypto's default asking on the terminal. */
static int no_passphrase(char *buf, int size, int rwflag, void *u)
{
	(void)buf; (void)size; (void)rwflag; (void)u;
	return -1;
}

static EVP_PKEY *read_key(struct out *o, const char *file)
{
	FILE *f;
	EVP_PKEY *k;

	if ((f = fopen(file, "r")) == NULL) {
		sys(o, "cannot read key file '%s'", file);
		return NULL;
	}
	k = PEM_read_PrivateKey(f, NULL, no_passphrase, NULL);
	fclose(f);
	if (k == NULL)
		crypto(o, "no unencrypted private key in '%s'", file);
	return k;
}

static X509 *read_cert(struct out *o, const char *file)
{
	FILE *f;
	X509 *x;

	if ((f = fopen(file, "r")) == NULL) {
		sys(o, "cannot read certificate file '%s'", file);
		return NULL;
	}
	x = PEM_read_X509(f, NULL, no_passphrase, NULL);
	fclose(f);
	if (x == NULL)
		crypto(o, "no certificate in '%s'", file);
	return x;
}

static int write_key(FILE *f, void *k)
{
	return PEM_write_PrivateKey(f, (EVP_PKEY *)k, NULL, NULL, 0, NULL, NULL);
}

static int write_cert(FILE *f, void *x)
{
	return PEM_write_X509(f, (X509 *)x);
}

/* Writes path, as what ("key file"), with write, into a temporary file
   beside it, mode mode, synced, then gives it path's name: by link if
   keep, which fails if path exists, else by rename, which replaces
   it. A failure leaves no file behind. */
static int write_file(struct out *o, const char *path, const char *what, mode_t mode,
    int keep, int (*write)(FILE *, void *), void *arg)
{
	size_t n = strlen(path);
	char *tmp;
	int fd, ok = 0;
	FILE *f;

	if ((tmp = malloc(n + 8)) == NULL)
		return sys(o, "cannot write %s '%s'", what, path);
	memcpy(tmp, path, n);
	memcpy(tmp + n, ".XXXXXX", 8);
	/* mkstemp makes it 0600 and exclusively, so a key is never
	   readable by others, even for a moment. */
	if ((fd = mkstemp(tmp)) < 0) {
		sys(o, "cannot write %s '%s'", what, path);
		free(tmp);
		return 0;
	}
	if ((f = fdopen(fd, "w")) == NULL) {
		sys(o, "cannot write %s '%s'", what, path);
		close(fd);
		goto out;
	}
	if (fchmod(fd, mode) != 0) {
		sys(o, "cannot write %s '%s'", what, path);
		fclose(f);
		goto out;
	}
	if (!write(f, arg)) {
		crypto(o, "cannot write %s '%s'", what, path);
		fclose(f);
		goto out;
	}
	if (fflush(f) != 0 || fsync(fd) != 0) {
		sys(o, "cannot write %s '%s'", what, path);
		fclose(f);
		goto out;
	}
	if (fclose(f) != 0) {
		sys(o, "cannot write %s '%s'", what, path);
		goto out;
	}
	if (keep ? link(tmp, path) != 0 : rename(tmp, path) != 0) {
		sys(o, "cannot write %s '%s'", what, path);
		goto out;
	}
	ok = 1;
out:
	/* After a rename, tmp names nothing, and unlink does nothing. */
	if (!ok || keep)
		unlink(tmp);
	free(tmp);
	return ok;
}

/* A key into file: EC P-256 if bits is 0, else RSA of bits. */
int32_t tlsmake_key(intptr_t file, int32_t bits, intptr_t err, int64_t errlen)
{
	struct out o = { (char *)err, (size_t)errlen };
	EVP_PKEY_CTX *c = NULL;
	EVP_PKEY *k = NULL;
	int ok;

	if (o.len > 0)
		o.buf[0] = '\0';
	ERR_clear_error();
	if (!same_library(&o))
		return 0;
	if (bits == 0)
		ok = (c = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL)) != NULL
		    && EVP_PKEY_keygen_init(c) > 0
		    && EVP_PKEY_CTX_set_ec_paramgen_curve_nid(c, NID_X9_62_prime256v1) > 0
		    && EVP_PKEY_CTX_set_ec_param_enc(c, OPENSSL_EC_NAMED_CURVE) > 0
		    && EVP_PKEY_keygen(c, &k) > 0;
	else
		ok = (c = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL)) != NULL
		    && EVP_PKEY_keygen_init(c) > 0
		    && EVP_PKEY_CTX_set_rsa_keygen_bits(c, bits) > 0
		    && EVP_PKEY_keygen(c, &k) > 0;
	if (!ok)
		crypto(&o, "cannot make a key");
	else
		ok = write_file(&o, (const char *)file, "key file", 0600, 1, write_key, k);
	EVP_PKEY_free(k);
	EVP_PKEY_CTX_free(c);
	ERR_clear_error();
	return ok;
}

/* Adds extension nid, as value in libcrypto's configuration language,
   with issuer as the issuing certificate: only fixed values come here,
   never a caller's text. */
static int add_ext(struct out *o, X509 *x, X509 *issuer, int nid, const char *value)
{
	X509V3_CTX ctx;
	X509_EXTENSION *e;
	int ok;

	X509V3_set_ctx(&ctx, issuer, x, NULL, NULL, 0);
	if ((e = X509V3_EXT_conf_nid(NULL, &ctx, nid, (char *)value)) == NULL)
		return crypto(o, "cannot make extension %s", OBJ_nid2sn(nid));
	ok = X509_add_ext(x, e, -1);
	X509_EXTENSION_free(e);
	if (!ok)
		return crypto(o, "cannot add extension %s", OBJ_nid2sn(nid));
	return 1;
}

/* A DNS name: 1 to 253 letters, digits, '-', '.' and '*'. */
static int dns_name(const char *s)
{
	size_t n = strlen(s);

	return n > 0 && n <= 253
	    && strspn(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-.*") == n;
}

/* The subject alternative names in names, separated by spaces: each an
   IP address if it parses as one, else a DNS name. Built as structures,
   not through the configuration language, so that a name can't add an
   entry of another kind. None, no extension. */
static int add_names(struct out *o, X509 *x, const char *names)
{
	GENERAL_NAMES *gens;
	GENERAL_NAME *g;
	ASN1_OCTET_STRING *ip;
	ASN1_IA5STRING *dns;
	char name[256];
	size_t n;
	int ok = 1, any = 0;

	if ((gens = GENERAL_NAMES_new()) == NULL)
		return crypto(o, "cannot make the subject alternative names");
	while (ok && *names != '\0') {
		if (*names == ' ') {
			names++;
			continue;
		}
		n = strcspn(names, " ");
		if (n >= sizeof name) {
			ok = say(o, "not an IP address or a DNS name: '%.40s...'", names);
			break;
		}
		memcpy(name, names, n);
		name[n] = '\0';
		names += n;
		if ((g = GENERAL_NAME_new()) == NULL) {
			ok = crypto(o, "cannot make the subject alternative names");
			break;
		}
		if ((ip = a2i_IPADDRESS(name)) != NULL)
			GENERAL_NAME_set0_value(g, GEN_IPADD, ip);
		else if (dns_name(name)) {
			if ((dns = ASN1_IA5STRING_new()) == NULL
			    || !ASN1_STRING_set(dns, name, (int)n)) {
				ASN1_IA5STRING_free(dns);
				GENERAL_NAME_free(g);
				ok = crypto(o, "cannot make the subject alternative names");
				break;
			}
			GENERAL_NAME_set0_value(g, GEN_DNS, dns);
		} else {
			GENERAL_NAME_free(g);
			ok = say(o, "not an IP address or a DNS name: '%s'", name);
			break;
		}
		if (!sk_GENERAL_NAME_push(gens, g)) {
			GENERAL_NAME_free(g);
			ok = crypto(o, "cannot make the subject alternative names");
			break;
		}
		any = 1;
	}
	/* a2i_IPADDRESS may have queued errors for the DNS names. */
	ERR_clear_error();
	if (ok && any && !X509_add1_ext_i2d(x, NID_subject_alt_name, gens, 0, X509V3_ADD_DEFAULT))
		ok = crypto(o, "cannot add the subject alternative names");
	GENERAL_NAMES_free(gens);
	return ok;
}

/* A random positive serial of 16 bytes, its top bit clear so that it
   needs no sign byte, the next set so that it needs all 16. */
static int set_serial(struct out *o, X509 *x)
{
	unsigned char b[16];
	BIGNUM *bn;
	int ok;

	if (RAND_bytes(b, sizeof b) != 1)
		return crypto(o, "cannot make a serial number");
	b[0] = (b[0] & 0x7f) | 0x40;
	if ((bn = BN_bin2bn(b, sizeof b, NULL)) == NULL)
		return crypto(o, "cannot make a serial number");
	ok = BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x)) != NULL;
	BN_free(bn);
	return ok ? 1 : crypto(o, "cannot set the serial number");
}

/* time t, in seconds since the epoch, into a, as UTCTime from 1950 to
   2049 and GeneralizedTime otherwise (RFC 5280, 4.1.2.5). */
static int set_time(struct out *o, ASN1_TIME *a, int64_t t, const char *what)
{
	if ((int64_t)(time_t)t != t || ASN1_TIME_set(a, (time_t)t) == NULL)
		return say(o, "%s out of range: %lld", what, (long long)t);
	return 1;
}

/* A certificate into certfile for the key in keyfile, with common name
   cn and subject alternative names names, a CA if ca, valid from
   notbefore to notafter: signed by the CA of cacertfile and cakeyfile,
   or self-signed if cacertfile is "". */
int32_t tlsmake_cert(intptr_t keyfile, intptr_t certfile, intptr_t cn, intptr_t names,
	int32_t ca, int64_t notbefore, int64_t notafter, intptr_t cacertfile,
	intptr_t cakeyfile, intptr_t err, int64_t errlen)
{
	struct out o = { (char *)err, (size_t)errlen };
	const char *cafile = (const char *)cacertfile;
	EVP_PKEY *key = NULL, *cakey = NULL;
	X509 *x = NULL, *issuer = NULL;
	X509_NAME *subject;
	int ok = 0;

	if (o.len > 0)
		o.buf[0] = '\0';
	ERR_clear_error();
	if (!same_library(&o))
		return 0;
	if ((key = read_key(&o, (const char *)keyfile)) == NULL)
		goto out;
	if (cafile[0] != '\0') {
		if ((issuer = read_cert(&o, cafile)) == NULL
		    || (cakey = read_key(&o, (const char *)cakeyfile)) == NULL)
			goto out;
		if (X509_check_private_key(issuer, cakey) != 1) {
			ERR_clear_error();
			say(&o, "the key in '%s' isn't the one of the CA certificate '%s'",
			    (const char *)cakeyfile, cafile);
			goto out;
		}
	}
	if ((x = X509_new()) == NULL) {
		crypto(&o, "cannot make a certificate");
		goto out;
	}
	if (!X509_set_version(x, 2)) {
		crypto(&o, "cannot set the version");
		goto out;
	}
	if (!set_serial(&o, x)
	    || !set_time(&o, X509_getm_notBefore(x), notbefore, "notBefore")
	    || !set_time(&o, X509_getm_notAfter(x), notafter, "notAfter"))
		goto out;
	if (!X509_set_pubkey(x, key)) {
		crypto(&o, "cannot set the public key");
		goto out;
	}
	subject = X509_get_subject_name(x);
	if (!X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_UTF8,
	    (const unsigned char *)cn, -1, -1, 0)) {
		crypto(&o, "cannot set the common name '%s'", (const char *)cn);
		goto out;
	}
	if (!X509_set_issuer_name(x, issuer != NULL ? X509_get_subject_name(issuer) : subject)) {
		crypto(&o, "cannot set the issuer");
		goto out;
	}
	if (!add_ext(&o, x, issuer != NULL ? issuer : x, NID_basic_constraints,
	        ca ? "critical,CA:TRUE" : "critical,CA:FALSE")
	    || (ca && !add_ext(&o, x, issuer != NULL ? issuer : x, NID_key_usage,
	        "critical,keyCertSign,cRLSign"))
	    || !add_ext(&o, x, issuer != NULL ? issuer : x, NID_subject_key_identifier, "hash")
	    || (issuer != NULL && !add_ext(&o, x, issuer, NID_authority_key_identifier,
	        "keyid:always"))
	    || !add_names(&o, x, (const char *)names))
		goto out;
	if (X509_sign(x, issuer != NULL ? cakey : key, EVP_sha256()) <= 0) {
		crypto(&o, "cannot sign the certificate");
		goto out;
	}
	ok = write_file(&o, (const char *)certfile, "certificate file", 0644, 0, write_cert, x);
out:
	X509_free(x);
	X509_free(issuer);
	EVP_PKEY_free(cakey);
	EVP_PKEY_free(key);
	ERR_clear_error();
	return ok;
}
