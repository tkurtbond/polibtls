/* TestPeers.c -- the C part of module TestPeers, the tests' own access
   to the system: a socket pair to run TLS over, without the network or
   posockets, and a TLS peer in a thread of its own for the blocking
   tests (PLAN.md, "Testing"). Labelled TestPeers.-<name>. Commands run
   as child processes are module Child's, through pounix. */

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <tls.h>
#include <unistd.h>

#define NAME(n) __asm__("TestPeers.-" n)

int32_t testpeers_pair(int64_t *fds, int32_t nonblocking) NAME("pair");
int32_t testpeers_close(int64_t fd) NAME("close");
void testpeers_ignore_sigpipe(void) NAME("ignore-sigpipe");
intptr_t testpeers_start(int32_t server, int64_t fd, const char *ca,
    const char *cert, const char *key, const char *servername,
    const char *send, int64_t sendlen, int64_t expect, int32_t abrupt)
    NAME("start");
int32_t testpeers_join(intptr_t p, char *got, int64_t gotmax,
    int64_t *gotlen, char *error, int64_t errormax) NAME("join");

/* A connected pair of Unix-domain stream sockets in fds[0] and fds[1],
   close-on-exec, and non-blocking if asked: 0, or -1. */
int32_t testpeers_pair(int64_t *fds, int32_t nonblocking)
{
	int sv[2];
	int type = SOCK_STREAM | SOCK_CLOEXEC | (nonblocking ? SOCK_NONBLOCK : 0);

	if (socketpair(AF_UNIX, type, 0, sv) != 0)
		return -1;
	/* NetBSD gives a socket pair 8 KiB, less than one TLS record (16
	   KiB), so a writer whose peer reads nothing never finishes a
	   record, and the write-timeout test sees nothing written. Raise
	   each end's send buffer to 64 KiB, as FreeBSD's is; never lower
	   it (Linux's is larger). */
	for (int i = 0; i < 2; i++) {
		int v; socklen_t l = sizeof v;
		if (getsockopt(sv[i], SOL_SOCKET, SO_SNDBUF, &v, &l) == 0 && v < 65536) {
			v = 65536;
			setsockopt(sv[i], SOL_SOCKET, SO_SNDBUF, &v, sizeof v);
		}
	}
	fds[0] = sv[0];
	fds[1] = sv[1];
	return 0;
}

int32_t testpeers_close(int64_t fd) { return close((int)fd); }

/* Writing to a gone peer then fails with EPIPE instead of killing the
   test (PLAN.md, "I/O"). */
void testpeers_ignore_sigpipe(void) { signal(SIGPIPE, SIG_IGN); }


/* A TLS peer, run in a thread of its own with blocking calls, so that
   the Oberon side can block too. It runs only C: everything it uses is
   copied into C memory first, so the collector, which scans only the
   main thread's stack, never needs to see it.

   A client connects (verifying the server against ca, or nothing if ca
   is ""; with a certificate if cert is not ""), writes send, then reads
   until end of data. A server (verifying nothing, a client certificate
   optional) reads until it has expect bytes or end of data, then writes
   send. Then each closes with close_notify, or if abrupt shuts the
   socket down without one. It never closes the descriptor. */
struct peer {
	pthread_t thread;
	int server, fd, abrupt;
	char *ca, *cert, *key, *servername, *send;
	size_t sendlen, expect;
	char *got;
	size_t gotlen, gotcap;
	int status;		/* 0, or -1 with error */
	char *error;
};

static char *dup_or_null(const char *s)
{
	return s[0] == '\0' ? NULL : strdup(s);
}

/* A blocking call can still return TLS_WANT_*: retry at once (PLAN.md,
   Phase 0). */
#define RETRY(call) ({ ssize_t r_; \
	do r_ = (call); while (r_ == TLS_WANT_POLLIN || r_ == TLS_WANT_POLLOUT); r_; })

static void fail(struct peer *p, struct tls *ctx, struct tls_config *cfg,
    const char *what)
{
	const char *e = ctx != NULL ? tls_error(ctx) : NULL;

	if (e == NULL && cfg != NULL)
		e = tls_config_error(cfg);
	p->status = -1;
	p->error = malloc(strlen(what) + (e ? strlen(e) : 0) + 3);
	strcpy(p->error, what);
	if (e != NULL) {
		strcat(p->error, ": ");
		strcat(p->error, e);
	}
}

static int append(struct peer *p, const char *buf, size_t n)
{
	if (p->gotlen + n > p->gotcap) {
		p->gotcap = (p->gotlen + n) * 2;
		p->got = realloc(p->got, p->gotcap);
	}
	memcpy(p->got + p->gotlen, buf, n);
	p->gotlen += n;
	return 0;
}

static void *run(void *arg)
{
	struct peer *p = arg;
	struct tls_config *cfg = tls_config_new();
	struct tls *ctx = NULL, *conn = NULL, *srv = NULL;
	char buf[4096];
	ssize_t r;
	size_t off;

	if (p->cert != NULL &&
	    tls_config_set_keypair_file(cfg, p->cert, p->key) != 0) {
		fail(p, NULL, cfg, "keypair"); goto out;
	}
	if (p->server) {
		tls_config_verify_client_optional(cfg);
		tls_config_insecure_noverifycert(cfg);
		srv = tls_server();
		if (tls_configure(srv, cfg) != 0) { fail(p, srv, NULL, "configure"); goto out; }
		if (tls_accept_socket(srv, &conn, p->fd) != 0) { fail(p, srv, NULL, "accept"); goto out; }
		ctx = conn;
	} else {
		if (p->ca != NULL) {
			if (tls_config_set_ca_file(cfg, p->ca) != 0) { fail(p, NULL, cfg, "ca"); goto out; }
		} else {
			tls_config_insecure_noverifycert(cfg);
			tls_config_insecure_noverifyname(cfg);
		}
		ctx = tls_client();
		if (tls_configure(ctx, cfg) != 0) { fail(p, ctx, NULL, "configure"); goto out; }
		if (tls_connect_socket(ctx, p->fd, p->servername) != 0) { fail(p, ctx, NULL, "connect"); goto out; }
	}
	if (RETRY(tls_handshake(ctx)) != 0) { fail(p, ctx, NULL, "handshake"); goto out; }
	if (!p->server) {
		for (off = 0; off < p->sendlen; off += r)
			if ((r = RETRY(tls_write(ctx, p->send + off, p->sendlen - off))) < 0) {
				fail(p, ctx, NULL, "write"); goto out;
			}
	}
	while (!p->server || p->gotlen < p->expect) {
		if ((r = RETRY(tls_read(ctx, buf, sizeof buf))) < 0) { fail(p, ctx, NULL, "read"); goto out; }
		if (r == 0) break;
		append(p, buf, r);
	}
	if (p->server) {
		for (off = 0; off < p->sendlen; off += r)
			if ((r = RETRY(tls_write(ctx, p->send + off, p->sendlen - off))) < 0) {
				fail(p, ctx, NULL, "write"); goto out;
			}
	}
	if (p->abrupt)
		shutdown(p->fd, SHUT_RDWR);
	else if (RETRY(tls_close(ctx)) != 0)
		fail(p, ctx, NULL, "close");
 out:
	tls_free(ctx == srv ? NULL : ctx);
	tls_free(srv);
	tls_config_free(cfg);
	return NULL;
}

/* Starts a peer on fd (see struct peer); 0 if no thread could start. */
intptr_t testpeers_start(int32_t server, int64_t fd, const char *ca,
    const char *cert, const char *key, const char *servername,
    const char *send, int64_t sendlen, int64_t expect, int32_t abrupt)
{
	struct peer *p = calloc(1, sizeof *p);

	p->server = server; p->fd = (int)fd; p->abrupt = abrupt;
	p->ca = dup_or_null(ca); p->cert = dup_or_null(cert);
	p->key = dup_or_null(key); p->servername = dup_or_null(servername);
	p->send = malloc(sendlen > 0 ? sendlen : 1);
	memcpy(p->send, send, sendlen);
	p->sendlen = sendlen; p->expect = expect;
	if (pthread_create(&p->thread, NULL, run, p) != 0) {
		free(p->send); free(p->ca); free(p->cert); free(p->key);
		free(p->servername); free(p);
		return 0;
	}
	return (intptr_t)p;
}

/* Waits for the peer, copies what it read (up to gotmax bytes; gotlen
   says how many it read in all) and its error text (cut to errormax,
   0X-terminated, "" if none), frees it, and returns its status. */
int32_t testpeers_join(intptr_t pp, char *got, int64_t gotmax,
    int64_t *gotlen, char *error, int64_t errormax)
{
	struct peer *p = (struct peer *)pp;
	int32_t status;

	pthread_join(p->thread, NULL);
	*gotlen = p->gotlen;
	memcpy(got, p->got, p->gotlen < (size_t)gotmax ? p->gotlen : (size_t)gotmax);
	error[0] = '\0';
	if (p->error != NULL) {
		strncat(error, p->error, errormax - 1);
	}
	status = p->status;
	free(p->got); free(p->error); free(p->send); free(p->ca);
	free(p->cert); free(p->key); free(p->servername); free(p);
	return status;
}
