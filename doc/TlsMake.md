# TlsMake: private keys and certificates, made through libcrypto into files

<!-- Made by doc/mkref.py from TlsMake.Mod; edit the source, then make doc. -->

What `openssl genpkey` and `openssl req -x509` make, so that a program, such as a Gemini server or client making its own identity, needs no openssl command (PLAN.md, "Making keys and certificates"). Its C part, TlsMake.c, calls the libcrypto that libtls itself loads, which the library links by its path, and each call fails if the libcrypto it finds isn't the one polibtls was built with.

Everything goes through files, as libtls takes key pairs by file name: a key never passes through Oberon memory.

- A key file is PEM (PKCS#8), unencrypted, mode 0600, and is never
  replaced: making a key into a file that exists fails.
- A certificate file is PEM, mode 0644, and replaces any file of that
  name at once and whole (written beside it, then renamed).
- A failure leaves no file behind.

A certificate is X.509 v3, signed with SHA-256, with a random serial number and a subject of one common name. A CA's has basicConstraints CA:TRUE and keyUsage keyCertSign and cRLSign, both critical; any other's basicConstraints CA:FALSE. Each has a subject key identifier, and one signed by a CA an authority key identifier.

names, the subject alternative names, are separated by spaces: each is an IP address, v4 or v6, if it reads as one, and otherwise a DNS name, of letters, digits, '-', '.' and '*' ("*.example.org"). "" gives none, and then libtls matches the common name instead (RFC 6125).

Times are seconds since the epoch, as TlsCerts.Validity and libtls's PeerCertNotBefore give them.

Every procedure returns TRUE, with error NIL, or FALSE, with error saying what failed. Nothing here halts: a bad argument is a FALSE result too, since a program may take names and times from its user. String arguments must be 0X-terminated.

## Constants

```oberon
MinRsaBits* = 2048;
MaxRsaBits* = 16384;
```

## Procedures

### Keys

#### EcKey

```oberon
PROCEDURE EcKey*(keyFile: ARRAY OF CHAR; VAR error: Tls.String): BOOLEAN;
```

An EC key on curve P-256 (prime256v1), the usual choice: small, fast and accepted everywhere TLS 1.2 or 1.3 is. Fails if keyFile exists.

#### RsaKey

```oberon
PROCEDURE RsaKey*(keyFile: ARRAY OF CHAR; bits: LONGINT; VAR error: Tls.String): BOOLEAN;
```

An RSA key of bits bits, MinRsaBits to MaxRsaBits, for a peer that takes no EC key. Fails if keyFile exists. A large key takes long to make, and how long varies, with the search for primes: once each on a 2026 desktop, 0.2 s at 4096 bits and 2.8 s at 8192.

### Certificates

#### SelfSigned

```oberon
PROCEDURE SelfSigned*(keyFile, certFile, commonName, names: ARRAY OF CHAR; ca: BOOLEAN;
    notBefore, notAfter: HUGEINT; VAR error: Tls.String): BOOLEAN;
```

A certificate into certFile for the key in keyFile, signed by that key: a server's or a client's own identity, as Gemini uses them, or with ca a CA's root. commonName is its subject's CN, at most 64 characters, and names its subject alternative names; it is valid from notBefore to notAfter.

#### Signed

```oberon
PROCEDURE Signed*(keyFile, certFile, commonName, names: ARRAY OF CHAR; ca: BOOLEAN;
    notBefore, notAfter: HUGEINT; caCertFile, caKeyFile: ARRAY OF CHAR;
    VAR error: Tls.String): BOOLEAN;
```

As SelfSigned, but signed by the CA whose certificate is in caCertFile and key in caKeyFile, which must match; its issuer is the CA's subject.
