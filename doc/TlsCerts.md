# TlsCerts: certificates' fingerprints and validity, in Oberon: PEM, DER and SHA-256

<!-- Made by doc/mkref.py from TlsCerts.Mod; edit the source, then make doc. -->

What a program pins a peer by, computed here rather than by libcrypto, which polibtls didn't link when this was written: libtls's flags may put a second libcrypto beside the one libtls uses (NetBSD's -L/usr/pkg/lib, on a host with pkgsrc's OpenSSL too; PLAN.md, "The peer's public key"). TlsMake now links libcrypto, by the path of the one libtls loads, but this needs none.

A certificate comes as PEM text, as tls_peer_cert_chain_pem gives it (the peer's own certificate first) or as a file holds it; the first CERTIFICATE block is the one used. Its hashes are written as tls_peer_cert_hash writes the certificate's: "SHA256:" and 64 lowercase hex digits, HashLength characters with the 0X.

- CertHash: of the whole certificate (DER), as libtls's
  PeerCertHash, so as a Gemini server knows a client.
- KeyHash: of its SubjectPublicKeyInfo (DER), the key and its
  algorithm, so that a certificate renewed with the same key hashes
  the same; as Lagrange pins a server, and as `openssl x509 -pubkey
  | openssl pkey -pubin -outform DER | openssl dgst -sha256` gives.
- Validity: its notBefore and notAfter, in seconds since the epoch,
  as libtls's PeerCertNotBefore and PeerCertNotAfter give a peer's,
  so that a program can say when a certificate file of its own
  expires (pogeminilib's identities; PLAN.md, "A certificate's
  validity").

What a certificate holds is outside data: text that isn't a certificate gives FALSE, never a halt. A range outside the array given halts (93), and so does a hash array shorter than HashLength (99).

## Constants

```oberon
HashLength* = 72;  (* "SHA256:", 64 hex digits and 0X *)
DigestLength* = 32;
```

## Types

```oberon
Bytes* = POINTER TO ARRAY OF CHAR;
Digest* = ARRAY DigestLength OF CHAR;  (* a SHA-256, as bytes *)
```

## Procedures

#### Sha256

```oberon
PROCEDURE Sha256*(data-: ARRAY OF CHAR; pos, len: LONGINT; VAR digest: Digest);
```

The SHA-256 of the len bytes of data from pos

#### Hex

```oberon
PROCEDURE Hex*(digest-: Digest; VAR hash: ARRAY OF CHAR);
```

"SHA256:" and digest in lowercase hex, into hash

### PEM

#### Der

```oberon
PROCEDURE Der*(pem-: ARRAY OF CHAR; len: LONGINT; VAR der: Bytes; VAR derLen: LONGINT): BOOLEAN;
```

The DER of the first certificate in the len characters of pem, in a new der^ of which derLen bytes are it: FALSE if there is none, or its base64 is broken.

### DER

#### PublicKey

```oberon
PROCEDURE PublicKey*(der-: ARRAY OF CHAR; len: LONGINT; VAR pos, n: LONGINT): BOOLEAN;
```

Where the SubjectPublicKeyInfo of the certificate in the len bytes of der is: n bytes from pos, its tag and length included. FALSE if der isn't a certificate as far as that.

#### Times

```oberon
PROCEDURE Times*(der-: ARRAY OF CHAR; len: LONGINT; VAR notBefore, notAfter: HUGEINT): BOOLEAN;
```

The validity of the certificate in the len bytes of der, its notBefore and notAfter in seconds since the epoch: FALSE if der isn't a certificate as far as that, or either time isn't one RFC 5280 allows. A day past the month's last (31 February) isn't checked.

### Hashes

#### CertHash

```oberon
PROCEDURE CertHash*(pem-: ARRAY OF CHAR; len: LONGINT; VAR hash: ARRAY OF CHAR): BOOLEAN;
```

The hash of the first certificate in the len characters of pem, into hash: FALSE if there is no certificate.

#### KeyHash

```oberon
PROCEDURE KeyHash*(pem-: ARRAY OF CHAR; len: LONGINT; VAR hash: ARRAY OF CHAR): BOOLEAN;
```

The hash of the public key of the first certificate in the len characters of pem, into hash: FALSE if there is no certificate, or none can be read as far as its key.

### Validity

#### Validity

```oberon
PROCEDURE Validity*(pem-: ARRAY OF CHAR; len: LONGINT; VAR notBefore, notAfter: HUGEINT): BOOLEAN;
```

The validity of the first certificate in the len characters of pem, its notBefore and notAfter in seconds since the epoch, as Times: FALSE if there is no certificate, or none can be read as far as its validity.
