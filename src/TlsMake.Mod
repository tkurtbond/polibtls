MODULE TlsMake; (* private keys and certificates, made through libcrypto into files *)

(* What `openssl genpkey` and `openssl req -x509` make, so that a
   program, such as a Gemini server or client making its own identity,
   needs no openssl command (PLAN.md, "Making keys and certificates").
   Its C part, TlsMake.c, calls the libcrypto that libtls itself loads,
   which the library links by its path, and each call fails if the
   libcrypto it finds isn't the one polibtls was built with.

   Everything goes through files, as libtls takes key pairs by file
   name: a key never passes through Oberon memory.

   - A key file is PEM (PKCS#8), unencrypted, mode 0600, and is never
     replaced: making a key into a file that exists fails.
   - A certificate file is PEM, mode 0644, and replaces any file of that
     name at once and whole (written beside it, then renamed).
   - A failure leaves no file behind.

   A certificate is X.509 v3, signed with SHA-256, with a random serial
   number and a subject of one common name. A CA's has basicConstraints
   CA:TRUE and keyUsage keyCertSign and cRLSign, both critical; any
   other's basicConstraints CA:FALSE. Each has a subject key
   identifier, and one signed by a CA an authority key identifier.

   names, the subject alternative names, are separated by spaces: each
   is an IP address, v4 or v6, if it reads as one, and otherwise a DNS
   name, of letters, digits, '-', '.' and '*' ("*.example.org"). ""
   gives none, and then libtls matches the common name instead (RFC
   6125).

   Times are seconds since the epoch, as TlsCerts.Validity and libtls's
   PeerCertNotBefore give them.

   Every procedure returns TRUE, with error NIL, or FALSE, with error
   saying what failed. Nothing here halts: a bad argument is a FALSE
   result too, since a program may take names and times from its user.
   String arguments must be 0X-terminated. *)

IMPORT SYSTEM, Tls;

CONST
  MinRsaBits* = 2048;
  MaxRsaBits* = 16384;
  errorLength = 512;

PROCEDURE ["C", "TlsMake.-key"] CKey(file: ARRAY OF CHAR; bits: SYSTEM.INT32;
  VAR err: ARRAY OF CHAR; errlen: SYSTEM.INT64): SYSTEM.INT32;
PROCEDURE ["C", "TlsMake.-cert"] CCert(keyfile, certfile, cn, names: ARRAY OF CHAR;
  ca: SYSTEM.INT32; notbefore, notafter: SYSTEM.INT64; cacertfile, cakeyfile: ARRAY OF CHAR;
  VAR err: ARRAY OF CHAR; errlen: SYSTEM.INT64): SYSTEM.INT32;

(* A new String holding text up to its 0X. *)
PROCEDURE NewString(text: ARRAY OF CHAR): Tls.String;
  VAR n, i: LONGINT; s: Tls.String;
BEGIN
  n := 0; WHILE (n < LEN(text)) & (text[n] # 0X) DO INC(n) END;
  NEW(s, n + 1);
  FOR i := 0 TO n - 1 DO s[i] := text[i] END;
  s[n] := 0X;
  RETURN s
END NewString;

(* Whether s ends with a 0X within its array, as the C part needs. *)
PROCEDURE Terminated(s: ARRAY OF CHAR): BOOLEAN;
  VAR i: LONGINT;
BEGIN
  i := 0; WHILE (i < LEN(s)) & (s[i] # 0X) DO INC(i) END;
  RETURN i < LEN(s)
END Terminated;

(* Whether every string is 0X-terminated; error says which isn't. *)
PROCEDURE CheckStrings(a, b, c, d, e, f: ARRAY OF CHAR; VAR error: Tls.String): BOOLEAN;
BEGIN
  IF ~(Terminated(a) & Terminated(b) & Terminated(c) & Terminated(d)
       & Terminated(e) & Terminated(f)) THEN
    error := NewString("TlsMake: a string argument has no 0X");
    RETURN FALSE
  END;
  RETURN TRUE
END CheckStrings;

PROCEDURE Result(r: SYSTEM.INT32; err: ARRAY OF CHAR; VAR error: Tls.String): BOOLEAN;
BEGIN
  IF r # 0 THEN error := NIL; RETURN TRUE END;
  IF err[0] = 0X THEN error := NewString("TlsMake: failed, no reason given")
  ELSE error := NewString(err)
  END;
  RETURN FALSE
END Result;

(* --- Keys --- *)

(* An EC key on curve P-256 (prime256v1), the usual choice: small, fast
   and accepted everywhere TLS 1.2 or 1.3 is. Fails if keyFile exists. *)
PROCEDURE EcKey*(keyFile: ARRAY OF CHAR; VAR error: Tls.String): BOOLEAN;
  VAR err: ARRAY errorLength OF CHAR;
BEGIN
  IF ~CheckStrings(keyFile, "", "", "", "", "", error) THEN RETURN FALSE END;
  RETURN Result(CKey(keyFile, 0, err, LEN(err)), err, error)
END EcKey;

(* An RSA key of bits bits, MinRsaBits to MaxRsaBits, for a peer that
   takes no EC key. Fails if keyFile exists. A large key takes long to
   make, and how long varies, with the search for primes: once each on
   a 2026 desktop, 0.2 s at 4096 bits and 2.8 s at 8192. *)
PROCEDURE RsaKey*(keyFile: ARRAY OF CHAR; bits: LONGINT; VAR error: Tls.String): BOOLEAN;
  VAR err: ARRAY errorLength OF CHAR;
BEGIN
  IF ~CheckStrings(keyFile, "", "", "", "", "", error) THEN RETURN FALSE END;
  IF (bits < MinRsaBits) OR (bits > MaxRsaBits) THEN
    error := NewString("TlsMake: RSA key size out of range (2048 to 16384 bits)");
    RETURN FALSE
  END;
  RETURN Result(CKey(keyFile, SYSTEM.VAL(SYSTEM.INT32, bits), err, LEN(err)), err, error)
END RsaKey;

(* --- Certificates --- *)

PROCEDURE Make(keyFile, certFile, commonName, names: ARRAY OF CHAR; ca: BOOLEAN;
    notBefore, notAfter: HUGEINT; caCertFile, caKeyFile: ARRAY OF CHAR;
    VAR error: Tls.String): BOOLEAN;
  VAR err: ARRAY errorLength OF CHAR; isCa: SYSTEM.INT32;
BEGIN
  IF ~CheckStrings(keyFile, certFile, commonName, names, caCertFile, caKeyFile, error) THEN
    RETURN FALSE
  END;
  IF commonName[0] = 0X THEN
    error := NewString("TlsMake: the common name is empty"); RETURN FALSE
  END;
  IF notAfter < notBefore THEN
    error := NewString("TlsMake: notAfter is before notBefore"); RETURN FALSE
  END;
  IF ca THEN isCa := 1 ELSE isCa := 0 END;
  RETURN Result(CCert(keyFile, certFile, commonName, names, isCa, notBefore, notAfter,
    caCertFile, caKeyFile, err, LEN(err)), err, error)
END Make;

(* A certificate into certFile for the key in keyFile, signed by that
   key: a server's or a client's own identity, as Gemini uses them, or
   with ca a CA's root. commonName is its subject's CN, at most 64
   characters, and names its subject alternative names; it is valid from
   notBefore to notAfter. *)
PROCEDURE SelfSigned*(keyFile, certFile, commonName, names: ARRAY OF CHAR; ca: BOOLEAN;
    notBefore, notAfter: HUGEINT; VAR error: Tls.String): BOOLEAN;
BEGIN
  RETURN Make(keyFile, certFile, commonName, names, ca, notBefore, notAfter, "", "", error)
END SelfSigned;

(* As SelfSigned, but signed by the CA whose certificate is in caCertFile
   and key in caKeyFile, which must match; its issuer is the CA's
   subject. *)
PROCEDURE Signed*(keyFile, certFile, commonName, names: ARRAY OF CHAR; ca: BOOLEAN;
    notBefore, notAfter: HUGEINT; caCertFile, caKeyFile: ARRAY OF CHAR;
    VAR error: Tls.String): BOOLEAN;
BEGIN
  IF caCertFile[0] = 0X THEN
    error := NewString("TlsMake: no CA certificate file"); RETURN FALSE
  END;
  RETURN Make(keyFile, certFile, commonName, names, ca, notBefore, notAfter,
    caCertFile, caKeyFile, error)
END Signed;

END TlsMake.
