MODULE TlsCerts; (* certificates' fingerprints and validity, in Oberon: PEM, DER and SHA-256 *)

(* What a program pins a peer by, computed here rather than by libcrypto,
   which polibtls doesn't link: libtls's flags may put a second
   libcrypto beside the one libtls uses (NetBSD's -L/usr/pkg/lib, on a
   host with pkgsrc's OpenSSL too; PLAN.md, "The peer's public key").

   A certificate comes as PEM text, as tls_peer_cert_chain_pem gives it
   (the peer's own certificate first) or as a file holds it; the first
   CERTIFICATE block is the one used. Its hashes are written as
   tls_peer_cert_hash writes the certificate's: "SHA256:" and 64
   lowercase hex digits, HashLength characters with the 0X.

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

   What a certificate holds is outside data: text that isn't a
   certificate gives FALSE, never a halt. A range outside the array
   given halts (93), and so does a hash array shorter than HashLength
   (99). *)

IMPORT SYSTEM;

CONST
  HashLength* = 72;  (* "SHA256:", 64 hex digits and 0X *)
  DigestLength* = 32;

  (* DER tags *)
  integer = 02H; utcTime = 17H; generalizedTime = 18H; sequence = 30H; explicit0 = 0A0H;

TYPE
  Bytes* = POINTER TO ARRAY OF CHAR;
  Digest* = ARRAY DigestLength OF CHAR;  (* a SHA-256, as bytes *)

  Word = SYSTEM.CARD32;  (* arithmetic wraps modulo 2^32, as SHA-256's *)

VAR
  k: ARRAY 64 OF Word;  (* SHA-256's round constants, set by the body *)

(* --- SHA-256 (FIPS 180-4) --- *)

PROCEDURE Xor(a, b: Word): Word;
BEGIN RETURN SYSTEM.VAL(Word, SYSTEM.VAL(SET, a) / SYSTEM.VAL(SET, b))
END Xor;

PROCEDURE And(a, b: Word): Word;
BEGIN RETURN SYSTEM.VAL(Word, SYSTEM.VAL(SET, a) * SYSTEM.VAL(SET, b))
END And;

PROCEDURE Not(a: Word): Word;
BEGIN RETURN SYSTEM.VAL(Word, -SYSTEM.VAL(SET, a))
END Not;

(* x rotated right by n *)
PROCEDURE R(x: Word; n: INTEGER): Word;
BEGIN RETURN SYSTEM.ROT(x, -n)
END R;

(* x shifted right by n, zeros in *)
PROCEDURE S(x: Word; n: INTEGER): Word;
BEGIN RETURN SYSTEM.LSH(x, -n)
END S;

(* The 64 bytes of b from at, into the state h *)
PROCEDURE Block(VAR h: ARRAY OF Word; b-: ARRAY OF CHAR; at: LONGINT);
  VAR w: ARRAY 64 OF Word; i: INTEGER; a, bb, c, d, e, f, g, hh, t1, t2: Word;
BEGIN
  FOR i := 0 TO 15 DO
    w[i] := SYSTEM.LSH(VAL(Word, ORD(b[at])), 24) + SYSTEM.LSH(VAL(Word, ORD(b[at + 1])), 16)
      + SYSTEM.LSH(VAL(Word, ORD(b[at + 2])), 8) + VAL(Word, ORD(b[at + 3]));
    INC(at, 4)
  END;
  FOR i := 16 TO 63 DO
    w[i] := w[i - 16] + Xor(Xor(R(w[i - 15], 7), R(w[i - 15], 18)), S(w[i - 15], 3))
      + w[i - 7] + Xor(Xor(R(w[i - 2], 17), R(w[i - 2], 19)), S(w[i - 2], 10))
  END;
  a := h[0]; bb := h[1]; c := h[2]; d := h[3]; e := h[4]; f := h[5]; g := h[6]; hh := h[7];
  FOR i := 0 TO 63 DO
    t1 := hh + Xor(Xor(R(e, 6), R(e, 11)), R(e, 25)) + Xor(And(e, f), And(Not(e), g)) + k[i] + w[i];
    t2 := Xor(Xor(R(a, 2), R(a, 13)), R(a, 22)) + Xor(Xor(And(a, bb), And(a, c)), And(bb, c));
    hh := g; g := f; f := e; e := d + t1; d := c; c := bb; bb := a; a := t1 + t2
  END;
  h[0] := h[0] + a; h[1] := h[1] + bb; h[2] := h[2] + c; h[3] := h[3] + d;
  h[4] := h[4] + e; h[5] := h[5] + f; h[6] := h[6] + g; h[7] := h[7] + hh
END Block;

(* The SHA-256 of the len bytes of data from pos *)
PROCEDURE Sha256*(data-: ARRAY OF CHAR; pos, len: LONGINT; VAR digest: Digest);
  VAR h: ARRAY 8 OF Word; tail: ARRAY 128 OF CHAR; i, n, end: LONGINT; bits: HUGEINT;
BEGIN
  ASSERT((pos >= 0) & (len >= 0) & (pos <= LEN(data) - len), 93);
  h[0] := 06A09E667H; h[1] := 0BB67AE85H; h[2] := 03C6EF372H; h[3] := 0A54FF53AH;
  h[4] := 0510E527FH; h[5] := 09B05688CH; h[6] := 01F83D9ABH; h[7] := 05BE0CD19H;
  i := 0;
  WHILE len - i >= 64 DO Block(h, data, pos + i); INC(i, 64) END;
  (* the rest, 80X, zeros, and the length in bits, big-endian, in one
     block or two *)
  n := 0;
  WHILE i < len DO tail[n] := data[pos + i]; INC(n); INC(i) END;
  tail[n] := 80X; INC(n);
  IF n <= 56 THEN end := 64 ELSE end := 128 END;
  WHILE n < end - 8 DO tail[n] := 0X; INC(n) END;
  bits := len; bits := bits * 8;
  FOR i := end - 1 TO end - 8 BY -1 DO tail[i] := CHR(SHORT(SHORT(bits MOD 256))); bits := bits DIV 256 END;
  Block(h, tail, 0);
  IF end = 128 THEN Block(h, tail, 64) END;
  FOR i := 0 TO 7 DO
    digest[4 * i] := CHR(VAL(INTEGER, S(h[i], 24)));
    digest[4 * i + 1] := CHR(VAL(INTEGER, And(S(h[i], 16), 0FFH)));
    digest[4 * i + 2] := CHR(VAL(INTEGER, And(S(h[i], 8), 0FFH)));
    digest[4 * i + 3] := CHR(VAL(INTEGER, And(h[i], 0FFH)))
  END
END Sha256;

(* "SHA256:" and digest in lowercase hex, into hash *)
PROCEDURE Hex*(digest-: Digest; VAR hash: ARRAY OF CHAR);
  VAR i, j: INTEGER;

  PROCEDURE Digit(n: INTEGER): CHAR;
  BEGIN IF n < 10 THEN RETURN CHR(ORD("0") + n) ELSE RETURN CHR(ORD("a") + n - 10) END
  END Digit;

BEGIN
  ASSERT(LEN(hash) >= HashLength, 99);
  COPY("SHA256:", hash); j := 7;
  FOR i := 0 TO DigestLength - 1 DO
    hash[j] := Digit(ORD(digest[i]) DIV 16); hash[j + 1] := Digit(ORD(digest[i]) MOD 16);
    INC(j, 2)
  END;
  hash[j] := 0X
END Hex;

(* --- PEM --- *)

(* Whether s (to its 0X) is at text[i], within len *)
PROCEDURE At(text-: ARRAY OF CHAR; len, i: LONGINT; s: ARRAY OF CHAR): BOOLEAN;
  VAR j: LONGINT;
BEGIN
  j := 0;
  WHILE (s[j] # 0X) & (i + j < len) & (text[i + j] = s[j]) DO INC(j) END;
  RETURN s[j] = 0X
END At;

(* A base64 digit's value, or -1 *)
PROCEDURE Value(c: CHAR): INTEGER;
BEGIN
  CASE c OF
    "A".."Z": RETURN ORD(c) - ORD("A")
  | "a".."z": RETURN ORD(c) - ORD("a") + 26
  | "0".."9": RETURN ORD(c) - ORD("0") + 52
  | "+": RETURN 62
  | "/": RETURN 63
  ELSE RETURN -1
  END
END Value;

(* The DER of the first certificate in the len characters of pem, in a
   new der^ of which derLen bytes are it: FALSE if there is none, or its
   base64 is broken. *)
PROCEDURE Der*(pem-: ARRAY OF CHAR; len: LONGINT; VAR der: Bytes; VAR derLen: LONGINT): BOOLEAN;
  CONST begin = "-----BEGIN CERTIFICATE-----"; beginLen = 27; end = "-----END CERTIFICATE-----";
  VAR i, start, stop, acc, q, pad, v: LONGINT; c: CHAR;
BEGIN
  ASSERT((len >= 0) & (len <= LEN(pem)), 93);
  der := NIL; derLen := 0;
  i := 0;
  WHILE (i < len) & ~At(pem, len, i, begin) DO INC(i) END;
  IF i >= len THEN RETURN FALSE END;
  start := i + beginLen; stop := start;
  WHILE (stop < len) & (pem[stop] # "-") DO INC(stop) END;
  IF ~At(pem, len, stop, end) THEN RETURN FALSE END;
  NEW(der, (stop - start) DIV 4 * 3 + 3);
  acc := 0; q := 0; pad := 0;
  FOR i := start TO stop - 1 DO
    c := pem[i];
    IF (c = " ") OR (c = 9X) OR (c = 0AX) OR (c = 0DX) THEN (* skipped *)
    ELSE
      IF c = "=" THEN v := 0; INC(pad)
      ELSE v := Value(c); IF (v < 0) OR (pad > 0) THEN RETURN FALSE END
      END;
      acc := acc * 64 + v; INC(q);
      IF q = 4 THEN
        IF pad > 2 THEN RETURN FALSE END;
        der[derLen] := CHR(acc DIV 10000H); INC(derLen);
        IF pad < 2 THEN der[derLen] := CHR(acc DIV 100H MOD 100H); INC(derLen) END;
        IF pad < 1 THEN der[derLen] := CHR(acc MOD 100H); INC(derLen) END;
        acc := 0; q := 0
      END
    END
  END;
  RETURN (q = 0) & (derLen > 0)
END Der;

(* --- DER --- *)

(* The tag and length of the element at der[i], within end: i then at
   its contents, n bytes, all within end. Only what a certificate uses:
   a one-byte tag and a definite length of up to three bytes. *)
PROCEDURE Header(der-: ARRAY OF CHAR; end: LONGINT; VAR i: LONGINT; VAR tag: INTEGER; VAR n: LONGINT): BOOLEAN;
  VAR b, m: INTEGER;
BEGIN
  IF i >= end THEN RETURN FALSE END;
  tag := ORD(der[i]); INC(i);
  IF (tag MOD 32 = 31) OR (i >= end) THEN RETURN FALSE END;
  b := ORD(der[i]); INC(i);
  IF b < 128 THEN n := b
  ELSIF (b = 128) OR (b > 128 + 3) THEN RETURN FALSE
  ELSE
    n := 0;
    FOR m := 1 TO b - 128 DO
      IF i >= end THEN RETURN FALSE END;
      n := n * 256 + ORD(der[i]); INC(i)
    END
  END;
  RETURN n <= end - i
END Header;

(* Where element k of the TBSCertificate of the certificate in the len
   bytes of der is, counting from 0 after the optional [0] version:
   serialNumber, signature, issuer, validity, subject,
   subjectPublicKeyInfo. n bytes from pos, its tag and length included;
   FALSE if der isn't a certificate as far as that. *)
PROCEDURE Element(der-: ARRAY OF CHAR; len: LONGINT; k: INTEGER; VAR pos, n: LONGINT): BOOLEAN;
  VAR i, m, end, start: LONGINT; j: INTEGER; tag: INTEGER;
BEGIN
  ASSERT((len >= 0) & (len <= LEN(der)), 93);
  pos := 0; n := 0; i := 0;
  (* Certificate, then TBSCertificate *)
  IF ~Header(der, len, i, tag, m) OR (tag # sequence) THEN RETURN FALSE END;
  end := i + m;
  IF ~Header(der, end, i, tag, m) OR (tag # sequence) THEN RETURN FALSE END;
  end := i + m;
  IF (i < end) & (ORD(der[i]) = explicit0) THEN
    IF ~Header(der, end, i, tag, m) THEN RETURN FALSE END;
    INC(i, m)
  END;
  (* serialNumber an INTEGER, the rest SEQUENCEs *)
  FOR j := 0 TO k DO
    start := i;
    IF ~Header(der, end, i, tag, m) OR ((j = 0) & (tag # integer)) OR ((j > 0) & (tag # sequence)) THEN
      RETURN FALSE
    END;
    INC(i, m)
  END;
  pos := start; n := i - start;
  RETURN TRUE
END Element;

(* Where the SubjectPublicKeyInfo of the certificate in the len bytes
   of der is: n bytes from pos, its tag and length included. FALSE if
   der isn't a certificate as far as that. *)
PROCEDURE PublicKey*(der-: ARRAY OF CHAR; len: LONGINT; VAR pos, n: LONGINT): BOOLEAN;
BEGIN RETURN Element(der, len, 5, pos, n)
END PublicKey;

(* The n digits at der[i] as a number into v, i past them: FALSE if one
   isn't a digit. *)
PROCEDURE Digits(der-: ARRAY OF CHAR; VAR i: LONGINT; n: INTEGER; VAR v: LONGINT): BOOLEAN;
BEGIN
  v := 0;
  WHILE n > 0 DO
    IF (der[i] < "0") OR (der[i] > "9") THEN RETURN FALSE END;
    v := v * 10 + ORD(der[i]) - ORD("0"); INC(i); DEC(n)
  END;
  RETURN TRUE
END Digits;

(* The time at der[i], within end, in seconds since the epoch into t, i
   past it: RFC 5280's UTCTime, YYMMDDHHMMSSZ, its year 1950 to 2049,
   or GeneralizedTime, YYYYMMDDHHMMSSZ, in UTC with seconds and no
   fraction, as RFC 5280 has them. *)
PROCEDURE Time(der-: ARRAY OF CHAR; end: LONGINT; VAR i: LONGINT; VAR t: HUGEINT): BOOLEAN;
  VAR tag: INTEGER; n, y, mo, d, h, mi, sec, era, yoe, doy, days: LONGINT;
BEGIN
  IF ~Header(der, end, i, tag, n) THEN RETURN FALSE END;
  IF (tag = utcTime) & (n = 13) THEN
    IF ~Digits(der, i, 2, y) THEN RETURN FALSE END;
    IF y < 50 THEN INC(y, 2000) ELSE INC(y, 1900) END
  ELSIF (tag = generalizedTime) & (n = 15) THEN
    IF ~Digits(der, i, 4, y) THEN RETURN FALSE END
  ELSE RETURN FALSE
  END;
  IF ~Digits(der, i, 2, mo) OR ~Digits(der, i, 2, d) OR ~Digits(der, i, 2, h)
    OR ~Digits(der, i, 2, mi) OR ~Digits(der, i, 2, sec) OR (der[i] # "Z")
    OR (mo < 1) OR (mo > 12) OR (d < 1) OR (d > 31) OR (h > 23) OR (mi > 59) OR (sec > 60)
  THEN
    RETURN FALSE
  END;
  INC(i);
  (* days since the epoch by the civil calendar, Howard Hinnant's
     days_from_civil, as cert-info.sh has it; DIV floors *)
  IF mo <= 2 THEN DEC(y) END;
  era := y DIV 400; yoe := y - era * 400;
  IF mo > 2 THEN doy := (153 * (mo - 3) + 2) DIV 5 + d - 1 ELSE doy := (153 * (mo + 9) + 2) DIV 5 + d - 1 END;
  days := era * 146097 + yoe * 365 + yoe DIV 4 - yoe DIV 100 + doy - 719468;
  t := days; t := ((t * 24 + h) * 60 + mi) * 60 + sec;
  RETURN TRUE
END Time;

(* The validity of the certificate in the len bytes of der, its
   notBefore and notAfter in seconds since the epoch: FALSE if der isn't
   a certificate as far as that, or either time isn't one RFC 5280
   allows. A day past the month's last (31 February) isn't checked. *)
PROCEDURE Times*(der-: ARRAY OF CHAR; len: LONGINT; VAR notBefore, notAfter: HUGEINT): BOOLEAN;
  VAR pos, n, i, m: LONGINT; tag: INTEGER;
BEGIN
  notBefore := 0; notAfter := 0;
  IF ~Element(der, len, 3, pos, n) THEN RETURN FALSE END;
  i := pos;
  IF ~Header(der, pos + n, i, tag, m) OR (tag # sequence) THEN RETURN FALSE END;
  RETURN Time(der, i + m, i, notBefore) & Time(der, i + m, i, notAfter) & (i = pos + n)
END Times;

(* --- Hashes --- *)

(* The hash of the first certificate in the len characters of pem, into
   hash: FALSE if there is no certificate. *)
PROCEDURE CertHash*(pem-: ARRAY OF CHAR; len: LONGINT; VAR hash: ARRAY OF CHAR): BOOLEAN;
  VAR der: Bytes; n: LONGINT; d: Digest;
BEGIN
  ASSERT(LEN(hash) >= HashLength, 99);
  hash[0] := 0X;
  IF ~Der(pem, len, der, n) THEN RETURN FALSE END;
  Sha256(der^, 0, n, d); Hex(d, hash);
  RETURN TRUE
END CertHash;

(* The hash of the public key of the first certificate in the len
   characters of pem, into hash: FALSE if there is no certificate, or
   none can be read as far as its key. *)
PROCEDURE KeyHash*(pem-: ARRAY OF CHAR; len: LONGINT; VAR hash: ARRAY OF CHAR): BOOLEAN;
  VAR der: Bytes; n, pos, m: LONGINT; d: Digest;
BEGIN
  ASSERT(LEN(hash) >= HashLength, 99);
  hash[0] := 0X;
  IF ~Der(pem, len, der, n) OR ~PublicKey(der^, n, pos, m) THEN RETURN FALSE END;
  Sha256(der^, pos, m, d); Hex(d, hash);
  RETURN TRUE
END KeyHash;

(* --- Validity --- *)

(* The validity of the first certificate in the len characters of pem,
   its notBefore and notAfter in seconds since the epoch, as Times: FALSE
   if there is no certificate, or none can be read as far as its
   validity. *)
PROCEDURE Validity*(pem-: ARRAY OF CHAR; len: LONGINT; VAR notBefore, notAfter: HUGEINT): BOOLEAN;
  VAR der: Bytes; n: LONGINT;
BEGIN
  notBefore := 0; notAfter := 0;
  RETURN Der(pem, len, der, n) & Times(der^, n, notBefore, notAfter)
END Validity;

PROCEDURE SetK(i: INTEGER; a, b, c, d: Word);
BEGIN k[i] := a; k[i + 1] := b; k[i + 2] := c; k[i + 3] := d
END SetK;

BEGIN
  SetK(0, 0428A2F98H, 071374491H, 0B5C0FBCFH, 0E9B5DBA5H);
  SetK(4, 03956C25BH, 059F111F1H, 0923F82A4H, 0AB1C5ED5H);
  SetK(8, 0D807AA98H, 012835B01H, 0243185BEH, 0550C7DC3H);
  SetK(12, 072BE5D74H, 080DEB1FEH, 09BDC06A7H, 0C19BF174H);
  SetK(16, 0E49B69C1H, 0EFBE4786H, 00FC19DC6H, 0240CA1CCH);
  SetK(20, 02DE92C6FH, 04A7484AAH, 05CB0A9DCH, 076F988DAH);
  SetK(24, 0983E5152H, 0A831C66DH, 0B00327C8H, 0BF597FC7H);
  SetK(28, 0C6E00BF3H, 0D5A79147H, 006CA6351H, 014292967H);
  SetK(32, 027B70A85H, 02E1B2138H, 04D2C6DFCH, 053380D13H);
  SetK(36, 0650A7354H, 0766A0ABBH, 081C2C92EH, 092722C85H);
  SetK(40, 0A2BFE8A1H, 0A81A664BH, 0C24B8B70H, 0C76C51A3H);
  SetK(44, 0D192E819H, 0D6990624H, 0F40E3585H, 0106AA070H);
  SetK(48, 019A4C116H, 01E376C08H, 02748774CH, 034B0BCB5H);
  SetK(52, 0391C0CB3H, 04ED8AA4AH, 05B9CCA4FH, 0682E6FF3H);
  SetK(56, 0748F82EEH, 078A5636FH, 084C87814H, 08CC70208H);
  SetK(60, 090BEFFFAH, 0A4506CEBH, 0BEF9A3F7H, 0C67178F2H)
END TlsCerts.
