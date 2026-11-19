MODULE TestCerts; (* TlsCerts: SHA-256, PEM, DER, and a certificate's hashes *)

(* SHA-256 against FIPS 180-4's examples and openssl's digests of
   lengths about a block's end; each test certificate's hashes against
   what openssl says of it (cert-info.sh); and text that isn't a
   certificate, or DER cut short or changed, giving FALSE without a
   halt. Certificates are test/make-certs.sh's, from test/. *)

IMPORT Check, Child, TlsCerts;

CONST
  certs = "../build/certs/";

TYPE
  Name = ARRAY 128 OF CHAR;
  Hash = ARRAY TlsCerts.HashLength OF CHAR;

VAR
  pem, pem2: ARRAY 16384 OF CHAR;  (* a certificate file's text, and another's *)

PROCEDURE Append(VAR s: ARRAY OF CHAR; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0;
  WHILE (j < LEN(part)) & (part[j] # 0X) & (i < LEN(s) - 1) DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

(* "SHA256:" and want, as Hex writes it *)
PROCEDURE Want(want: ARRAY OF CHAR; VAR s: Hash);
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, "SHA256:"); Append(s, i, want)
END Want;

(* Whether the SHA-256 of data[pos..pos+len-1] is want, in hex *)
PROCEDURE Sha(data-: ARRAY OF CHAR; pos, len: LONGINT; want: ARRAY OF CHAR): BOOLEAN;
  VAR d: TlsCerts.Digest; got, w: Hash;
BEGIN
  TlsCerts.Sha256(data, pos, len, d); TlsCerts.Hex(d, got); Want(want, w);
  RETURN got = w
END Sha;

PROCEDURE Digests;
  VAR s: ARRAY 256 OF CHAR; big: TlsCerts.Bytes; i: LONGINT;

  PROCEDURE As(n: LONGINT; want, label: ARRAY OF CHAR);
    VAR i: LONGINT;
  BEGIN
    FOR i := 0 TO n - 1 DO s[i] := "a" END;
    Check.Check(Sha(s, 0, n, want), label)
  END As;

BEGIN
  s := "";
  Check.Check(Sha(s, 0, 0, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"), "sha256: empty");
  s := "abc";
  Check.Check(Sha(s, 0, 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"), "sha256: abc");
  s := "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  Check.Check(Sha(s, 0, 56, "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    "sha256: 448 bits, two blocks");
  s := "xxabcyy";
  Check.Check(Sha(s, 2, 3, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    "sha256: from pos");
  (* about the end of a block: 55 bytes leave room for the padding, 56
     don't; openssl's digests *)
  As(55, "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318", "sha256: 55 a's");
  As(56, "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a", "sha256: 56 a's");
  As(57, "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6", "sha256: 57 a's");
  As(63, "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34", "sha256: 63 a's");
  As(64, "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb", "sha256: 64 a's");
  As(65, "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0", "sha256: 65 a's");
  As(119, "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb", "sha256: 119 a's");
  As(120, "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c", "sha256: 120 a's");
  As(128, "6836cf13bac400e9105071cd6af47084dfacad4e5e302c94bfed24e013afb73e", "sha256: 128 a's");
  (* every byte value, the high ones above all *)
  FOR i := 0 TO 255 DO s[i] := CHR(i) END;
  Check.Check(Sha(s, 0, 256, "40aff2e9d2d8922e47afd4648e6967497158785fbd1da870e7110266bf944880"),
    "sha256: bytes 0 to 255");
  NEW(big, 1000000);
  FOR i := 0 TO LEN(big^) - 1 DO big[i] := "a" END;
  Check.Check(Sha(big^, 0, LEN(big^), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"),
    "sha256: a million a's")
END Digests;

(* The text of file name.crt in buf, n characters *)
PROCEDURE Read(name: ARRAY OF CHAR; VAR buf: ARRAY OF CHAR; VAR n: LONGINT): BOOLEAN;
  VAR cmd: Name; i: LONGINT; c: Child.Child;
BEGIN
  i := 0; Append(cmd, i, "cat "); Append(cmd, i, certs); Append(cmd, i, name); Append(cmd, i, ".crt");
  RETURN Child.Spawn(cmd, "", 0, c) & (Child.Wait(c, buf, n) = 0) & (n > 0) & (n < LEN(buf))
END Read;

(* Line k (from 0) of out[0..n-1] in line *)
PROCEDURE Line(VAR out: ARRAY OF CHAR; n, k: LONGINT; VAR line: ARRAY OF CHAR);
  VAR i, j: LONGINT;
BEGIN
  i := 0;
  WHILE (k > 0) & (i < n) DO IF out[i] = 0AX THEN DEC(k) END; INC(i) END;
  j := 0;
  WHILE (i < n) & (out[i] # 0AX) & (j < LEN(line) - 1) DO line[j] := out[i]; INC(i); INC(j) END;
  line[j] := 0X
END Line;

(* The number s, in decimal, or -1 *)
PROCEDURE Number(s: ARRAY OF CHAR): HUGEINT;
  VAR i: LONGINT; v: HUGEINT;
BEGIN
  v := 0; i := 0;
  IF s[0] = 0X THEN RETURN -1 END;
  WHILE s[i] # 0X DO
    IF (s[i] < "0") OR (s[i] > "9") THEN RETURN -1 END;
    v := v * 10 + ORD(s[i]) - ORD("0"); INC(i)
  END;
  RETURN v
END Number;

(* What openssl says of name.crt, by cert-info.sh: its hashes, and its
   validity in seconds since the epoch *)
PROCEDURE Openssl(name: ARRAY OF CHAR; VAR cert, key: Hash; VAR notBefore, notAfter: HUGEINT): BOOLEAN;
  VAR cmd: Name; i, n: LONGINT; c: Child.Child; out: ARRAY 1024 OF CHAR; t: Hash;
BEGIN
  i := 0; Append(cmd, i, "sh cert-info.sh "); Append(cmd, i, certs); Append(cmd, i, name);
  Append(cmd, i, ".crt");
  IF ~Child.Spawn(cmd, "", 0, c) OR (Child.Wait(c, out, n) # 0) THEN RETURN FALSE END;
  Line(out, n, 0, cert); Line(out, n, 5, key);
  Line(out, n, 3, t); notBefore := Number(t);
  Line(out, n, 4, t); notAfter := Number(t);
  RETURN (cert[0] = "S") & (key[0] = "S") & (notBefore >= 0) & (notAfter >= 0)
END Openssl;

(* name.crt's hashes and validity, by TlsCerts and by openssl, alike;
   its hashes in cert and key, its notAfter in notAfter *)
PROCEDURE File(name: ARRAY OF CHAR; VAR cert, key: Hash; VAR notAfter: HUGEINT);
  VAR n: LONGINT; wantCert, wantKey: Hash; label: Name; i: LONGINT;
    before, wantBefore, wantAfter: HUGEINT;
BEGIN
  cert := ""; key := ""; notAfter := 0;
  IF Read(name, pem, n) & Openssl(name, wantCert, wantKey, wantBefore, wantAfter) THEN
    i := 0; Append(label, i, "hashes as openssl's: "); Append(label, i, name);
    Check.Check(TlsCerts.CertHash(pem, n, cert) & (cert = wantCert)
      & TlsCerts.KeyHash(pem, n, key) & (key = wantKey), label);
    i := 0; Append(label, i, "validity as openssl's: "); Append(label, i, name);
    Check.Check(TlsCerts.Validity(pem, n, before, notAfter)
      & (before = wantBefore) & (notAfter = wantAfter), label)
  ELSE
    i := 0; Append(label, i, "read and openssl: "); Append(label, i, name);
    Check.Check(FALSE, label)
  END
END File;

PROCEDURE Files(k: ARRAY OF CHAR);
  CONST names = 8;
  VAR i, j, n, m: LONGINT; name, label: Name;
    cert, key: ARRAY names OF Hash; base: ARRAY names OF ARRAY 16 OF CHAR;
    after: ARRAY names OF HUGEINT;
    differ: BOOLEAN; got: Hash;
BEGIN
  base[0] := "ca-"; base[1] := "server-"; base[2] := "self-"; base[3] := "other-";
  base[4] := "client1-"; base[5] := "client2-"; base[6] := "expired-"; base[7] := "renewed-";
  FOR i := 0 TO names - 1 DO
    j := 0; Append(name, j, base[i]); Append(name, j, k);
    File(name, cert[i], key[i], after[i])
  END;
  (* expired-K's ends with January 2020; renewed-K's after 2049, a
     GeneralizedTime *)
  j := 0; Append(label, j, "expired: notAfter 2020-02-01T00:00:00Z: "); Append(label, j, k);
  Check.Check(after[6] = 1580515200, label);
  j := 0; Append(label, j, "renewed: notAfter after 2049: "); Append(label, j, k);
  Check.Check(after[7] >= 2524608000, label);
  (* each certificate's own key, but renewed-K's, which is self-K's *)
  differ := TRUE;
  FOR i := 0 TO names - 2 DO
    FOR j := i + 1 TO names - 2 DO
      differ := differ & (cert[i] # cert[j]) & (key[i] # key[j])
    END
  END;
  j := 0; Append(label, j, "the certificates' and keys' hashes differ: "); Append(label, j, k);
  Check.Check(differ, label);
  j := 0; Append(label, j, "renewed, same key, another certificate: "); Append(label, j, k);
  Check.Check((key[7] = key[2]) & (cert[7] # cert[2]) & (cert[7][0] = "S"), label);
  (* a chain, as tls_peer_cert_chain_pem gives it: the first is used *)
  j := 0; Append(name, j, "server-"); Append(name, j, k);
  IF Read(name, pem, n) THEN
    j := 0; Append(name, j, "ca-"); Append(name, j, k);
    IF Read(name, pem2, m) & (n + m + 9 < LEN(pem)) THEN
      FOR i := 0 TO m - 1 DO pem[n + i] := pem2[i] END;
      j := 0; Append(label, j, "a chain gives its first's hashes: "); Append(label, j, k);
      Check.Check(TlsCerts.KeyHash(pem, n + m, got) & (got = key[1])
        & TlsCerts.CertHash(pem, n + m, got) & (got = cert[1]), label);
      (* and text before it, as openssl x509 -text writes *)
      FOR i := n + m - 1 TO 0 BY -1 DO pem[i + 9] := pem[i] END;
      pem2 := "Subject:"; pem2[8] := 0AX;
      FOR i := 0 TO 8 DO pem[i] := pem2[i] END;
      j := 0; Append(label, j, "text before the certificate: "); Append(label, j, k);
      Check.Check(TlsCerts.KeyHash(pem, n + m + 9, got) & (got = key[1]), label)
    ELSE Check.Check(FALSE, "read ca")
    END
  ELSE Check.Check(FALSE, "read server")
  END
END Files;

(* s as PEM text, n characters: neither hash, and hash "", nor validity *)
PROCEDURE NotCert(s: ARRAY OF CHAR; n: LONGINT; label: ARRAY OF CHAR);
  VAR h1, h2: Hash; t1, t2: HUGEINT;
BEGIN
  h1 := "x"; h2 := "x";
  Check.Check(~TlsCerts.CertHash(s, n, h1) & (h1 = "") & ~TlsCerts.KeyHash(s, n, h2) & (h2 = "")
    & ~TlsCerts.Validity(s, n, t1, t2), label)
END NotCert;

(* der, len bytes, with its notBefore, a UTCTime at der[at], changed to
   time: its notBefore by Times, or -1 if FALSE *)
PROCEDURE NotBefore(der: TlsCerts.Bytes; len, at: LONGINT; time: ARRAY OF CHAR): HUGEINT;
  VAR i: LONGINT; was: ARRAY 16 OF CHAR; before, after: HUGEINT; ok: BOOLEAN;
BEGIN
  FOR i := 0 TO 14 DO was[i] := der[at + i] END;
  i := 0; WHILE time[i] # 0X DO der[at + i] := time[i]; INC(i) END;
  ok := TlsCerts.Times(der^, len, before, after);
  FOR i := 0 TO 14 DO der[at + i] := was[i] END;
  IF ok THEN RETURN before ELSE RETURN -1 END
END NotBefore;

PROCEDURE Length(s: ARRAY OF CHAR): LONGINT;
  VAR n: LONGINT;
BEGIN n := 0; WHILE s[n] # 0X DO INC(n) END; RETURN n
END Length;

(* begin, body and end into s *)
PROCEDURE Pem(begin, body, end: ARRAY OF CHAR; VAR s: ARRAY OF CHAR): LONGINT;
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, begin); Append(s, i, body); Append(s, i, end); RETURN i
END Pem;

PROCEDURE Bad;
  CONST
    b = "-----BEGIN CERTIFICATE-----"; e = "-----END CERTIFICATE-----";
  VAR s: ARRAY 256 OF CHAR; i, n, len, pos, m: LONGINT; der: TlsCerts.Bytes;
    ok, cut: BOOLEAN; k: INTEGER; v: ARRAY 5 OF CHAR; h: Hash; t1, t2, t3, t4: HUGEINT;
BEGIN
  s := ""; NotCert(s, 0, "no text");
  s := "hello"; NotCert(s, 5, "no certificate");
  NotCert(s, Pem(b, "MIIB", "", s), "no END");
  NotCert(s, Pem(b, "MII!", e, s), "not base64");
  NotCert(s, Pem(b, "MIIBAA=", e, s), "base64 cut short");
  NotCert(s, Pem(b, "MI==AAAA", e, s), "base64 after padding");
  NotCert(s, Pem(b, "", e, s), "nothing in it");
  NotCert(s, Pem("-----BEGIN PRIVATE KEY-----", "MIIB", "-----END PRIVATE KEY-----", s),
    "not a certificate");
  n := Pem("xx", b, "MAA=", s); i := n; Append(s, i, e);
  NotCert(s, 10, "BEGIN past the length given");
  (* DER that isn't a certificate, an empty SEQUENCE: its hash, no key *)
  n := Pem(b, "MAA=", e, s);
  Check.Check(TlsCerts.CertHash(s, n, h) & ~TlsCerts.KeyHash(s, n, h) & (h = "")
    & ~TlsCerts.Validity(s, n, t1, t2), "an empty SEQUENCE: a hash, no key or validity");

  (* self-ec's DER, cut short anywhere: FALSE; changed anywhere: no halt *)
  IF Read("self-ec", pem, n) & TlsCerts.Der(pem, n, der, len) THEN
    ok := TRUE;
    FOR i := 0 TO len - 1 DO
      ok := ok & ~TlsCerts.PublicKey(der^, i, pos, m) & ~TlsCerts.Times(der^, i, t1, t2)
    END;
    Check.Check(ok, "DER cut short: FALSE");
    Check.Check(TlsCerts.PublicKey(der^, len, pos, m) & (pos > 0) & (pos + m < len), "DER whole: its key");
    Check.Check(TlsCerts.Times(der^, len, t1, t2) & (t1 > 1700000000) & (t2 > t1), "DER whole: its validity");
    (* its notBefore, the first UTCTime: tag 17H, length 13 *)
    pos := 0; WHILE (pos < len - 1) & ~((der[pos] = 17X) & (der[pos + 1] = 0DX)) DO INC(pos) END;
    INC(pos, 2);
    Check.Check((pos < len) & (NotBefore(der, len, pos, "") = t1), "a UTCTime found");
    Check.Check(NotBefore(der, len, pos, "700101000000Z") = 0, "UTCTime 70: 1970, the epoch");
    Check.Check(NotBefore(der, len, pos, "491231235959Z") = 2524607999, "UTCTime 49: 2049");
    Check.Check(NotBefore(der, len, pos, "500101000000Z") = -631152000, "UTCTime 50: 1950");
    Check.Check(NotBefore(der, len, pos, "000229120000Z") = 951825600, "UTCTime 00: 2000, a leap day");
    Check.Check(NotBefore(der, len, pos, "991231235960Z") = 946684800, "a leap second: as the next");
    Check.Check(NotBefore(der, len, pos, "001301000000Z") = -1, "month 13: FALSE");
    Check.Check(NotBefore(der, len, pos, "000001000000Z") = -1, "month 0: FALSE");
    Check.Check(NotBefore(der, len, pos, "000132000000Z") = -1, "day 32: FALSE");
    Check.Check(NotBefore(der, len, pos, "000100000000Z") = -1, "day 0: FALSE");
    Check.Check(NotBefore(der, len, pos, "000101240000Z") = -1, "hour 24: FALSE");
    Check.Check(NotBefore(der, len, pos, "000101006000Z") = -1, "minute 60: FALSE");
    Check.Check(NotBefore(der, len, pos, "000101000061Z") = -1, "second 61: FALSE");
    Check.Check(NotBefore(der, len, pos, "0001010000000") = -1, "no Z: FALSE");
    Check.Check(NotBefore(der, len, pos, "00010100000aZ") = -1, "not a digit: FALSE");
    Check.Check(NotBefore(der, len, pos, "00010100000 Z") = -1, "a space: FALSE");
    der[pos - 2] := 18X;
    Check.Check(~TlsCerts.Times(der^, len, t3, t4), "GeneralizedTime of 13: FALSE");
    der[pos - 2] := 17X;
    Check.Check(TlsCerts.Times(der^, len, t3, t4) & (t3 = t1) & (t4 = t2), "restored: as before");
    v[0] := 0X; v[1] := 7FX; v[2] := 80X; v[3] := 84X; v[4] := 0FFX;
    cut := FALSE;
    FOR i := 0 TO len - 1 DO
      FOR k := 0 TO 4 DO
        s[0] := der[i]; der[i] := v[k];
        IF TlsCerts.PublicKey(der^, len, pos, m) THEN
          cut := cut OR (pos < 0) OR (m <= 0) OR (pos + m > len)
        END;
        IF TlsCerts.Times(der^, len, t3, t4) THEN END;
        der[i] := s[0]
      END
    END;
    Check.Check(~cut, "DER changed: no halt, the key within it, a validity or FALSE")
  ELSE Check.Check(FALSE, "read self-ec")
  END
END Bad;

BEGIN
  Digests;
  Files("ec"); Files("rsa");
  Bad;
  Check.Summary
END TestCerts.
