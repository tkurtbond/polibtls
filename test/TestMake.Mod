MODULE TestMake; (* Keys and certificates made by TlsMake *)

(* Makes, for EC and RSA keys alike, a CA, a server certificate it
   signs, a self-signed server and client, an expired certificate and a
   renewal of the self-signed one with the same key, into build/made/
   (from test/, ../build/made/, made afresh each run). Then checks them
   by TlsCerts, by openssl where it runs, and by handshakes over
   TestPeers' socket pairs, both ends Oberon (as TestInfo); and checks
   that each bad argument or file gives FALSE, a reason, and no file. *)

IMPORT Check, Child, Clocks, Instants, Tls, TlsCerts, TlsMake, TestPeers;

CONST
  dir = "../build/made/";
  day = 86400;

TYPE
  Name = ARRAY 256 OF CHAR;

VAR
  now: HUGEINT;  (* seconds since the epoch *)
  pem: ARRAY 16384 OF CHAR;
  openssl: BOOLEAN;  (* whether an openssl runs, to cross-check *)

PROCEDURE Append(VAR s: ARRAY OF CHAR; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0;
  WHILE (j < LEN(part)) & (part[j] # 0X) & (i < LEN(s) - 1) DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

(* dir, name, "-", k and ext: as "../build/made/ca-ec.crt" *)
PROCEDURE Path(name, k, ext: ARRAY OF CHAR; VAR s: ARRAY OF CHAR);
  VAR i: LONGINT;
BEGIN
  i := 0; Append(s, i, dir); Append(s, i, name);
  IF k # "" THEN Append(s, i, "-"); Append(s, i, k) END;
  Append(s, i, ext)
END Path;

(* label, then " (", detail and ")" *)
PROCEDURE Label(label, detail: ARRAY OF CHAR; VAR s: ARRAY OF CHAR);
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, label); Append(s, i, " ("); Append(s, i, detail); Append(s, i, ")")
END Label;

(* Runs command; its output in out, n characters; TRUE if it exited 0 *)
PROCEDURE Run(command: ARRAY OF CHAR; VAR out: ARRAY OF CHAR; VAR n: LONGINT): BOOLEAN;
  VAR c: Child.Child; ok: BOOLEAN;
BEGIN
  ok := Child.Spawn(command, "", 0, c) & (Child.Wait(c, out, n) = 0);
  IF n < LEN(out) THEN out[n] := 0X ELSE out[LEN(out) - 1] := 0X END;
  RETURN ok
END Run;

(* Runs command, part1 and part2, joined by spaces; TRUE if it exited 0
   and its output contains want *)
PROCEDURE Says(command, part1, part2, want: ARRAY OF CHAR): BOOLEAN;
  VAR cmd: ARRAY 1024 OF CHAR; out: ARRAY 8192 OF CHAR; i, n: LONGINT;
BEGIN
  i := 0; Append(cmd, i, command); Append(cmd, i, " "); Append(cmd, i, part1);
  Append(cmd, i, " "); Append(cmd, i, part2);
  RETURN Run(cmd, out, n) & Check.Contains(out, want)
END Says;

PROCEDURE Exists(file: ARRAY OF CHAR): BOOLEAN;
BEGIN RETURN Says("test -e", file, "&& echo yes", "yes")
END Exists;

(* The text of file in pem, n characters *)
PROCEDURE Read(file: ARRAY OF CHAR; VAR n: LONGINT): BOOLEAN;
  VAR cmd: Name; i: LONGINT;
BEGIN
  i := 0; Append(cmd, i, "cat "); Append(cmd, i, file);
  RETURN Run(cmd, pem, n) & (n > 0) & (n < LEN(pem))
END Read;

(* Whether certificate file is valid from notBefore to notAfter, by
   TlsCerts *)
PROCEDURE Valid(file: ARRAY OF CHAR; notBefore, notAfter: HUGEINT): BOOLEAN;
  VAR n: LONGINT; b, a: HUGEINT;
BEGIN
  RETURN Read(file, n) & TlsCerts.Validity(pem, n, b, a) & (b = notBefore) & (a = notAfter)
END Valid;

PROCEDURE Hashes(file: ARRAY OF CHAR; VAR cert, key: Name): BOOLEAN;
  VAR n: LONGINT;
BEGIN
  cert := ""; key := "";
  RETURN Read(file, n) & TlsCerts.CertHash(pem, n, cert) & TlsCerts.KeyHash(pem, n, key)
END Hashes;

(* A key into name-k.key: EC or RSA as k *)
PROCEDURE Key(name, k: ARRAY OF CHAR): BOOLEAN;
  VAR key: Name; error: Tls.String; ok: BOOLEAN;
BEGIN
  Path(name, k, ".key", key);
  IF k = "ec" THEN ok := TlsMake.EcKey(key, error) ELSE ok := TlsMake.RsaKey(key, 2048, error) END;
  IF ~ok THEN Check.Check(FALSE, error^) END;
  RETURN ok & (error = NIL)
END Key;

(* A certificate into name-k.crt for key name-k.key (or keyName-k.key),
   self-signed if caName = "", else signed by caName-k *)
PROCEDURE Cert(name, keyName, k, cn, names: ARRAY OF CHAR; ca: BOOLEAN;
    notBefore, notAfter: HUGEINT; caName: ARRAY OF CHAR): BOOLEAN;
  VAR crt, key, caCrt, caKey: Name; error: Tls.String; ok: BOOLEAN;
BEGIN
  Path(name, k, ".crt", crt); Path(keyName, k, ".key", key);
  IF caName = "" THEN
    ok := TlsMake.SelfSigned(key, crt, cn, names, ca, notBefore, notAfter, error)
  ELSE
    Path(caName, k, ".crt", caCrt); Path(caName, k, ".key", caKey);
    ok := TlsMake.Signed(key, crt, cn, names, ca, notBefore, notAfter, caCrt, caKey, error)
  END;
  IF ~ok THEN Check.Check(FALSE, error^) END;
  RETURN ok & (error = NIL)
END Cert;

(* A file's mode as ls -l shows it, as "-rw-------" *)
PROCEDURE Mode(file, want: ARRAY OF CHAR): BOOLEAN;
BEGIN RETURN Says("ls -l", file, "", want)
END Mode;

PROCEDURE Make(k: ARRAY OF CHAR);
  VAR label, file, file2: Name; selfCert, selfKey, renewedCert, renewedKey: Name;
BEGIN
  Label("keys made", k, label);
  Check.Check(Key("ca", k) & Key("server", k) & Key("self", k) & Key("client", k)
    & Key("expired", k), label);
  Label("CA, self-signed", k, label);
  Check.Check(Cert("ca", "ca", k, "polibtls test CA", "", TRUE, now - day, now + 3650 * day, ""),
    label);
  Label("server certificate, signed by the CA", k, label);
  Check.Check(Cert("server", "server", k, "localhost", "localhost 127.0.0.1 ::1", FALSE,
    now - day, now + 365 * day, "ca"), label);
  Label("self-signed server certificate", k, label);
  Check.Check(Cert("self", "self", k, "self.example", "self.example *.self.example", FALSE,
    now - day, now + 365 * day, ""), label);
  Label("self-signed client certificate, no names", k, label);
  Check.Check(Cert("client", "client", k, "client", "", FALSE, now - day, now + 365 * day, ""),
    label);
  Label("expired certificate", k, label);
  (* 2020-01-01 to 2020-12-31: UTCTime *)
  Check.Check(Cert("expired", "expired", k, "expired", "", FALSE, 1577836800, 1609372800, ""),
    label);
  Label("renewed: self's key, 10000 days", k, label);
  (* past 2049: GeneralizedTime *)
  Check.Check(Cert("renewed", "self", k, "self.example", "self.example", FALSE,
    now, now + 10000 * day, ""), label);

  Path("ca", k, ".crt", file); Label("CA's validity, by TlsCerts", k, label);
  Check.Check(Valid(file, now - day, now + 3650 * day), label);
  Path("expired", k, ".crt", file); Label("expired's validity, UTCTime", k, label);
  Check.Check(Valid(file, 1577836800, 1609372800), label);
  Path("renewed", k, ".crt", file); Label("renewed's validity, GeneralizedTime", k, label);
  Check.Check(Valid(file, now, now + 10000 * day), label);

  Path("self", k, ".crt", file); Path("renewed", k, ".crt", file2);
  Label("renewed: the same key hash as self's, another certificate hash", k, label);
  Check.Check(Hashes(file, selfCert, selfKey) & Hashes(file2, renewedCert, renewedKey)
    & (selfKey = renewedKey) & (selfCert # renewedCert), label);

  Path("server", k, ".key", file); Label("key file mode 0600", k, label);
  Check.Check(Mode(file, "-rw-------"), label);
  Path("server", k, ".crt", file); Label("certificate file mode 0644", k, label);
  Check.Check(Mode(file, "-rw-r--r--"), label)
END Make;

(* What openssl makes of them *)
PROCEDURE Openssl(k: ARRAY OF CHAR);
  VAR label, ca, server, self, cmd, sig: Name; i: LONGINT;
BEGIN
  IF k = "ec" THEN sig := "Signature Algorithm: ecdsa-with-SHA256"
  ELSE sig := "Signature Algorithm: sha256WithRSAEncryption"
  END;
  IF ~openssl THEN Label("openssl checks", k, label); Check.Skip(label); RETURN END;
  Path("ca", k, ".crt", ca); Path("server", k, ".crt", server); Path("self", k, ".crt", self);
  i := 0; Append(cmd, i, "openssl verify -CAfile "); Append(cmd, i, ca);
  Label("openssl verifies the server certificate by the CA", k, label);
  Check.Check(Says(cmd, server, "", ": OK"), label);
  Label("openssl verifies the CA", k, label);
  Check.Check(Says(cmd, ca, "", ": OK"), label);
  Label("openssl: the CA is a CA", k, label);
  Check.Check(Says("openssl x509 -noout -text -in", ca, "", "CA:TRUE")
    & Says("openssl x509 -noout -text -in", ca, "", "Certificate Sign, CRL Sign"), label);
  Label("openssl: the server's names", k, label);
  Check.Check(Says("openssl x509 -noout -text -in", server, "", "DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1"),
    label);
  Label("openssl: the server is no CA, signed with SHA-256, v3", k, label);
  Check.Check(Says("openssl x509 -noout -text -in", server, "", "CA:FALSE")
    & Says("openssl x509 -noout -text -in", server, "", sig)
    & Says("openssl x509 -noout -text -in", server, "", "Version: 3")
    & Says("openssl x509 -noout -text -in", server, "", "X509v3 Authority Key Identifier"),
    label);
  Label("openssl: the self-signed server's names", k, label);
  Check.Check(Says("openssl x509 -noout -text -in", self, "", "DNS:self.example, DNS:*.self.example"),
    label)
END Openssl;

(* A server context with key pair name-k *)
PROCEDURE Server(name, k: ARRAY OF CHAR): Tls.Context;
  VAR c: Tls.Config; x: Tls.Context; crt, key: Name; ok: BOOLEAN;
BEGIN
  c := Tls.NewConfig();
  Path(name, k, ".crt", crt); Path(name, k, ".key", key);
  ok := c.SetKeypairFile(crt, key);
  c.VerifyClientOptional; c.InsecureNoVerifyCert;
  x := Tls.NewServer();
  ok := ok & x.Configure(c);
  c.Close;
  IF ~ok THEN Check.Check(FALSE, "server context") END;
  RETURN x
END Server;

(* A client config verifying by CA certificate caName-k.crt,
   presenting client-k unless cert = "" *)
PROCEDURE Client(caName, k, cert: ARRAY OF CHAR): Tls.Config;
  VAR c: Tls.Config; ca, crt, key: Name; ok: BOOLEAN;
BEGIN
  c := Tls.NewConfig();
  Path(caName, k, ".crt", ca); ok := c.SetCaFile(ca);
  IF cert # "" THEN Path(cert, k, ".crt", crt); Path(cert, k, ".key", key);
    ok := ok & c.SetKeypairFile(crt, key)
  END;
  IF ~ok THEN Check.Check(FALSE, "client config") END;
  RETURN c
END Client;

(* A handshake between server x and a client with config c asking for
   servername, over a non-blocking socket pair, each side in turn: TRUE
   if both finished; the server's end in s *)
PROCEDURE Connect(x: Tls.Context; c: Tls.Config; servername: ARRAY OF CHAR;
    VAR s: Tls.Connection): BOOLEAN;
  VAR k: Tls.Connection; a, b, turns: LONGINT; sDone, kDone, ok: BOOLEAN;
BEGIN
  s := NIL; k := NIL; ok := FALSE;
  IF TestPeers.Pair(a, b, TRUE) THEN
    IF x.AcceptSocket(a, s) & Tls.ConnectSocket(c, b, servername, k) THEN
      sDone := FALSE; kDone := FALSE; turns := 0;
      WHILE ~(sDone & kDone) & (turns < 20) DO
        IF ~sDone THEN
          sDone := s.Handshake();
          IF ~sDone & (s.error.kind # Tls.wouldBlock) THEN turns := 100 END
        END;
        IF ~kDone THEN
          kDone := k.Handshake();
          IF ~kDone & (k.error.kind # Tls.wouldBlock) THEN turns := 100 END
        END;
        INC(turns)
      END;
      ok := sDone & kDone
    END;
    IF k # NIL THEN k.Discard END;
    IF TestPeers.Close(a) & TestPeers.Close(b) THEN END
  END;
  RETURN ok
END Connect;

(* Whether a client of x with c asking for name verifies as want *)
PROCEDURE Verifies(x: Tls.Context; c: Tls.Config; name, k: ARRAY OF CHAR; want: BOOLEAN);
  VAR s: Tls.Connection; label, detail: Name; i: LONGINT;
BEGIN
  i := 0; Append(detail, i, name); Append(detail, i, ", "); Append(detail, i, k);
  IF want THEN Label("libtls verifies the server by the CA as", detail, label)
  ELSE Label("libtls rejects the server by the CA as", detail, label)
  END;
  Check.Check(Connect(x, c, name, s) = want, label);
  IF s # NIL THEN s.Discard END
END Verifies;

(* libtls takes them *)
PROCEDURE Handshakes(k: ARRAY OF CHAR);
  VAR x: Tls.Context; c: Tls.Config; s: Tls.Connection; label, file, cert, key: Name;
    hash: Tls.String;
BEGIN
  x := Server("server", k); c := Client("ca", k, "client");
  Verifies(x, c, "localhost", k, TRUE); Verifies(x, c, "127.0.0.1", k, TRUE);
  Verifies(x, c, "::1", k, TRUE); Verifies(x, c, "other.example", k, FALSE);
  Label("the server sees the client's certificate as TlsCerts hashes it", k, label);
  Path("client", k, ".crt", file);
  IF Connect(x, c, "localhost", s) & Hashes(file, cert, key) THEN
    hash := s.PeerCertHash();
    Check.Check((hash # NIL) & (hash^ = cert), label)
  ELSE Check.Check(FALSE, label)
  END;
  IF s # NIL THEN s.Discard END;
  c.Close; x.Close;

  x := Server("self", k); c := Client("self", k, "");
  Label("libtls verifies a self-signed server by itself, wildcard", k, label);
  Check.Check(Connect(x, c, "www.self.example", s), label);
  IF s # NIL THEN s.Discard END;
  c.Close; x.Close;

  x := Server("expired", k); c := Client("expired", k, "");
  Label("libtls rejects the expired certificate", k, label);
  Check.Check(~Connect(x, c, "expired", s), label);
  IF s # NIL THEN s.Discard END;
  c.Close; x.Close
END Handshakes;

(* --- What fails --- *)

(* That ok is FALSE with an error containing want, and file doesn't exist *)
PROCEDURE Fails(ok: BOOLEAN; error: Tls.String; want, file, label: ARRAY OF CHAR);
BEGIN
  Check.Check(~ok & (error # NIL) & Check.Contains(error^, want) & ~Exists(file), label)
END Fails;

PROCEDURE Bad;
  VAR error: Tls.String; ok: BOOLEAN; key, crt, caCrt, caKey, rsaKey, missing, enc, cmd: Name;
    long: ARRAY 66 OF CHAR; open: ARRAY 4 OF CHAR; i, n: LONGINT; out: ARRAY 1024 OF CHAR;
BEGIN
  Path("server", "ec", ".key", key); Path("bad", "", ".crt", crt);
  Path("ca", "ec", ".crt", caCrt); Path("ca", "ec", ".key", caKey);
  Path("ca", "rsa", ".key", rsaKey); Path("missing", "", ".key", missing);

  ok := TlsMake.EcKey(key, error);
  Check.Check(~ok & (error # NIL) & Check.Contains(error^, "exists"),
    "a key never replaces a file");
  Check.Check(Exists(key) & Cert("server", "server", "ec", "localhost", "", FALSE, now, now + day, "ca"),
    "the key it would have replaced is still there and good");
  ok := TlsMake.EcKey("../build/made/no/such/dir.key", error);
  Fails(ok, error, "No such file", "../build/made/no/such/dir.key", "a key in a missing directory");
  ok := TlsMake.RsaKey(missing, 1024, error);
  Fails(ok, error, "out of range", missing, "an RSA key of 1024 bits");
  ok := TlsMake.RsaKey(missing, 32768, error);
  Fails(ok, error, "out of range", missing, "an RSA key of 32768 bits");

  ok := TlsMake.SelfSigned(missing, crt, "x", "", FALSE, now, now + day, error);
  Fails(ok, error, "cannot read key file", crt, "a missing key file");
  ok := TlsMake.SelfSigned(caCrt, crt, "x", "", FALSE, now, now + day, error);
  Fails(ok, error, "no unencrypted private key", crt, "a certificate as the key file");
  ok := TlsMake.SelfSigned(key, crt, "x", "good.example bad_name", FALSE, now, now + day, error);
  Fails(ok, error, "not an IP address or a DNS name: 'bad_name'", crt, "a bad name");
  ok := TlsMake.SelfSigned(key, crt, "x", "a.example 300.1.2.3/8", FALSE, now, now + day, error);
  Fails(ok, error, "not an IP address or a DNS name", crt, "a bad address");
  ok := TlsMake.SelfSigned(key, crt, "", "", FALSE, now, now + day, error);
  Fails(ok, error, "common name is empty", crt, "an empty common name");
  FOR i := 0 TO 64 DO long[i] := "a" END; long[65] := 0X;
  ok := TlsMake.SelfSigned(key, crt, long, "", FALSE, now, now + day, error);
  Fails(ok, error, "cannot set the common name", crt, "a common name of 65 characters");
  long[64] := 0X;
  ok := TlsMake.SelfSigned(key, crt, long, "", FALSE, now, now + day, error);
  Check.Check(ok & (error = NIL) & Exists(crt), "a common name of 64 characters");
  ok := TlsMake.SelfSigned(key, crt, "x", "", FALSE, now, now - 1, error);
  Fails(ok, error, "notAfter is before notBefore", "../build/made/none.crt", "notAfter before notBefore");
  FOR i := 0 TO 3 DO open[i] := "a" END;
  ok := TlsMake.SelfSigned(key, "../build/made/open.crt", open, "", FALSE, now, now + day, error);
  Fails(ok, error, "no 0X", "../build/made/open.crt", "a string without 0X");
  ok := TlsMake.Signed(key, "../build/made/mismatch.crt", "x", "", FALSE, now, now + day,
    caCrt, rsaKey, error);
  Fails(ok, error, "isn't the one of the CA certificate", "../build/made/mismatch.crt",
    "a CA key that isn't the CA's");
  ok := TlsMake.Signed(key, "../build/made/noca.crt", "x", "", FALSE, now, now + day, "", caKey, error);
  Fails(ok, error, "no CA certificate file", "../build/made/noca.crt", "Signed without a CA");
  ok := TlsMake.SelfSigned(key, "../build/made/no/such/dir.crt", "x", "", FALSE, now, now + day, error);
  Fails(ok, error, "No such file", "../build/made/no/such/dir.crt", "a certificate in a missing directory");

  IF openssl THEN
    Path("encrypted", "", ".key", enc);
    i := 0; Append(cmd, i, "openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes256 -pass pass:secret -out ");
    Append(cmd, i, enc);
    IF Run(cmd, out, n) THEN
      ok := TlsMake.SelfSigned(enc, "../build/made/enc.crt", "x", "", FALSE, now, now + day, error);
      Fails(ok, error, "no unencrypted private key", "../build/made/enc.crt",
        "an encrypted key fails, asking for no passphrase")
    ELSE Check.Check(FALSE, "openssl made an encrypted key")
    END
  ELSE Check.Skip("an encrypted key fails, asking for no passphrase")
  END;

  Check.Check(~Says("ls", dir, "| grep -v '[.]crt$' | grep -v '[.]key$'", ""),
    "no temporary file left behind")
END Bad;

PROCEDURE Setup(): BOOLEAN;
  VAR t: Instants.Instant; out: Name; n: LONGINT;
BEGIN
  Clocks.Now(t); now := Instants.UnixSeconds(t);
  openssl := Child.Openssl() # Child.noOpenssl;
  RETURN Run("rm -rf ../build/made && mkdir ../build/made", out, n)
END Setup;

BEGIN
  TestPeers.IgnoreBrokenPipe;
  IF Setup() THEN
    Make("ec"); Make("rsa");
    Openssl("ec"); Openssl("rsa");
    Handshakes("ec"); Handshakes("rsa");
    Bad
  ELSE Check.Check(FALSE, "made ../build/made")
  END;
  Check.Summary
END TestMake.
