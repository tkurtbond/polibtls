MODULE TestInfo; (* Connection info and the peer's certificate, both ends *)

(* Over non-blocking socket pairs from TestPeers, both ends Oberon, the
   handshakes driven in turn by this program (as TestTasks' "alone"), so
   both ends can be asked, and memcheck sees all of it. What each
   certificate should give comes from openssl, by test/cert-info.sh.
   Certificates are test/make-certs.sh's, from test/. *)

IMPORT Check, Tls, TestPeers, Child;

CONST
  certs = "../build/certs/";

TYPE
  Name = ARRAY 128 OF CHAR;

  (* What openssl says of a certificate (cert-info.sh) *)
  Info = RECORD
    hash, subject, issuer: Name;
    notBefore, notAfter: HUGEINT
  END;

VAR
  server: Tls.Context;  (* self-K first, other-K for SNI; client certificates optional, not verified *)

PROCEDURE Append(VAR s: ARRAY OF CHAR; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0;
  WHILE (j < LEN(part)) & (part[j] # 0X) & (i < LEN(s) - 1) DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

PROCEDURE Path(name, ext: ARRAY OF CHAR; VAR s: Name);
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, certs); Append(s, i, name); Append(s, i, ext)
END Path;

(* label, then " (", detail and ")" *)
PROCEDURE Label(label, detail: ARRAY OF CHAR; VAR s: ARRAY OF CHAR);
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, label); Append(s, i, " ("); Append(s, i, detail); Append(s, i, ")")
END Label;

PROCEDURE Is(s: Tls.String; want: ARRAY OF CHAR): BOOLEAN;
BEGIN RETURN (s # NIL) & (s^ = want)
END Is;

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

PROCEDURE Number(s: ARRAY OF CHAR): HUGEINT;
  VAR i: LONGINT; v: HUGEINT;
BEGIN
  i := 0; v := 0;
  WHILE (s[i] >= "0") & (s[i] <= "9") DO v := v * 10 + (ORD(s[i]) - ORD("0")); INC(i) END;
  RETURN v
END Number;

(* What openssl says of certificate name.crt *)
PROCEDURE GetInfo(name: ARRAY OF CHAR; VAR info: Info): BOOLEAN;
  VAR cmd, crt, line: Name; i, n: LONGINT; child: Child.Child; out: ARRAY 1024 OF CHAR;
BEGIN
  Path(name, ".crt", crt);
  i := 0; Append(cmd, i, "sh cert-info.sh "); Append(cmd, i, crt);
  IF ~Child.Spawn(cmd, "", 0, child) OR (Child.Wait(child, out, n) # 0) THEN RETURN FALSE END;
  Line(out, n, 0, info.hash); Line(out, n, 1, info.subject); Line(out, n, 2, info.issuer);
  Line(out, n, 3, line); info.notBefore := Number(line);
  Line(out, n, 4, line); info.notAfter := Number(line);
  RETURN (info.hash[0] = "S") & (info.notAfter > info.notBefore)
END GetInfo;

PROCEDURE ServerContext(k: ARRAY OF CHAR): Tls.Context;
  VAR c: Tls.Config; x: Tls.Context; crt, key: Name; ok: BOOLEAN; i: LONGINT; self, other: Name;
BEGIN
  i := 0; Append(self, i, "self-"); Append(self, i, k);
  i := 0; Append(other, i, "other-"); Append(other, i, k);
  c := Tls.NewConfig();
  Path(self, ".crt", crt); Path(self, ".key", key); ok := c.SetKeypairFile(crt, key);
  Path(other, ".crt", crt); Path(other, ".key", key); ok := ok & c.AddKeypairFile(crt, key);
  c.VerifyClientOptional; c.InsecureNoVerifyCert;
  x := Tls.NewServer();
  ok := ok & x.Configure(c);
  c.Close;
  Check.Check(ok, "server context: self and other key pairs, client certificates optional");
  RETURN x
END ServerContext;

(* A client config: presenting cert.crt unless cert = "", accepting a
   self-signed server, verifying its name unless noName, with protocols
   unless "". *)
PROCEDURE ClientConfig(cert, protocols: ARRAY OF CHAR; noName: BOOLEAN): Tls.Config;
  VAR c: Tls.Config; crt, key: Name; ok: BOOLEAN;
BEGIN
  c := Tls.NewConfig(); ok := TRUE;
  IF cert # "" THEN Path(cert, ".crt", crt); Path(cert, ".key", key); ok := c.SetKeypairFile(crt, key) END;
  IF protocols # "" THEN ok := ok & c.SetProtocols(protocols) END;
  c.InsecureNoVerifyCert;
  IF noName THEN c.InsecureNoVerifyName END;
  IF ~ok THEN Check.Check(FALSE, "client config") END;
  RETURN c
END ClientConfig;

(* Both ends of a connection on a new non-blocking socket pair a, b, the
   client with config c asking for servername, the handshakes made in
   turn: TRUE if both finished. *)
PROCEDURE Connect(c: Tls.Config; servername: ARRAY OF CHAR; VAR s, k: Tls.Connection;
    VAR a, b: LONGINT): BOOLEAN;
  VAR sDone, kDone: BOOLEAN; turns: LONGINT;
BEGIN
  s := NIL; k := NIL;
  IF ~TestPeers.Pair(a, b, TRUE) OR ~server.AcceptSocket(a, s)
    OR ~Tls.ConnectSocket(c, b, servername, k) THEN RETURN FALSE
  END;
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
  RETURN sDone & kDone
END Connect;

PROCEDURE Done(s, k: Tls.Connection; a, b: LONGINT);
BEGIN
  IF s # NIL THEN s.Discard END;
  IF k # NIL THEN k.Discard END;
  IF TestPeers.Close(a) & TestPeers.Close(b) THEN END
END Done;

(* Whether conn's peer certificate is as openssl says of info *)
PROCEDURE Matches(conn: Tls.Connection; VAR info: Info): BOOLEAN;
BEGIN
  RETURN conn.PeerCertProvided() & Is(conn.PeerCertHash(), info.hash)
    & Is(conn.PeerCertSubject(), info.subject) & Is(conn.PeerCertIssuer(), info.issuer)
    & (conn.PeerCertNotBefore() = info.notBefore) & (conn.PeerCertNotAfter() = info.notAfter)
END Matches;

(* A client presenting cert.crt: the server sees it as openssl does *)
PROCEDURE ClientCert(cert: ARRAY OF CHAR; VAR hash: Name);
  VAR c: Tls.Config; s, k: Tls.Connection; a, b: LONGINT; info: Info; label: Name;
BEGIN
  hash := "";
  Label("client certificate", cert, label);
  IF ~GetInfo(cert, info) THEN Check.Check(FALSE, label); RETURN END;
  c := ClientConfig(cert, "", FALSE);
  IF Connect(c, "localhost", s, k, a, b) THEN
    Check.Check(Matches(s, info), label);
    COPY(info.hash, hash)
  ELSE Check.Check(FALSE, label)
  END;
  c.Close; Done(s, k, a, b)
END ClientCert;

PROCEDURE ClientCerts(k: ARRAY OF CHAR);
  VAR h1, h2, he, hs: Name; i: LONGINT; name, label: Name; info: Info;
    c: Tls.Config; s, kk: Tls.Connection; a, b: LONGINT;
BEGIN
  i := 0; Append(name, i, "client1-"); Append(name, i, k); ClientCert(name, h1);
  i := 0; Append(name, i, "client2-"); Append(name, i, k); ClientCert(name, h2);
  i := 0; Append(name, i, "self-"); Append(name, i, k); ClientCert(name, hs);
  i := 0; Append(name, i, "expired-"); Append(name, i, k); ClientCert(name, he);
  Label("the clients' hashes differ", k, label);
  Check.Check((h1 # h2) & (h1 # he) & (h2 # he) & (hs # h1), label);
  (* the expired one, accepted without verification, ended in 2020 *)
  IF GetInfo(name, info) THEN
    Label("expired: ended 2020-02-01", k, label);
    Check.Check(info.notAfter = 1580515200, label)
  END;
  (* no certificate *)
  c := ClientConfig("", "", FALSE);
  Label("no client certificate", k, label);
  IF Connect(c, "localhost", s, kk, a, b) THEN
    Check.Check(~s.PeerCertProvided() & (s.PeerCertHash() = NIL) & (s.PeerCertSubject() = NIL)
      & (s.PeerCertIssuer() = NIL) & (s.PeerCertNotBefore() = -1) & (s.PeerCertNotAfter() = -1)
      & ~s.PeerCertContainsName("localhost"), label)
  ELSE Check.Check(FALSE, label)
  END;
  c.Close; Done(s, kk, a, b)
END ClientCerts;

(* What each end sees of the other and of the connection, asking for
   servername: the server presents expect.crt. *)
PROCEDURE Sni(k, servername, expect: ARRAY OF CHAR; noName: BOOLEAN);
  VAR c: Tls.Config; s, kk: Tls.Connection; a, b: LONGINT; info: Info; label, name: Name; i: LONGINT;
BEGIN
  i := 0; Append(name, i, expect); Append(name, i, "-"); Append(name, i, k);
  i := 0; Append(label, i, "servername '"); Append(label, i, servername);
  Append(label, i, "' gets "); Append(label, i, name);
  IF ~GetInfo(name, info) THEN Check.Check(FALSE, label); RETURN END;
  c := ClientConfig("", "", noName);
  IF Connect(c, servername, s, kk, a, b) THEN
    Check.Check(Matches(kk, info), label);
    i := 0; Append(label, i, "server's Servername for '"); Append(label, i, servername); Append(label, i, "'");
    IF (servername = "") OR (servername[0] >= "0") & (servername[0] <= "9") OR (servername[0] = ":") THEN
      Check.Check(s.Servername() = NIL, label)
    ELSE Check.Check(Is(s.Servername(), servername), label)
    END;
    i := 0; Append(label, i, "client's Servername for '"); Append(label, i, servername); Append(label, i, "'");
    IF servername = "" THEN Check.Check(kk.Servername() = NIL, label)
    ELSE Check.Check(Is(kk.Servername(), servername), label)
    END
  ELSE Check.Check(FALSE, label)
  END;
  c.Close; Done(s, kk, a, b)
END Sni;

PROCEDURE Names(k: ARRAY OF CHAR);
  VAR c: Tls.Config; s, kk: Tls.Connection; a, b, i: LONGINT; label, name: Name;
BEGIN
  i := 0; Append(name, i, "client1-"); Append(name, i, k);
  c := ClientConfig(name, "", FALSE);
  Label("PeerCertContainsName", k, label);
  IF Connect(c, "localhost", s, kk, a, b) THEN
    Check.Check(kk.PeerCertContainsName("localhost") & kk.PeerCertContainsName("127.0.0.1")
      & kk.PeerCertContainsName("::1") & ~kk.PeerCertContainsName("other.example")
      & ~kk.PeerCertContainsName("127.0.0.2") & ~kk.PeerCertContainsName(""), label);
    (* client1 has no subject alternative names: its common name counts *)
    Label("PeerCertContainsName, common name only", k, label);
    Check.Check(s.PeerCertContainsName("polibtls test client1")
      & ~s.PeerCertContainsName("polibtls test client2"), label)
  ELSE Check.Check(FALSE, label)
  END;
  c.Close; Done(s, kk, a, b)
END Names;

(* Version and Cipher on both ends, with protocols, expecting version *)
PROCEDURE Protocol(protocols, version: ARRAY OF CHAR);
  VAR c: Tls.Config; s, k: Tls.Connection; a, b: LONGINT; label: Name; sc, kc: Tls.String;
BEGIN
  c := ClientConfig("client2-ec", protocols, FALSE);
  Label("Version", version, label);
  IF Connect(c, "localhost", s, k, a, b) THEN
    Check.Check(Is(s.Version(), version) & Is(k.Version(), version), label);
    sc := s.Cipher(); kc := k.Cipher();
    Label("Cipher, the same on both ends", version, label);
    Check.Check((sc # NIL) & (kc # NIL) & (sc^ = kc^) & (sc[0] # 0X), label);
    Label("client certificate", version, label);
    Check.Check(s.PeerCertProvided(), label)
  ELSE Check.Check(FALSE, label)
  END;
  c.Close; Done(s, k, a, b)
END Protocol;

(* The handshake made inside Read and Write, not Handshake: the info is
   there after. *)
PROCEDURE Implicit;
  VAR c: Tls.Config; s, k: Tls.Connection; a, b, n, m, turns: LONGINT; buf: ARRAY 16 OF CHAR;
    info: Info; got, sent: BOOLEAN;
BEGIN
  c := ClientConfig("client1-ec", "", FALSE);
  IF TestPeers.Pair(a, b, TRUE) & server.AcceptSocket(a, s) & Tls.ConnectSocket(c, b, "localhost", k)
    & GetInfo("client1-ec", info) THEN
    got := FALSE; sent := FALSE; turns := 0;
    WHILE ~(got & sent) & (turns < 20) DO
      IF ~sent THEN sent := k.Write("ping", 0, 4, m) END;
      IF ~got THEN got := s.Read(buf, 0, LEN(buf), n) END;
      INC(turns)
    END;
    Check.Check(got & sent & (n = 4), "handshake in Read and Write");
    Check.Check(Matches(s, info) & Is(k.PeerCertSubject(), "/CN=localhost"),
      "info after a handshake in Read and Write")
  ELSE Check.Check(FALSE, "handshake in Read and Write")
  END;
  c.Close; Done(s, k, a, b)
END Implicit;

PROCEDURE Kind(k: ARRAY OF CHAR);
BEGIN
  server := ServerContext(k);
  ClientCerts(k);
  Sni(k, "localhost", "self", FALSE);
  Sni(k, "other.example", "other", FALSE);
  Sni(k, "unknown.example", "self", TRUE);
  Sni(k, "127.0.0.1", "self", FALSE);
  Sni(k, "", "self", TRUE);
  Names(k);
  server.Close
END Kind;

BEGIN
  TestPeers.IgnoreBrokenPipe;
  Kind("ec");
  Kind("rsa");
  server := ServerContext("ec");
  Protocol("", "TLSv1.3");
  Protocol("tlsv1.2", "TLSv1.2");
  Implicit;
  server.Close;
  Check.Summary
END TestInfo.
