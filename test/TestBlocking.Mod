MODULE TestBlocking; (* Tls.Context and Tls.Connection over blocking descriptors *)

(* Each test runs over a socket pair from TestPeers: the Oberon side on
   one end, and on the other a C peer in a thread of its own (TestPeers.c,
   "struct peer"), since two tasks can't both block in libtls (PLAN.md,
   Phase 4). Certificates are test/make-certs.sh's, from test/. *)

IMPORT Check, Tls, TestPeers;

CONST
  certs = "../build/certs/";
  big = 200000;  (* more than a socket pair's buffers hold: WriteAll waits for the peer *)
  request = "hello, server";
  response = "hello, client";

TYPE Name = ARRAY 128 OF CHAR;

VAR
  crt, key, ca: Name;
  data: POINTER TO ARRAY OF CHAR;  (* big bytes to send *)
  got: POINTER TO ARRAY OF CHAR;   (* what was read, by us or by the peer *)
  error: ARRAY 256 OF CHAR;
  n: LONGINT;

PROCEDURE Append(VAR s: Name; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0; WHILE part[j] # 0X DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

(* s := certs + name + ext; no string + in poc. *)
PROCEDURE Path(name, ext: ARRAY OF CHAR; VAR s: Name);
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, certs); Append(s, i, name); Append(s, i, ext)
END Path;

PROCEDURE Pair(name: ARRAY OF CHAR; VAR crt, key: Name);
BEGIN Path(name, ".crt", crt); Path(name, ".key", key)
END Pair;

PROCEDURE Length(s: ARRAY OF CHAR): LONGINT;
  VAR n: LONGINT;
BEGIN n := 0; WHILE s[n] # 0X DO INC(n) END; RETURN n
END Length;

(* got[0..n-1] = s[0..n-1], and n = Length(s) *)
PROCEDURE Same(VAR got: ARRAY OF CHAR; n: LONGINT; s: ARRAY OF CHAR): BOOLEAN;
  VAR i: LONGINT;
BEGIN
  IF n # Length(s) THEN RETURN FALSE END;
  i := 0; WHILE (i < n) & (got[i] = s[i]) DO INC(i) END;
  RETURN i = n
END Same;

(* e is an error of kind whose text has part *)
PROCEDURE IsError(e: Tls.Error; kind: INTEGER; part: ARRAY OF CHAR): BOOLEAN;
BEGIN RETURN (e # NIL) & (e.kind = kind) & Check.Contains(e.text^, part)
END IsError;

(* A server config: key pair name, client certificates optional and not
   verified, as a Gemini server's. *)
PROCEDURE ServerConfig(name: ARRAY OF CHAR): Tls.Config;
  VAR c: Tls.Config;
BEGIN
  c := Tls.NewConfig();
  Pair(name, crt, key);
  Check.Check(c.SetKeypairFile(crt, key), "server config: SetKeypairFile");
  c.VerifyClientOptional; c.InsecureNoVerifyCert;
  RETURN c
END ServerConfig;

PROCEDURE NewServer(name: ARRAY OF CHAR): Tls.Context;
  VAR x: Tls.Context; c: Tls.Config;
BEGIN
  c := ServerConfig(name);
  x := Tls.NewServer();
  Check.Check(x.Configure(c), "server context: Configure");
  c.Close;  (* libtls keeps its own reference *)
  RETURN x
END NewServer;

(* Reads into got until the peer ends, at most max bytes; the bytes
   read, and the Read that ended it in conn.error. *)
PROCEDURE ReadToEnd(conn: Tls.Connection; max: LONGINT): LONGINT;
  VAR n, m: LONGINT;
BEGIN
  n := 0;
  WHILE (n < max) & conn.Read(got^, n, max - n, m) DO INC(n, m) END;
  RETURN n
END ReadToEnd;

PROCEDURE ClosePair(a, b: LONGINT);
BEGIN
  IF TestPeers.Close(a) & TestPeers.Close(b) THEN END
END ClosePair;

(* An Oberon server with key pair server-K: reads a request from a C
   client, answers with big bytes in one WriteAll, and closes. The
   client verifies the server against ca-K, and presents client1-ec if
   withCert. *)
PROCEDURE Serve(k: ARRAY OF CHAR; withCert: BOOLEAN);
  VAR x: Tls.Context; conn: Tls.Connection; a, b, n, m: LONGINT; peer: TestPeers.Peer;
    name, ccrt, ckey: Name; i: LONGINT; ok: BOOLEAN;
BEGIN
  i := 0; Append(name, i, "server-"); Append(name, i, k);
  i := 0; Append(ca, i, certs); Append(ca, i, "ca-"); Append(ca, i, k); Append(ca, i, ".crt");
  IF withCert THEN Pair("client1-ec", ccrt, ckey) ELSE ccrt := ""; ckey := "" END;
  Check.Check(TestPeers.Pair(a, b, FALSE), "server: a socket pair");
  x := NewServer(name);
  peer := TestPeers.StartClient(b, ca, ccrt, ckey, "localhost", request, Length(request), FALSE);
  Check.Check(peer # 0, "server: the peer started");
  Check.Check(x.AcceptSocket(a, conn) & (x.error = NIL) & (conn.fd = a), "server: AcceptSocket");
  Check.Check(conn.Handshake() & (conn.error = NIL), "server: Handshake");
  n := 0;
  WHILE (n < Length(request)) & conn.Read(got^, n, Length(request) - n, m) DO INC(n, m) END;
  Check.Check(Same(got^, n, request), "server: Read the request");
  Check.Check(conn.WriteAll(data^, 0, big, n) & (n = big), "server: WriteAll a large response");
  Check.Check(conn.Close() & (conn.error = NIL), "server: Close");
  Check.Check(conn.Close(), "server: Close again does nothing");
  ok := TestPeers.Join(peer, got^, m, error);
  Check.Check(ok, "server: the client finished");
  IF ~ok THEN Check.Check(FALSE, error) END;
  n := 0; WHILE (n < big) & (got[n] = data[n]) DO INC(n) END;
  Check.Check((m = big) & (n = big), "server: the client got the whole response");
  x.Close; x.Close;
  ClosePair(a, b)
END Serve;

(* An Oberon client, with c, against a C server with key pair server-ec:
   writes the request and reads the response until Read fails. abrupt:
   the server shuts the socket down without close_notify. The result is
   in conn and n (bytes read into got), the server's in peerOk and
   error; the caller closes conn, then the pair. *)
PROCEDURE Fetch(c: Tls.Config; servername: ARRAY OF CHAR; abrupt: BOOLEAN;
    VAR a, b: LONGINT; VAR conn: Tls.Connection; VAR n: LONGINT; VAR peerOk: BOOLEAN);
  VAR m: LONGINT; peer: TestPeers.Peer; peerGot: ARRAY 64 OF CHAR;
BEGIN
  n := 0;
  Check.Check(TestPeers.Pair(a, b, FALSE), "client: a socket pair");
  Pair("server-ec", crt, key);
  peer := TestPeers.StartServer(b, crt, key, Length(request), response, Length(response), abrupt);
  Check.Check(Tls.ConnectSocket(c, a, servername, conn) & (conn.error = NIL), "client: ConnectSocket");
  IF conn.WriteAll(request, 0, Length(request), m) THEN n := ReadToEnd(conn, LEN(got^)) END;
  peerOk := TestPeers.Join(peer, peerGot, m, error);
  IF peerOk THEN peerOk := Same(peerGot, m, request) END
END Fetch;

PROCEDURE ClientConfig(caName: ARRAY OF CHAR): Tls.Config;
  VAR c: Tls.Config;
BEGIN
  c := Tls.NewConfig();
  Check.Check(c.SetCaFile(caName), "client config: SetCaFile");
  RETURN c
END ClientConfig;

PROCEDURE Client;
  VAR c: Tls.Config; conn: Tls.Connection; a, b, n: LONGINT; ok: BOOLEAN;
BEGIN
  c := ClientConfig("../build/certs/ca-ec.crt");
  Fetch(c, "localhost", FALSE, a, b, conn, n, ok);
  Check.Check(Same(got^, n, response), "client: Read the response");
  Check.Check(IsError(conn.error, Tls.closed, "connection closed by peer"),
    "client: Read after close_notify fails, kind closed");
  Check.Check(~conn.Read(got^, 0, 1, n) & (n = 0) & IsError(conn.error, Tls.closed, "connection closed by peer"),
    "client: Read again gives the same");
  Check.Check(ok, "client: the server got the request and closed");
  IF ~ok THEN Check.Check(FALSE, error) END;
  Check.Check(conn.Close() & (conn.error = NIL), "client: Close");
  ClosePair(a, b);

  (* the same config serves a second connection: a client's keys aren't cleared *)
  Fetch(c, "localhost", TRUE, a, b, conn, n, ok);
  Check.Check(Same(got^, n, response), "abrupt: Read the response");
  Check.Check(ok, "abrupt: the server finished");
  (* An end without close_notify, which a truncation attack would also
     give, is an error: on OpenSSL 3 tls_read fails, "unexpected eof
     while reading", and tls_close then "shutdown failed"; OpenBSD's
     libtls returns 0 from tls_read, and Read's own tls_close fails,
     "EOF without close notify" (PLAN.md, Phase 10) *)
  Check.Check(IsError(conn.error, Tls.io, "unexpected eof while reading")
      OR IsError(conn.error, Tls.io, "EOF without close notify"),
    "abrupt: Read fails, kind io");
  Check.Check(~conn.Close() & (IsError(conn.error, Tls.io, "shutdown failed")
      OR IsError(conn.error, Tls.io, "EOF without close notify")),
    "abrupt: Close fails, kind io, and frees all the same");
  Check.Check(conn.Close(), "abrupt: Close again does nothing");
  ClosePair(a, b);
  c.Close
END Client;

(* A client with c and servername, against server-ec, that fails in
   ConnectSocket if atConnect, else in Handshake, with part in its error.
   Our end is shut before the server is joined, so it never waits for
   a handshake that won't come; its result isn't checked, since when
   only the name is wrong, its handshake succeeds. *)
PROCEDURE Unverified(c: Tls.Config; servername: ARRAY OF CHAR; atConnect: BOOLEAN;
    part, label: ARRAY OF CHAR);
  VAR conn: Tls.Connection; a, b: LONGINT; peer: TestPeers.Peer; m: LONGINT; ok: BOOLEAN;
BEGIN
  Check.Check(TestPeers.Pair(a, b, FALSE), "a socket pair");
  Pair("server-ec", crt, key);
  peer := TestPeers.StartServer(b, crt, key, Length(request), response, Length(response), FALSE);
  IF atConnect THEN ok := ~Tls.ConnectSocket(c, a, servername, conn)
  ELSE ok := Tls.ConnectSocket(c, a, servername, conn) & ~conn.Handshake()
  END;
  Check.Check(ok & IsError(conn.error, Tls.handshake, part), label);
  (* After a failed verification OpenSSL is still in the handshake, so
     tls_close fails ("shutdown failed"); Close frees all the same *)
  IF conn.Close() THEN END;
  Check.Check(conn.Close(), "then Close does nothing");
  IF TestPeers.Close(a) & TestPeers.Join(peer, got^, m, error) THEN END;
  IF TestPeers.Close(b) THEN END
END Unverified;

PROCEDURE Verification;
  VAR c: Tls.Config;
BEGIN
  c := ClientConfig("../build/certs/ca-rsa.crt");
  Unverified(c, "localhost", FALSE, "certificate verification failed", "a server signed by another CA");
  c := ClientConfig("../build/certs/ca-ec.crt");
  Unverified(c, "other.example", FALSE, "name `other.example' not present in server certificate",
    "a server not of that name");
  (* libtls parses the CA file only when it sets up verification, in
     tls_connect_common *)
  c := ClientConfig("make-certs.sh");
  Unverified(c, "localhost", TRUE, "ssl verify memory setup failure",
    "a CA file that isn't PEM fails ConnectSocket");
  c.Close
END Verification;

(* x configured with cert and key fails with part *)
PROCEDURE BadKey(certName, keyName, part, label: ARRAY OF CHAR);
  VAR c: Tls.Config; x: Tls.Context;
BEGIN
  c := Tls.NewConfig(); x := Tls.NewServer();
  Check.Check(c.SetKeypairFile(certName, keyName), "SetKeypairFile");
  Check.Check(~x.Configure(c) & IsError(x.error, Tls.handshake, part), label);
  x.Close; c.Close
END BadKey;

PROCEDURE Contexts;
  VAR c: Tls.Config; x, y: Tls.Context; conn: Tls.Connection;
BEGIN
  BadKey("../build/certs/self-ec.crt", "../build/certs/self-rsa.key", "private/public key mismatch",
    "Configure: an RSA key with an EC certificate");
  BadKey("../build/certs/self-ec.crt", "../build/certs/other-ec.key", "failed to load private key",
    "Configure: another EC key");
  BadKey("../build/certs/self-ec.crt", "make-certs.sh", "failed to read private key",
    "Configure: a key that isn't PEM");

  (* Configure clears the config's keys: a second server context fails *)
  c := ServerConfig("self-ec");
  x := Tls.NewServer(); y := Tls.NewServer();
  Check.Check(x.Configure(c), "Configure");
  (* with the key gone, libtls's check of the pair fails *)
  Check.Check(~y.Configure(c) & IsError(y.error, Tls.handshake, "private/public key mismatch"),
    "Configure: the keys were cleared");
  Pair("self-ec", crt, key);
  Check.Check(c.SetKeypairFile(crt, key) & y.Configure(c), "Configure: after setting them again");
  y.Close; c.Close;

  (* an unconfigured context can't accept *)
  y := Tls.NewServer();
  Check.Check(~y.AcceptSocket(0, conn) & (conn = NIL) & IsError(y.error, Tls.handshake, "ssl failure"),
    "AcceptSocket: an unconfigured context");
  y.Close;

  (* left for the finalizers: a context and a connection from it, never
     closed (valgrind sees that they are freed) *)
  Check.Check(x.AcceptSocket(0, conn), "AcceptSocket on standard input, which sees no I/O");
  x := NIL; conn := NIL
END Contexts;

BEGIN
  TestPeers.IgnoreBrokenPipe;
  NEW(data, big); NEW(got, big);
  FOR n := 0 TO big - 1 DO data[n] := CHR(n MOD 251) END;
  Serve("ec", TRUE);
  Serve("rsa", FALSE);
  Client;
  Verification;
  Contexts;
  Check.Summary
END TestBlocking.
