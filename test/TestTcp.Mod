MODULE TestTcp; (* Tls over TCP connections from posockets *)

(* For each of 127.0.0.1 and ::1, a listener on port 0 (the port the
   kernel chose read back, so runs never collide), then over connections
   accepted from it: an Oberon server with a C libtls client
   (TestPeers' peer thread), an Oberon client with a C libtls server, and
   an Oberon server with openssl s_client in a child process, making a
   Gemini request. Each verifies the server's certificate, server-K,
   whose names include both addresses, against ca-K. posockets is a
   test-only dependency (PLAN.md, "Testing"); the makefile skips this
   test without it. Certificates are test/make-certs.sh's, from test/. *)

IMPORT Check, Tls, TestPeers, Sockets;

CONST
  certs = "../build/certs/";
  request = "gemini://localhost/";
  response = "20 text/gemini";
  CR = 0DX; LF = 0AX;

TYPE Text = ARRAY 256 OF CHAR;

VAR
  got: ARRAY 65536 OF CHAR;
  error: ARRAY 256 OF CHAR;
  haveOpenssl: BOOLEAN;

PROCEDURE Append(VAR s: ARRAY OF CHAR; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0; WHILE part[j] # 0X DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

PROCEDURE AppendInt(VAR s: ARRAY OF CHAR; VAR i: LONGINT; n: LONGINT);
  VAR d: ARRAY 24 OF CHAR; k: LONGINT;
BEGIN
  k := 0; REPEAT d[k] := CHR(ORD("0") + n MOD 10); n := n DIV 10; INC(k) UNTIL n = 0;
  WHILE k > 0 DO DEC(k); s[i] := d[k]; INC(i) END;
  s[i] := 0X
END AppendInt;

(* s := certs + name + "-" + k + ext *)
PROCEDURE Path(name, k, ext: ARRAY OF CHAR; VAR s: Text);
  VAR i: LONGINT;
BEGIN
  i := 0; Append(s, i, certs); Append(s, i, name); Append(s, i, "-"); Append(s, i, k);
  Append(s, i, ext)
END Path;

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

(* got[0..n-1] contains s *)
PROCEDURE Has(VAR got: ARRAY OF CHAR; n: LONGINT; s: ARRAY OF CHAR): BOOLEAN;
  VAR i, j, m: LONGINT;
BEGIN
  m := Length(s); i := 0;
  WHILE i + m <= n DO
    j := 0; WHILE (j < m) & (got[i + j] = s[j]) DO INC(j) END;
    IF j = m THEN RETURN TRUE END;
    INC(i)
  END;
  RETURN FALSE
END Has;

(* A label: what + " (" + host + ")" *)
PROCEDURE Label(what, host: ARRAY OF CHAR; VAR s: Text);
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, what); Append(s, i, " ("); Append(s, i, host); Append(s, i, ")")
END Label;

PROCEDURE Ok(ok: BOOLEAN; what, host: ARRAY OF CHAR);
  VAR s: Text;
BEGIN Label(what, host, s); Check.Check(ok, s)
END Ok;

(* Reports err, if anything failed, as a failed check. *)
PROCEDURE Report(ok: BOOLEAN; VAR err: Sockets.Error);
BEGIN IF ~ok THEN Check.Check(FALSE, err.text) END
END Report;

(* A server context with key pair server-K, client certificates optional
   and not verified, as a Gemini server's. *)
PROCEDURE NewServer(k: ARRAY OF CHAR): Tls.Context;
  VAR c: Tls.Config; x: Tls.Context; crt, key: Text;
BEGIN
  c := Tls.NewConfig();
  Path("server", k, ".crt", crt); Path("server", k, ".key", key);
  Check.Check(c.SetKeypairFile(crt, key), "SetKeypairFile");
  c.VerifyClientOptional; c.InsecureNoVerifyCert;
  x := Tls.NewServer();
  Check.Check(x.Configure(c), "Configure");
  c.Close;
  RETURN x
END NewServer;

(* A TCP connection to l, from client to server, both blocking: the
   kernel completes the connection into l's queue before Accept. *)
PROCEDURE Connect(l: Sockets.Socket; host: ARRAY OF CHAR; port: INTEGER;
    VAR client, server: Sockets.Socket): BOOLEAN;
  VAR peer: Sockets.Address; err: Sockets.Error; ok: BOOLEAN; h: Text;
BEGIN
  ok := Sockets.Connect(host, port, client, err);
  Report(ok, err);
  IF ok THEN
    ok := Sockets.Accept(l, FALSE, server, peer, err);
    Report(ok, err);
    IF ok THEN COPY(peer.host, h); Ok(Same(h, Length(host), host), "Accept: the peer's address", host) END
  END;
  RETURN ok
END Connect;

(* The request line a Gemini server reads, up to CR LF, into got; its
   length without them, or -1 if the connection ended first. *)
PROCEDURE ReadLine(conn: Tls.Connection): LONGINT;
  VAR n, m: LONGINT;
BEGIN
  n := 0;
  WHILE ~((n >= 2) & (got[n - 2] = CR) & (got[n - 1] = LF)) & (n < LEN(got)) &
      conn.Read(got, n, 1, m) DO
    INC(n, m)
  END;
  IF (n >= 2) & (got[n - 2] = CR) & (got[n - 1] = LF) THEN RETURN n - 2 ELSE RETURN -1 END
END ReadLine;

(* An Oberon server with server-K, accepting from l, and a C libtls
   client that verifies it against ca-K by the address it connected to. *)
PROCEDURE ServeC(l: Sockets.Socket; host: ARRAY OF CHAR; port: INTEGER; k: ARRAY OF CHAR);
  VAR x: Tls.Context; conn: Tls.Connection; client, server: Sockets.Socket;
    peer: TestPeers.Peer; ca, line: Text; n, m: LONGINT; ok: BOOLEAN;
BEGIN
  IF Connect(l, host, port, client, server) THEN
    x := NewServer(k);
    Path("ca", k, ".crt", ca);
    line := request; n := Length(line); line[n] := CR; line[n + 1] := LF; line[n + 2] := 0X;
    peer := TestPeers.StartClient(client.fd, ca, "", "", host, line, n + 2, FALSE);
    Ok(peer # 0, "C client: started", host);
    Ok(x.AcceptSocket(server.fd, conn) & conn.Handshake(), "Oberon server: AcceptSocket, Handshake", host);
    Ok(Same(got, ReadLine(conn), request), "Oberon server: read the request", host);
    Ok(conn.WriteAll(response, 0, Length(response), m) & conn.Close(), "Oberon server: WriteAll, Close", host);
    ok := TestPeers.Join(peer, got, m, error);
    Ok(ok & Same(got, m, response), "C client: verified the server and read the response", host);
    IF ~ok THEN Check.Check(FALSE, error) END;
    x.Close;
    Sockets.Close(client); Sockets.Close(server)
  END
END ServeC;

(* An Oberon client verifying a C libtls server with server-ec against
   ca-ec, by the address it connected to. *)
PROCEDURE Fetch(l: Sockets.Socket; host: ARRAY OF CHAR; port: INTEGER);
  VAR c: Tls.Config; conn: Tls.Connection; client, server: Sockets.Socket;
    peer: TestPeers.Peer; crt, key, ca: Text; peerGot: ARRAY 64 OF CHAR; n, m: LONGINT; ok: BOOLEAN;
BEGIN
  IF Connect(l, host, port, client, server) THEN
    Path("server", "ec", ".crt", crt); Path("server", "ec", ".key", key);
    peer := TestPeers.StartServer(server.fd, crt, key, Length(request), response, Length(response), FALSE);
    Ok(peer # 0, "C server: started", host);
    c := Tls.NewConfig();
    Path("ca", "ec", ".crt", ca);
    Check.Check(c.SetCaFile(ca), "SetCaFile");
    Ok(Tls.ConnectSocket(c, client.fd, host, conn) & conn.Handshake(),
      "Oberon client: ConnectSocket, Handshake, verifying the server", host);
    Ok(conn.WriteAll(request, 0, Length(request), m), "Oberon client: WriteAll the request", host);
    n := 0; WHILE (n < LEN(got)) & conn.Read(got, n, LEN(got) - n, m) DO INC(n, m) END;
    Ok(Same(got, n, response) & (conn.error.kind = Tls.closed),
      "Oberon client: read the response, then the close_notify", host);
    Ok(conn.Close(), "Oberon client: Close", host);
    ok := TestPeers.Join(peer, peerGot, m, error);
    Ok(ok & Same(peerGot, m, request), "C server: read the request", host);
    IF ~ok THEN Check.Check(FALSE, error) END;
    c.Close;
    Sockets.Close(client); Sockets.Close(server)
  END
END Fetch;

(* An Oberon server with server-K, and openssl s_client, verifying it
   against ca-caK by address, making a Gemini request. s_client's -quiet
   implies -ign_eof: it sends its input, then reads until the server
   closes. With caK # k the verification must fail: s_client exits
   nonzero, and the server's Handshake fails. *)
PROCEDURE ServeOpenssl(l: Sockets.Socket; host: ARRAY OF CHAR; port: INTEGER; k, caK: ARRAY OF CHAR);
  VAR x: Tls.Context; conn: Tls.Connection; server: Sockets.Socket; peer: Sockets.Address;
    err: Sockets.Error; child: TestPeers.Child; command: ARRAY 512 OF CHAR; ca, line: Text;
    i, n, m: LONGINT; status: INTEGER; ok, good: BOOLEAN;
BEGIN
  good := Same(k, Length(caK), caK);
  Path("ca", caK, ".crt", ca);
  i := 0; Append(command, i, "exec openssl s_client -quiet -verify_return_error -CAfile ");
  Append(command, i, ca); Append(command, i, " -verify_ip "); Append(command, i, host);
  Append(command, i, " -connect ");
  IF host[0] = ":" THEN Append(command, i, "[") END;
  Append(command, i, host);
  IF host[0] = ":" THEN Append(command, i, "]") END;
  Append(command, i, ":"); AppendInt(command, i, port);
  line := request; n := Length(line); line[n] := CR; line[n + 1] := LF; line[n + 2] := 0X;
  ok := TestPeers.Spawn(command, line, n + 2, child);
  Ok(ok, "openssl s_client: started", host);
  IF ok THEN
    ok := Sockets.Accept(l, FALSE, server, peer, err);
    Report(ok, err);
    IF ok THEN
      x := NewServer(k);
      ok := x.AcceptSocket(server.fd, conn);
      Ok(ok, "Oberon server: AcceptSocket", host);
      IF good THEN
        Ok(conn.Handshake(), "Oberon server: Handshake", host);
        Ok(Same(got, ReadLine(conn), request), "Oberon server: read s_client's request", host);
        line := response; n := Length(line); line[n] := CR; line[n + 1] := LF; line[n + 2] := 0X;
        Ok(conn.WriteAll(line, 0, n + 2, m) & conn.Close(), "Oberon server: WriteAll, Close", host)
      ELSE
        (* s_client sends a bad_certificate alert, "unknown ca" with TLS 1.3 *)
        Ok(~conn.Handshake() & (conn.error.kind = Tls.handshake),
          "Oberon server: Handshake fails when s_client rejects the certificate", host);
        IF conn.Close() THEN END
      END;
      x.Close;
      Sockets.Close(server)
    END;
    status := TestPeers.Wait(child, got, m);
    IF m > LEN(got) - 1 THEN m := LEN(got) - 1 END;
    IF good THEN
      Ok((status = 0) & Has(got, m, response),
        "openssl s_client: verified the server, read the response, exited 0", host);
      IF status # 0 THEN got[m] := 0X; Check.Check(FALSE, got) END
    ELSE
      Ok((status > 0) & Has(got, m, "unable to get local issuer certificate"),
        "openssl s_client: a server signed by another CA, rejected", host)
    END
  END
END ServeOpenssl;

(* Whether openssl runs at all: if not, s_client would never connect, and
   Accept would wait forever. *)
PROCEDURE OpensslRuns(): BOOLEAN;
  VAR child: TestPeers.Child; n: LONGINT;
BEGIN
  RETURN TestPeers.Spawn("exec openssl version", "", 0, child) & (TestPeers.Wait(child, got, n) = 0)
END OpensslRuns;

PROCEDURE Over(host: ARRAY OF CHAR);
  VAR ls: ARRAY 2 OF Sockets.Socket; n: INTEGER; a: Sockets.Address; err: Sockets.Error; ok: BOOLEAN;
BEGIN
  ok := Sockets.Listen(host, 0, 4, FALSE, ls, n, err);
  Report(ok, err);
  Ok(ok & (n = 1), "Listen on port 0", host);
  IF ok THEN
    ok := Sockets.LocalAddress(ls[0], a, err);
    Report(ok, err);
    Ok(ok & (a.port > 0), "LocalAddress: the kernel's port", host);
    IF ok THEN
      ServeC(ls[0], host, a.port, "ec");
      ServeC(ls[0], host, a.port, "rsa");
      Fetch(ls[0], host, a.port);
      IF haveOpenssl THEN
        ServeOpenssl(ls[0], host, a.port, "ec", "ec");
        ServeOpenssl(ls[0], host, a.port, "rsa", "rsa");
        ServeOpenssl(ls[0], host, a.port, "ec", "rsa")
      END
    END;
    Sockets.Close(ls[0])
  END
END Over;

BEGIN
  (* libtls writes without MSG_NOSIGNAL *)
  Sockets.IgnoreBrokenPipe;
  haveOpenssl := OpensslRuns();
  IF ~haveOpenssl THEN Check.Check(FALSE, "openssl runs (for s_client)") END;
  Over("127.0.0.1");
  Over("::1");
  Check.Summary
END TestTcp.
