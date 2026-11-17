MODULE TestTcpTasks; (* A Gemini-shaped server in tasks, over TCP from posockets *)

(* For each of 127.0.0.1 and ::1: a non-blocking listener on port 0, an
   accept loop in a task (SocketTasks.Accept), and a task per accepted
   connection doing TLS through TlsTasks with a deadline, as a Gemini
   server would. Its clients, all at once: Oberon tasks verifying the
   server by address, one that connects and never says anything, which
   the server cuts off at its deadline, and openssl s_client in a child
   process. The accept loop stops through a flag it checks whenever its
   short deadline on the listener passes (posockets' PLAN.md, "Stopping
   a server"). posockets is a test-only dependency; the makefile skips
   this test without it. memcheck can't follow poc's coroutines, so
   this runs under valgrind's descriptor check only (TASKTESTS). *)

IMPORT Check, Tls, TlsTasks, Tasks, Child, Sockets, SocketTasks;

CONST
  certs = "../build/certs/";
  request = "gemini://localhost/";
  response = "20 text/gemini";
  CR = 0DX; LF = 0AX;
  clients = 6;      (* Oberon clients that make a request *)
  deadline = 500;   (* ms the server gives each connection *)

TYPE
  Text = ARRAY 256 OF CHAR;

  Accepter = POINTER TO AccepterDesc;
  AccepterDesc = RECORD (Tasks.TaskDesc)
    l: Sockets.Socket;
    accepted: LONGINT;
    error: Sockets.Error  (* why it stopped, if not asked to *)
  END;

  (* One connection's server side: handshake, request line, response,
     close_notify. *)
  Handler = POINTER TO RECORD (Tasks.TaskDesc)
    s: Sockets.Socket
  END;

  Client = POINTER TO ClientDesc;
  ClientDesc = RECORD (Tasks.TaskDesc)
    host: Text;
    port: INTEGER;
    silent: BOOLEAN;     (* connect, say nothing, hold on for a while *)
    ok: BOOLEAN;
    what: Text           (* what failed *)
  END;

VAR
  ctx: Tls.Context;
  client: Tls.Config;
  stop: BOOLEAN;           (* the accept loop is to stop *)
  served, failed: LONGINT; (* connections handled, by outcome *)
  timedOut: LONGINT;       (* of those failed, by deadline in the handshake *)
  haveOpenssl: BOOLEAN;
  got: ARRAY 65536 OF CHAR;

PROCEDURE Append(VAR s: ARRAY OF CHAR; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0; WHILE part[j] # 0X DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

PROCEDURE AppendInt(VAR s: ARRAY OF CHAR; VAR i: LONGINT; n: LONGINT);
  VAR d: ARRAY 12 OF CHAR; k: LONGINT;
BEGIN
  k := 0; REPEAT d[k] := CHR(ORD("0") + n MOD 10); n := n DIV 10; INC(k) UNTIL n = 0;
  WHILE k > 0 DO DEC(k); s[i] := d[k]; INC(i) END;
  s[i] := 0X
END AppendInt;

PROCEDURE Length(s: ARRAY OF CHAR): LONGINT;
  VAR n: LONGINT;
BEGIN n := 0; WHILE s[n] # 0X DO INC(n) END; RETURN n
END Length;

(* s followed by CR LF, in line; its length *)
PROCEDURE Line(s: ARRAY OF CHAR; VAR line: Text): LONGINT;
  VAR n: LONGINT;
BEGIN
  line := s; n := Length(line); line[n] := CR; line[n + 1] := LF; line[n + 2] := 0X;
  RETURN n + 2
END Line;

(* got[0..n-1] contains part *)
PROCEDURE Has(VAR got: ARRAY OF CHAR; n: LONGINT; part: ARRAY OF CHAR): BOOLEAN;
BEGIN
  IF n >= LEN(got) THEN n := LEN(got) - 1 END;
  got[n] := 0X;
  RETURN Check.Contains(got, part)
END Has;

PROCEDURE Label(what, host: ARRAY OF CHAR; VAR s: Text);
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, what); Append(s, i, " ("); Append(s, i, host); Append(s, i, ")")
END Label;

PROCEDURE Ok(ok: BOOLEAN; what, host: ARRAY OF CHAR);
  VAR s: Text;
BEGIN Label(what, host, s); Check.Check(ok, s)
END Ok;

(* --- the server --- *)

(* Reads up to CR LF, at most LEN(line) - 1 bytes; FALSE on failure *)
PROCEDURE ReadLine(conn: Tls.Connection; VAR line: Text): BOOLEAN;
  VAR n, m: LONGINT;
BEGIN
  n := 0;
  REPEAT
    IF ~TlsTasks.Read(conn, line, n, LEN(line) - 1 - n, m) THEN RETURN FALSE END;
    INC(n, m)
  UNTIL ((n >= 2) & (line[n - 2] = CR) & (line[n - 1] = LF)) OR (n = LEN(line) - 1);
  line[n] := 0X;
  RETURN TRUE
END ReadLine;

PROCEDURE (h: Handler) Run*;
  VAR conn: Tls.Connection; line, out: Text; n, m: LONGINT; ok: BOOLEAN;
BEGIN
  ok := ctx.AcceptSocket(h.s.fd, conn);
  IF ok THEN
    conn.SetDeadline(deadline);
    ok := TlsTasks.Handshake(conn) & ReadLine(conn, line)
      & Check.Contains(line, request);
    IF ok THEN
      n := Line(response, out);
      ok := TlsTasks.WriteAll(conn, out, 0, n, m) & TlsTasks.Close(conn)
    ELSE
      IF (conn.error # NIL) & (conn.error.kind = Tls.timedOut) THEN INC(timedOut) END;
      conn.Discard
    END
  END;
  Sockets.Close(h.s);
  IF ok THEN INC(served) ELSE INC(failed) END
END Run;

PROCEDURE (a: Accepter) Run*;
  VAR s: Sockets.Socket; peer: Sockets.Address; h: Handler;
BEGIN
  a.accepted := 0;
  LOOP
    Sockets.SetDeadline(a.l, 50);
    IF SocketTasks.Accept(a.l, s, peer, a.error) THEN
      INC(a.accepted);
      NEW(h); h.s := s; Tasks.Start(h, TlsTasks.stackSize)
    ELSIF a.error.kind # Sockets.timedOut THEN EXIT
    ELSIF stop THEN Sockets.ClearError(a.error); EXIT
    END
  END
END Run;

(* --- the clients --- *)

PROCEDURE (c: Client) Run*;
  VAR s: Sockets.Socket; err: Sockets.Error; conn: Tls.Connection;
    line: Text; n, m: LONGINT;
BEGIN
  c.ok := FALSE;
  IF ~SocketTasks.Connect(c.host, c.port, 2000, s, err) THEN c.what := err.text; RETURN END;
  IF c.silent THEN
    Tasks.Sleep(deadline + 500);
    (* the server has cut it off: its read sees the end *)
    c.ok := SocketTasks.Read(s, got, 0, LEN(got), n, err) OR (err.kind = Sockets.closed);
    Sockets.Close(s); RETURN
  END;
  IF ~Tls.ConnectSocket(client, s.fd, c.host, conn) THEN
    c.what := conn.error.text^; Sockets.Close(s); RETURN
  END;
  conn.SetDeadline(5000);
  n := Line(request, line);
  IF TlsTasks.Handshake(conn) & TlsTasks.WriteAll(conn, line, 0, n, m) THEN
    n := 0;
    WHILE TlsTasks.Read(conn, line, n, LEN(line) - 1 - n, m) DO INC(n, m) END;
    c.ok := (conn.error.kind = Tls.closed) & Has(line, n, response) & TlsTasks.Close(conn)
  END;
  IF ~c.ok & (conn.error # NIL) THEN c.what := conn.error.text^ END;
  conn.Discard;
  Sockets.Close(s)
END Run;

(* openssl s_client making a request to host and port, verifying the
   server by address, started now; Wait for it later. *)
PROCEDURE SClient(host: ARRAY OF CHAR; port: INTEGER; VAR child: Child.Child): BOOLEAN;
  VAR command: ARRAY 512 OF CHAR; line: Text; i, n: LONGINT;
BEGIN
  i := 0;
  Append(command, i, "exec openssl s_client -quiet -verify_return_error -CAfile ");
  Append(command, i, certs); Append(command, i, "ca-ec.crt");
  Append(command, i, " -verify_ip "); Append(command, i, host);
  Append(command, i, " -connect ");
  IF host[0] = ":" THEN Append(command, i, "[") END;
  Append(command, i, host);
  IF host[0] = ":" THEN Append(command, i, "]") END;
  Append(command, i, ":"); AppendInt(command, i, port);
  n := Line(request, line);
  RETURN Child.Spawn(command, line, n, child)
END SClient;

(* Whether there is an openssl whose s_client the test can drive: if
   none runs, a FAIL; if it isn't OpenSSL's, a skip. *)
PROCEDURE HaveOpenssl(): BOOLEAN;
  VAR k: INTEGER;
BEGIN
  k := Child.Openssl();
  IF k = Child.noOpenssl THEN Check.Check(FALSE, "openssl runs (for s_client)")
  ELSIF k = Child.otherOpenssl THEN
    Check.Skip("openssl s_client: not OpenSSL's (LibreSSL's has no -verify_ip)")
  END;
  RETURN k = Child.realOpenssl
END HaveOpenssl;

PROCEDURE Over(host: ARRAY OF CHAR);
  VAR ls: ARRAY 2 OF Sockets.Socket; nl: INTEGER; addr: Sockets.Address; err: Sockets.Error;
    a: Accepter; c: ARRAY clients + 1 OF Client; i, expected, waited, m: LONGINT;
    child: Child.Child; spawned, ok: BOOLEAN; status: INTEGER;
BEGIN
  ok := Sockets.Listen(host, 0, 16, TRUE, ls, nl, err)
    & Sockets.LocalAddress(ls[0], addr, err);
  IF ~ok THEN Check.Check(FALSE, err.text); RETURN END;
  Ok(nl = 1, "a non-blocking listener on port 0", host);
  stop := FALSE; served := 0; failed := 0; timedOut := 0;
  NEW(a); a.l := ls[0];
  Tasks.Start(a, TlsTasks.stackSize);
  FOR i := 0 TO clients DO
    NEW(c[i]); COPY(host, c[i].host); c[i].port := addr.port;
    c[i].silent := i = clients; c[i].what := "";
    Tasks.Start(c[i], TlsTasks.stackSize)
  END;
  expected := clients + 1;
  spawned := haveOpenssl & SClient(host, addr.port, child);
  IF spawned THEN INC(expected) END;
  FOR i := 0 TO clients DO
    Tasks.Join(c[i]);
    IF ~c[i].ok THEN Check.Check(FALSE, c[i].what) END
  END;
  waited := 0;
  WHILE (served + failed < expected) & (waited < 5000) DO Tasks.Sleep(10); INC(waited, 10) END;
  stop := TRUE; Tasks.Join(a);
  Ok(a.error.kind = Sockets.none, "the accept loop stopped when asked", host);
  Ok(a.accepted = expected, "every connection accepted", host);
  i := 0; WHILE (i < clients) & c[i].ok DO INC(i) END;
  Ok(i = clients, "every Oberon client verified the server and read the response", host);
  Ok((failed = 1) & (timedOut = 1), "the silent client cut off at the deadline", host);
  Ok(c[clients].ok, "the silent client saw the end of the connection", host);
  Ok(served = expected - 1, "every other connection served", host);
  IF spawned THEN
    status := Child.Wait(child, got, m);
    Ok((status = 0) & Has(got, m, response),
      "openssl s_client: verified the server, read the response, exited 0", host)
  END;
  Sockets.Close(ls[0])
END Over;

PROCEDURE Setup;
  VAR c: Tls.Config;
BEGIN
  c := Tls.NewConfig();
  Check.Check(c.SetKeypairFile("../build/certs/server-ec.crt", "../build/certs/server-ec.key"),
    "server config");
  c.VerifyClientOptional; c.InsecureNoVerifyCert;
  ctx := Tls.NewServer();
  Check.Check(ctx.Configure(c), "server context");
  c.Close;
  client := Tls.NewConfig();
  Check.Check(client.SetCaFile("../build/certs/ca-ec.crt"), "client config")
END Setup;

BEGIN
  Sockets.IgnoreBrokenPipe;
  haveOpenssl := HaveOpenssl();
  Setup;
  Over("127.0.0.1");
  Over("::1");
  client.Close; ctx.Close;
  Check.Summary
END TestTcpTasks.
