MODULE GeminiHello; (* A Gemini server answering every request with one page *)

(* Usage: GeminiHello [-n count] [-host host] port cert key [cert key ...]

   Listens at port on host (default: every local address, IPv6 and
   IPv4; port 0: one the kernel chooses) and prints "port <n>" as its
   first line, so a program that started it on port 0 learns where it
   is. The first certificate and key are its default; each further pair
   is presented to a client that asks for one of its names by SNI.

   To each gemini:// request it answers "20 text/gemini" and a page
   naming the URL and the client's certificate, by its SHA-256
   fingerprint, if the client sent one; to anything else, "59 bad
   request". It accepts any client certificate, self-signed or expired,
   as a Gemini server does, since the certificate is an identity, not
   something a CA vouches for. Each response ends with TLS close_notify,
   which is how a Gemini client knows it has the whole of it; then the
   server reads and discards what the client still sends, for a while,
   before it closes the socket, so that a client's own early close_notify
   doesn't make the kernel reset the connection under the response
   (SocketTasks.LingeringClose; PLAN.md, Phase 8).

   For each connection it prints one line: the client's address, then
   the status and URL and the client certificate's fingerprint, or "-"
   for none; or "failed:" and why. With count, it serves that many
   connections, waits for them to end, and exits; without, it serves
   until it is asked to stop, by SIGINT or SIGTERM (StopRequests), and
   then it stops accepting, waits for the connections it has to end, and
   exits. A second request of the same kind ends it at once.

   It shows a server Tls.Context with one or more key pairs, an accept
   task per listener (posockets' SocketTasks) and a task per connection
   using TlsTasks, so one thread serves every connection, each with a
   deadline for the whole exchange. It is a starting point for a server,
   not one: it serves no files. *)

IMPORT Platform, Out, Err, Args, Tasks, StopRequests, Sockets, SocketTasks, Tls, TlsTasks;

CONST
  Tick = 200;          (* ms an accept waits before looking at stop and StopRequests *)
  Deadline = 10000;    (* ms a connection has, handshake to close_notify *)
  Linger = 2000;       (* ms a closed connection is drained for *)
  MaxUrl = 1024;       (* a request's URL at most, by the specification *)
  CR = 0DX; LF = 0AX;

TYPE
  Handler = POINTER TO RECORD (Tasks.TaskDesc)
    s: Sockets.Socket;
    peer: Sockets.Address;
    next: Handler
  END;
  Acceptor = POINTER TO RECORD (Tasks.TaskDesc)
    l: Sockets.Socket
  END;

VAR
  ctx: Tls.Context;
  count, accepted: LONGINT;  (* connections to serve (0: no end), so far *)
  stop: BOOLEAN;
  handlers: Handler;         (* every connection's task, to join at the end *)

PROCEDURE Append(VAR s: ARRAY OF CHAR; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0;
  WHILE (part[j] # 0X) & (i < LEN(s) - 1) DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

PROCEDURE Put(VAR s: ARRAY OF CHAR; VAR i: LONGINT; c: CHAR);
BEGIN
  IF i < LEN(s) - 1 THEN s[i] := c; INC(i) END;
  s[i] := 0X
END Put;

(* Reads the request line, up to CR LF, into url without them: FALSE if
   it failed, or, with url "", if there was no CR LF in the first
   MaxUrl + 2 bytes. *)
PROCEDURE ReadRequest(c: Tls.Connection; VAR url: ARRAY OF CHAR): BOOLEAN;
  VAR buf: ARRAY MaxUrl + 2 OF CHAR; n, m: LONGINT;
BEGIN
  n := 0; url[0] := 0X;
  REPEAT
    IF ~TlsTasks.Read(c, buf, n, LEN(buf) - n, m) THEN RETURN FALSE END;
    INC(n, m)
  UNTIL (n >= 2) & (buf[n - 2] = CR) & (buf[n - 1] = LF) OR (n = LEN(buf));
  IF (buf[n - 2] = CR) & (buf[n - 1] = LF) THEN
    buf[n - 2] := 0X; COPY(buf, url)
  END;
  RETURN TRUE
END ReadRequest;

PROCEDURE IsGemini(url: ARRAY OF CHAR): BOOLEAN;
  CONST scheme = "gemini://";
  VAR i: LONGINT; s: ARRAY 10 OF CHAR;
BEGIN
  s := scheme; i := 0;
  WHILE (s[i] # 0X) & (url[i] = s[i]) DO INC(i) END;
  RETURN s[i] = 0X
END IsGemini;

(* The response to url, from a client whose certificate's fingerprint is
   hash, NIL for none, in r, and its length. *)
PROCEDURE Respond(url: ARRAY OF CHAR; hash: Tls.String; VAR r: ARRAY OF CHAR): LONGINT;
  VAR i: LONGINT;
BEGIN
  i := 0;
  IF ~IsGemini(url) THEN
    Append(r, i, "59 bad request"); Put(r, i, CR); Put(r, i, LF)
  ELSE
    Append(r, i, "20 text/gemini"); Put(r, i, CR); Put(r, i, LF);
    Append(r, i, "# Hello from polibtls"); Put(r, i, LF); Put(r, i, LF);
    Append(r, i, "You asked for "); Append(r, i, url); Append(r, i, "."); Put(r, i, LF); Put(r, i, LF);
    IF hash = NIL THEN Append(r, i, "You sent no client certificate.")
    ELSE Append(r, i, "Your client certificate is "); Append(r, i, hash^); Append(r, i, ".")
    END;
    Put(r, i, LF)
  END;
  RETURN i
END Respond;

(* Serves one connection: handshake, request, response, close_notify,
   all within Deadline; then prints how it went. *)
PROCEDURE (h: Handler) Run*;
  VAR c: Tls.Connection; url: ARRAY MaxUrl + 1 OF CHAR;
    r: ARRAY MaxUrl + 512 OF CHAR; n, m: LONGINT; hash: Tls.String; ok, closed: BOOLEAN;
BEGIN
  closed := FALSE;
  IF ~ctx.AcceptSocket(h.s.fd, c) THEN
    Out.String(h.peer.host); Out.String(" failed: "); Out.String(ctx.error.text^); Out.Ln
  ELSE
    c.SetDeadline(Deadline);
    ok := TlsTasks.Handshake(c) & ReadRequest(c, url);
    IF ok THEN
      hash := c.PeerCertHash();
      n := Respond(url, hash, r);
      ok := TlsTasks.WriteAll(c, r, 0, n, m) & TlsTasks.Close(c);
      (* A client may send its own close_notify straight after the
         request (gnutls-cli does, at the end of its input), which the
         server never reads; closing a socket with unread data makes the
         kernel reset the connection, and a client that gets the reset
         before it has read the response loses it. So the server reads
         and discards until the client closes, or for Linger at most. *)
      IF ok THEN closed := TRUE; IF SocketTasks.LingeringClose(h.s, Linger) THEN END END
    END;
    (* A line is printed with no wait between its parts, so the lines
       of tasks never mix. *)
    Out.String(h.peer.host); Out.Char(" ");
    IF ok THEN
      Out.Char(r[0]); Out.Char(r[1]); Out.Char(" ");
      IF url = "" THEN Out.String("-") ELSE Out.String(url) END;
      Out.Char(" ");
      IF hash = NIL THEN Out.String("-") ELSE Out.String(hash^) END
    ELSE
      Out.String("failed: "); Out.String(c.error.text^);
      c.Discard
    END;
    Out.Ln
  END;
  IF ~closed THEN Sockets.Close(h.s) END
END Run;

(* Accepts connections on l, starting a Handler for each, until stop or a
   request to stop. *)
PROCEDURE (a: Acceptor) Run*;
  VAR h: Handler; err: Sockets.Error;
BEGIN
  WHILE ~stop & (StopRequests.Latest() = StopRequests.none) DO
    NEW(h);
    Sockets.SetDeadline(a.l, Tick);
    IF SocketTasks.Accept(a.l, h.s, h.peer, err) THEN
      h.next := handlers; handlers := h; Tasks.Start(h, TlsTasks.stackSize);
      INC(accepted);
      IF accepted = count THEN stop := TRUE END
    ELSIF err.kind # Sockets.timedOut THEN
      (* EMFILE, a connection reset while queued: report, go on *)
      Err.String(err.text); Err.Ln; Tasks.Sleep(10)
    END
  END;
  Sockets.Close(a.l)
END Run;

PROCEDURE Usage;
BEGIN
  Err.String("usage: GeminiHello [-n count] [-host host] port cert key [cert key ...]"); Err.Ln;
  Platform.Exit(2)
END Usage;

(* A server context with the key pairs in arguments i, i + 1, ... *)
PROCEDURE Setup(i: INTEGER);
  VAR c: Tls.Config; cert, key: ARRAY 1024 OF CHAR; ok: BOOLEAN;
BEGIN
  c := Tls.NewConfig();
  Args.Get(i, cert); Args.Get(i + 1, key);
  ok := c.SetKeypairFile(cert, key);
  INC(i, 2);
  WHILE ok & (i < Args.argc) DO
    Args.Get(i, cert); Args.Get(i + 1, key);
    ok := c.AddKeypairFile(cert, key);
    INC(i, 2)
  END;
  IF ok THEN
    (* any client certificate: Gemini's are mostly self-signed *)
    c.VerifyClientOptional; c.InsecureNoVerifyCert;
    ctx := Tls.NewServer();
    IF ~ctx.Configure(c) THEN
      Err.String("GeminiHello: "); Err.String(ctx.error.text^); Err.Ln; Platform.Exit(1)
    END
  ELSE
    Err.String("GeminiHello: "); Err.String(c.error.text^); Err.Ln; Platform.Exit(1)
  END;
  c.Close
END Setup;

PROCEDURE Main;
  VAR arg, host: ARRAY 256 OF CHAR; ls: ARRAY 2 OF Sockets.Socket;
    as: ARRAY 2 OF Acceptor; a: Sockets.Address; err: Sockets.Error;
    port: LONGINT; i, n: INTEGER;
BEGIN
  count := 0; host := ""; i := 1;
  LOOP
    Args.Get(i, arg);
    IF arg = "-n" THEN count := -1; Args.GetInt(i + 1, count); INC(i, 2)
    ELSIF arg = "-host" THEN Args.Get(i + 1, host); INC(i, 2)
    ELSE EXIT
    END
  END;
  IF (Args.argc < i + 3) OR ODD(Args.argc - i - 1) THEN Usage END;
  port := -1; Args.GetInt(i, port);
  IF (port < 0) OR (port > 65535) OR (count < 0) THEN Usage END;
  Setup(i + 1);
  (* A client that goes away makes a write fail, not end the program. *)
  Sockets.IgnoreBrokenPipe;
  StopRequests.Catch;
  IF ~Sockets.Listen(host, SHORT(port), 16, TRUE, ls, n, err)
    OR ~Sockets.LocalAddress(ls[0], a, err) THEN
    Err.String("GeminiHello: "); Err.String(err.text); Err.Ln; Platform.Exit(1)
  END;
  (* With port 0, Listen gives both families the same port. *)
  Out.String("port "); Out.Int(a.port, 0); Out.Ln;
  FOR i := 0 TO n - 1 DO NEW(as[i]); as[i].l := ls[i]; Tasks.Start(as[i], TlsTasks.stackSize) END;
  FOR i := 0 TO n - 1 DO Tasks.Join(as[i]) END;
  WHILE handlers # NIL DO Tasks.Join(handlers); handlers := handlers.next END;
  ctx.Close
END Main;

BEGIN
  Main
END GeminiHello.
