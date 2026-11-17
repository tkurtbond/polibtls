MODULE TestTasks; (* Tls on non-blocking descriptors, and TlsTasks *)

(* Over non-blocking socket pairs from TestPeers, both ends Oberon: first
   Tls alone, the two ends driven in turn by this program's own loop on
   wouldBlock; then TlsTasks, the ends in tasks, with deadlines.
   Certificates are test/make-certs.sh's, from test/. memcheck can't
   follow poc's coroutines, so this runs under valgrind's descriptor
   check only (TASKTESTS). *)

IMPORT Check, Tls, TlsTasks, Tasks, Clocks, TestPeers;

CONST
  certs = "../build/certs/";
  many = 8;            (* clients served at once *)
  deadline = 500;      (* ms a server gives each connection *)
  huge = 4000000;      (* far more than a socket pair holds *)

TYPE
  Name = ARRAY 128 OF CHAR;

  (* The server's end of one connection: handshake, read the request
     line, write size bytes of data, close. With retry, a first timeout
     in the handshake or the read is counted and the deadline renewed. *)
  Server = POINTER TO ServerDesc;
  ServerDesc = RECORD (Tasks.TaskDesc)
    conn: Tls.Connection;
    deadline, size: LONGINT;
    retry: BOOLEAN;
    timeouts: LONGINT;    (* timeouts retried *)
    first: Tls.Error;     (* the first timeout *)
    ok: BOOLEAN;          (* everything succeeded *)
    error: Tls.Error;     (* why not *)
    step: INTEGER;        (* where it stopped: 1 handshake, 2 read, 3 write, 4 close *)
    written: LONGINT;     (* bytes written *)
    ms: HUGEINT           (* how long it ran *)
  END;

  (* The client's end: after delay ms, handshake, send the request, read
     the response to close_notify, close. silent: never handshake, hold
     the connection for delay ms. stall: send the ClientHello, then wait
     that long before finishing the handshake. pause: wait that long
     before sending the request. stuck: send the request, then read
     nothing for that long. slow: send the request a byte at a time,
     that many ms apart. *)
  Client = POINTER TO ClientDesc;
  ClientDesc = RECORD (Tasks.TaskDesc)
    conn: Tls.Connection;
    delay, stall, pause, stuck, slow: LONGINT;
    silent: BOOLEAN;
    ok: BOOLEAN;
    error: Tls.Error;
    got: LONGINT;         (* response bytes read *)
    same: BOOLEAN         (* and they were the data sent *)
  END;

VAR
  crt, key: Name;
  data: POINTER TO ARRAY OF CHAR;  (* the response's bytes *)
  ctx: Tls.Context;
  client, sc: Tls.Config;
  request: ARRAY 32 OF CHAR;  (* "hello, server" CR LF *)
  i: LONGINT;

PROCEDURE Append(VAR s: Name; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0; WHILE part[j] # 0X DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

PROCEDURE Path(name, ext: ARRAY OF CHAR; VAR s: Name);
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, certs); Append(s, i, name); Append(s, i, ext)
END Path;

PROCEDURE Length(s: ARRAY OF CHAR): LONGINT;
  VAR n: LONGINT;
BEGIN n := 0; WHILE s[n] # 0X DO INC(n) END; RETURN n
END Length;

PROCEDURE IsError(e: Tls.Error; kind: INTEGER; part: ARRAY OF CHAR): BOOLEAN;
BEGIN RETURN (e # NIL) & (e.kind = kind) & Check.Contains(e.text^, part)
END IsError;

PROCEDURE Now(): HUGEINT;
BEGIN RETURN Clocks.Monotonic() DIV 1000000
END Now;

(* --- the two ends --- *)

(* Whether the step that just failed is to be tried again. *)
PROCEDURE (s: Server) Retry(): BOOLEAN;
BEGIN
  IF s.retry & (s.timeouts = 0) & (s.conn.error.kind = Tls.timedOut) THEN
    INC(s.timeouts); s.first := s.conn.error;
    s.conn.SetDeadline(5000);
    RETURN TRUE
  END;
  RETURN FALSE
END Retry;

PROCEDURE (s: Server) Run*;
  VAR line: ARRAY 1024 OF CHAR; n, m: LONGINT; start: HUGEINT;
BEGIN
  start := Now(); s.ok := FALSE; s.written := 0;
  s.conn.SetDeadline(s.deadline);
  s.step := 1;
  WHILE ~TlsTasks.Handshake(s.conn) DO
    IF ~s.Retry() THEN s.error := s.conn.error; s.conn.Discard; s.ms := Now() - start; RETURN END
  END;
  s.step := 2; n := 0;
  REPEAT
    WHILE ~TlsTasks.Read(s.conn, line, n, LEN(line) - n, m) DO
      IF ~s.Retry() THEN s.error := s.conn.error; s.conn.Discard; s.ms := Now() - start; RETURN END
    END;
    INC(n, m)
  UNTIL (line[n - 1] = 0AX) OR (n = LEN(line));
  s.step := 3;
  IF ~TlsTasks.WriteAll(s.conn, data^, 0, s.size, s.written) THEN
    s.error := s.conn.error; s.step := 4;
    IF ~TlsTasks.Close(s.conn) THEN s.error := s.conn.error END;
    s.ms := Now() - start; RETURN
  END;
  s.step := 4;
  s.ok := TlsTasks.Close(s.conn);
  s.error := s.conn.error;
  s.ms := Now() - start
END Run;

PROCEDURE (c: Client) Run*;
  VAR buf: ARRAY 16384 OF CHAR; n, i: LONGINT; done: BOOLEAN; req: ARRAY 32 OF CHAR;
BEGIN
  c.ok := FALSE; c.got := 0; c.same := TRUE;
  IF c.delay > 0 THEN Tasks.Sleep(c.delay) END;
  IF c.silent THEN RETURN END;
  IF c.stall > 0 THEN
    IF c.conn.Handshake() OR (c.conn.error.kind # Tls.wouldBlock) THEN
      c.error := c.conn.error; c.conn.Discard; RETURN
    END;
    Tasks.Sleep(c.stall)
  END;
  IF ~TlsTasks.Handshake(c.conn) THEN c.error := c.conn.error; c.conn.Discard; RETURN END;
  IF c.pause > 0 THEN Tasks.Sleep(c.pause) END;
  req := request;
  IF c.slow > 0 THEN
    i := 0;
    WHILE i < Length(req) DO
      IF ~TlsTasks.WriteAll(c.conn, req, i, 1, n) THEN
        c.error := c.conn.error; c.conn.Discard; RETURN
      END;
      INC(i); Tasks.Sleep(c.slow)
    END
  ELSIF ~TlsTasks.WriteAll(c.conn, req, 0, Length(req), n) THEN
    c.error := c.conn.error; c.conn.Discard; RETURN
  END;
  IF c.stuck > 0 THEN Tasks.Sleep(c.stuck); c.conn.Discard; RETURN END;
  done := FALSE;
  WHILE ~done & TlsTasks.Read(c.conn, buf, 0, LEN(buf), n) DO
    FOR i := 0 TO n - 1 DO
      IF (c.got + i >= LEN(data^)) OR (buf[i] # data[c.got + i]) THEN c.same := FALSE END
    END;
    INC(c.got, n)
  END;
  IF c.conn.error.kind # Tls.closed THEN c.error := c.conn.error; c.conn.Discard; RETURN END;
  c.ok := TlsTasks.Close(c.conn);
  c.error := c.conn.error
END Run;

(* A connection over a new non-blocking pair: s's end accepted from ctx,
   c's connected with the client config. a and b are the descriptors, to
   be closed after. *)
PROCEDURE Connect(VAR s: Server; VAR c: Client; VAR a, b: LONGINT);
BEGIN
  NEW(s); NEW(c);
  Check.Check(TestPeers.Pair(a, b, TRUE) & ctx.AcceptSocket(a, s.conn)
    & Tls.ConnectSocket(client, b, "", c.conn),
    "a non-blocking socket pair, AcceptSocket, ConnectSocket");
  s.deadline := deadline; s.size := 1000; s.retry := FALSE; s.timeouts := 0;
  c.delay := 0; c.stall := 0; c.pause := 0; c.stuck := 0; c.slow := 0; c.silent := FALSE
END Connect;

PROCEDURE Run(s: Server; c: Client);
BEGIN
  Tasks.Start(s, TlsTasks.stackSize); Tasks.Start(c, TlsTasks.stackSize);
  Tasks.Join(s); Tasks.Join(c)
END Run;

PROCEDURE Done(a, b: LONGINT);
BEGIN
  Check.Check(TestPeers.Close(a) & TestPeers.Close(b), "close both descriptors")
END Done;

(* A client that read the whole response and closed cleanly *)
PROCEDURE Served(s: Server; c: Client): BOOLEAN;
BEGIN RETURN s.ok & c.ok & (c.got = s.size) & c.same
END Served;

(* --- Tls alone --- *)

(* Both ends in this task, each call made again after wouldBlock until
   it succeeds, as a program with its own poll loop would, but without
   waiting, since the other end's turn is what makes it ready. *)
PROCEDURE Alone;
  VAR s, c: Tls.Connection; a, b, n, m, turns: LONGINT; sDone, cDone: BOOLEAN;
    buf: ARRAY 64 OF CHAR; req: ARRAY 32 OF CHAR;
BEGIN
  Check.Check(TestPeers.Pair(a, b, TRUE), "alone: a non-blocking socket pair");
  Check.Check(ctx.AcceptSocket(a, s), "alone: AcceptSocket");
  Check.Check(Tls.ConnectSocket(client, b, "", c), "alone: ConnectSocket");
  Check.Check(s.NonBlocking() & c.NonBlocking(), "alone: NonBlocking");
  Check.Check(~s.Handshake() & IsError(s.error, Tls.wouldBlock, "readable")
    & (s.error.want = Tls.wantRead), "alone: server Handshake first: wouldBlock, wantRead");
  Check.Check(~c.Handshake() & IsError(c.error, Tls.wouldBlock, "readable")
    & (c.error.want = Tls.wantRead), "alone: client Handshake first: wouldBlock, wantRead (ClientHello sent)");
  sDone := FALSE; cDone := FALSE; turns := 0;
  WHILE ~(sDone & cDone) & (turns < 20) DO
    IF ~sDone THEN
      sDone := s.Handshake();
      IF ~sDone & (s.error.kind # Tls.wouldBlock) THEN turns := 100 END
    END;
    IF ~cDone THEN
      cDone := c.Handshake();
      IF ~cDone & (c.error.kind # Tls.wouldBlock) THEN turns := 100 END
    END;
    INC(turns)
  END;
  Check.Check(sDone & cDone, "alone: both handshakes finish, in turns");
  Check.Check(~s.Read(buf, 0, LEN(buf), n) & (n = 0) & (s.error.kind = Tls.wouldBlock)
    & (s.error.want = Tls.wantRead), "alone: Read with nothing sent: wouldBlock, wantRead");
  req := request;
  Check.Check(c.WriteAll(req, 0, Length(req), m) & (m = Length(req)), "alone: client WriteAll");
  Check.Check(s.Read(buf, 0, LEN(buf), n) & (n = Length(req)), "alone: server Read the request");
  Check.Check(s.Close() & c.Close(), "alone: Close both (close_notify fits in the buffer)");
  Done(a, b)
END Alone;

(* --- TlsTasks --- *)

PROCEDURE OneConnection;
  VAR s: Server; c: Client; a, b: LONGINT;
BEGIN
  Connect(s, c, a, b);
  s.size := 300000; s.deadline := 0;
  Run(s, c);
  Check.Check(Served(s, c), "tasks: handshake, request, 300000 bytes, close_notify, without deadline");
  Done(a, b)
END OneConnection;

(* many at once: some slow, one silent, which the server cuts off at its
   deadline *)
PROCEDURE Many;
  VAR s: ARRAY many OF Server; c: ARRAY many OF Client; a, b: ARRAY many OF LONGINT;
    i, served: LONGINT; silent: INTEGER;
BEGIN
  silent := 3; served := 0;
  FOR i := 0 TO many - 1 DO
    NEW(s[i]); NEW(c[i]);
    IF ~(TestPeers.Pair(a[i], b[i], TRUE) & ctx.AcceptSocket(a[i], s[i].conn)
      & Tls.ConnectSocket(client, b[i], "", c[i].conn)) THEN INC(served) END;
    s[i].deadline := deadline; s[i].retry := FALSE; s[i].timeouts := 0;
    c[i].delay := 0; c[i].stall := 0; c[i].pause := 0; c[i].stuck := 0;
    c[i].slow := 0; c[i].silent := FALSE;
    s[i].size := 50000 * (i + 1);
    IF i MOD 2 = 1 THEN c[i].delay := 100; c[i].slow := 10 END
  END;
  Check.Check(served = 0, "many: socket pairs, AcceptSocket, ConnectSocket");
  c[silent].silent := TRUE; c[silent].delay := deadline + 500;
  FOR i := 0 TO many - 1 DO
    Tasks.Start(s[i], TlsTasks.stackSize); Tasks.Start(c[i], TlsTasks.stackSize)
  END;
  served := 0;
  FOR i := 0 TO many - 1 DO
    Tasks.Join(s[i]); Tasks.Join(c[i]);
    IF (i # silent) & Served(s[i], c[i]) THEN INC(served) END
  END;
  Check.Check(served = many - 1, "many: every other client served, the slow ones too");
  Check.Check(~s[silent].ok & (s[silent].step = 1)
    & IsError(s[silent].error, Tls.timedOut, "handshake timed out"),
    "many: the silent client's handshake timed out (kind timedOut)");
  Check.Check((s[silent].ms >= deadline) & (s[silent].ms < deadline + 400),
    "many: at the deadline");
  served := 0;
  FOR i := 0 TO many - 1 DO
    IF TestPeers.Close(a[i]) & TestPeers.Close(b[i]) THEN INC(served) END
  END;
  Check.Check(served = many, "many: close every descriptor")
END Many;

(* The handshake times out half done, and is then finished: the
   connection stays usable after a timeout. *)
PROCEDURE MidHandshake;
  VAR s: Server; c: Client; a, b: LONGINT;
BEGIN
  Connect(s, c, a, b);
  s.deadline := 100; s.retry := TRUE; c.stall := 400;
  Run(s, c);
  Check.Check((s.timeouts = 1) & IsError(s.first, Tls.timedOut, "handshake timed out"),
    "mid-handshake: the server's handshake timed out once");
  Check.Check(Served(s, c), "mid-handshake: then finished, and the connection served");
  Done(a, b)
END MidHandshake;

PROCEDURE ReadTimeout;
  VAR s: Server; c: Client; a, b: LONGINT;
BEGIN
  Connect(s, c, a, b);
  s.deadline := 100; s.retry := TRUE; c.pause := 400;
  Run(s, c);
  Check.Check((s.timeouts = 1) & IsError(s.first, Tls.timedOut, "read timed out"),
    "read timeout: the server's read timed out once");
  Check.Check(Served(s, c), "read timeout: then read the request, and the connection served");
  Done(a, b)
END ReadTimeout;

(* The client reads nothing: the server's write times out, and so does
   its close, which discards the connection. *)
PROCEDURE WriteTimeout;
  VAR s: Server; c: Client; a, b: LONGINT;
BEGIN
  Connect(s, c, a, b);
  s.deadline := 300; s.size := huge; c.stuck := 800;
  Run(s, c);
  Check.Check(~s.ok & (s.step = 4) & (s.written > 0) & (s.written < huge),
    "write timeout: WriteAll stopped part way");
  Check.Check(IsError(s.error, Tls.timedOut, "close timed out"),
    "write timeout: then Close timed out too");
  Check.Check(s.conn.Close(), "write timeout: the connection was discarded");
  Done(a, b)
END WriteTimeout;

PROCEDURE Deadlines;
  VAR s, c: Tls.Connection; a, b: LONGINT;
BEGIN
  Check.Check(TestPeers.Pair(a, b, TRUE), "deadlines: a non-blocking socket pair");
  Check.Check(ctx.AcceptSocket(a, s), "deadlines: AcceptSocket");
  Check.Check((s.deadline = 0) & (s.TimeLeft() = -1), "deadlines: none at first");
  s.SetDeadline(1000);
  Check.Check((s.deadline # 0) & (s.TimeLeft() > 900) & (s.TimeLeft() <= 1000),
    "deadlines: SetDeadline(1000)");
  s.SetDeadline(0);
  Check.Check((s.deadline = 0) & (s.TimeLeft() = -1), "deadlines: SetDeadline(0) clears it");
  s.SetDeadline(1); Tasks.Sleep(5);
  Check.Check(s.TimeLeft() = 0, "deadlines: passed, TimeLeft is 0");
  Check.Check(~TlsTasks.Handshake(s) & IsError(s.error, Tls.timedOut, "handshake timed out"),
    "deadlines: a deadline already past still looks once, then times out");
  s.Discard;
  Done(a, b)
END Deadlines;

BEGIN
  TestPeers.IgnoreBrokenPipe;
  NEW(data, huge);
  FOR i := 0 TO huge - 1 DO data[i] := CHR(i MOD 251) END;
  request := "hello, server"; i := Length(request);
  request[i] := 0DX; request[i + 1] := 0AX; request[i + 2] := 0X;
  sc := Tls.NewConfig();
  Path("self-ec", ".crt", crt); Path("self-ec", ".key", key);
  Check.Check(sc.SetKeypairFile(crt, key), "server config");
  sc.VerifyClientOptional; sc.InsecureNoVerifyCert;
  ctx := Tls.NewServer();
  Check.Check(ctx.Configure(sc), "server context");
  sc.Close;
  client := Tls.NewConfig();
  client.InsecureNoVerifyCert; client.InsecureNoVerifyName;
  Alone; Deadlines; OneConnection; Many; MidHandshake; ReadTimeout; WriteTimeout;
  client.Close; ctx.Close;
  Check.Summary
END TestTasks.
