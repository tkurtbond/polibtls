MODULE TestPeers; (* What the tests need from the system beyond libtls *)

(* Its C part, TestPeers.c, is compiled with it. *)

IMPORT SYSTEM;

PROCEDURE ["C", "TestPeers.-pair"] CPair(VAR fds: ARRAY OF SYSTEM.INT64; nonblocking: SYSTEM.INT32): SYSTEM.INT32;
PROCEDURE ["C", "TestPeers.-close"] CClose(fd: SYSTEM.INT64): SYSTEM.INT32;
PROCEDURE ["C", "TestPeers.-ignore-sigpipe"] CIgnoreSigpipe;
PROCEDURE ["C", "TestPeers.-start"] CStart(server: SYSTEM.INT32; fd: SYSTEM.INT64;
  ca, cert, key, servername, send: ARRAY OF CHAR; sendlen, expect: SYSTEM.INT64;
  abrupt: SYSTEM.INT32): SYSTEM.ADDRESS;
PROCEDURE ["C", "TestPeers.-join"] CJoin(p: SYSTEM.ADDRESS; VAR got: ARRAY OF CHAR;
  gotmax: SYSTEM.INT64; VAR gotlen: SYSTEM.INT64; VAR error: ARRAY OF CHAR;
  errormax: SYSTEM.INT64): SYSTEM.INT32;
PROCEDURE ["C", "TestPeers.-spawn"] CSpawn(command, input: ARRAY OF CHAR;
  inputlen: SYSTEM.INT64; VAR out: SYSTEM.INT64): SYSTEM.INT32;
PROCEDURE ["C", "TestPeers.-wait"] CWait(pid: SYSTEM.INT32; out: SYSTEM.INT64;
  VAR got: ARRAY OF CHAR; gotmax: SYSTEM.INT64; VAR gotlen: SYSTEM.INT64): SYSTEM.INT32;
PROCEDURE ["C", "TestPeers.-readline"] CReadLine(out: SYSTEM.INT64;
  VAR line: ARRAY OF CHAR; max: SYSTEM.INT64; ms: SYSTEM.INT32): SYSTEM.INT32;
PROCEDURE ["C", "TestPeers.-kill"] CKill(pid: SYSTEM.INT32);

TYPE
  (* A TLS peer running in a thread of its own (TestPeers.c, "struct
     peer"), 0 if none could start. *)
  Peer* = SYSTEM.ADDRESS;

  (* A command running as a child process (Spawn). *)
  Child* = RECORD pid: SYSTEM.INT32; out: SYSTEM.INT64 END;

(* A connected pair of stream sockets, a for the server, b for the
   client; non-blocking if asked. *)
PROCEDURE Pair*(VAR a, b: LONGINT; nonblocking: BOOLEAN): BOOLEAN;
VAR fds: ARRAY 2 OF SYSTEM.INT64; nb: SYSTEM.INT32;
BEGIN
  IF nonblocking THEN nb := 1 ELSE nb := 0 END;
  IF CPair(fds, nb) # 0 THEN RETURN FALSE END;
  a := SYSTEM.VAL(LONGINT, fds[0]); b := SYSTEM.VAL(LONGINT, fds[1]);
  RETURN TRUE
END Pair;

PROCEDURE Close*(fd: LONGINT): BOOLEAN;
BEGIN RETURN CClose(fd) = 0
END Close;

PROCEDURE Flag(b: BOOLEAN): SYSTEM.INT32;
BEGIN IF b THEN RETURN 1 ELSE RETURN 0 END
END Flag;

(* A client on fd: verifies the server against ca ("": not at all),
   with a certificate if cert # "", asking for servername ("": none);
   writes send[0..sendlen-1], reads until end of data, then closes
   (with close_notify unless abrupt). *)
PROCEDURE StartClient*(fd: LONGINT; ca, cert, key, servername, send: ARRAY OF CHAR;
    sendlen: LONGINT; abrupt: BOOLEAN): Peer;
BEGIN
  RETURN CStart(0, fd, ca, cert, key, servername, send, sendlen, 0, Flag(abrupt))
END StartClient;

(* A server on fd with key pair cert and key, a client certificate
   optional and not verified: reads until it has expect bytes or end of
   data, writes send[0..sendlen-1], then closes (with close_notify
   unless abrupt). *)
PROCEDURE StartServer*(fd: LONGINT; cert, key: ARRAY OF CHAR; expect: LONGINT;
    send: ARRAY OF CHAR; sendlen: LONGINT; abrupt: BOOLEAN): Peer;
BEGIN
  RETURN CStart(1, fd, "", cert, key, "", send, sendlen, expect, Flag(abrupt))
END StartServer;

(* Waits for p to finish: what it read, as much as fits, and how much
   that was in all; and "" or what failed. TRUE if it all went well. *)
PROCEDURE Join*(p: Peer; VAR got: ARRAY OF CHAR; VAR gotlen: LONGINT;
    VAR error: ARRAY OF CHAR): BOOLEAN;
  VAR n: SYSTEM.INT64; r: SYSTEM.INT32;
BEGIN
  r := CJoin(p, got, LEN(got), n, error, LEN(error));
  gotlen := SYSTEM.VAL(LONGINT, n);
  RETURN r = 0
END Join;

(* Runs command with /bin/sh -c as a child process, giving it
   input[0..inputlen-1] (at most 64 KiB) on its standard input and then
   end of file. FALSE if it couldn't start. Its output, standard error
   included, must fit 64 KiB until Wait reads it. *)
PROCEDURE Spawn*(command, input: ARRAY OF CHAR; inputlen: LONGINT;
    VAR c: Child): BOOLEAN;
BEGIN
  c.pid := CSpawn(command, input, inputlen, c.out);
  RETURN c.pid > 0
END Spawn;

(* Waits for c to end: its output, standard error included, as much as
   fits in got, and how much there was in all; its exit status, or -1
   if it didn't exit normally. *)
PROCEDURE Wait*(VAR c: Child; VAR got: ARRAY OF CHAR; VAR gotlen: LONGINT): INTEGER;
  VAR n: SYSTEM.INT64; r: SYSTEM.INT32;
BEGIN
  r := CWait(c.pid, c.out, got, LEN(got), n);
  gotlen := SYSTEM.VAL(LONGINT, n);
  RETURN r
END Wait;

(* Reads c's next line of output, while it runs, into line, the newline
   included, waiting at most ms for each byte; FALSE if its output ended
   or ms passed first. Wait gets what is left. *)
PROCEDURE ReadLine*(VAR c: Child; VAR line: ARRAY OF CHAR; ms: LONGINT): BOOLEAN;
BEGIN RETURN CReadLine(c.out, line, LEN(line), SHORT(ms)) >= 0
END ReadLine;

(* Ends c, as for a server that won't finish by itself; Wait for it
   afterwards. *)
PROCEDURE Kill*(VAR c: Child);
BEGIN CKill(c.pid)
END Kill;

PROCEDURE IgnoreBrokenPipe*;
BEGIN CIgnoreSigpipe
END IgnoreBrokenPipe;

END TestPeers.
