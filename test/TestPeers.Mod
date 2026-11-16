MODULE TestPeers; (* What the tests need from the system beyond libtls *)

(* Its C part, TestPeers.c, is compiled with it. *)

IMPORT SYSTEM;

PROCEDURE ["C", "TestPeers.-pair"] CPair(VAR fds: ARRAY OF SYSTEM.INT64; nonblocking: SYSTEM.INT32): SYSTEM.INT32;
PROCEDURE ["C", "TestPeers.-close"] CClose(fd: SYSTEM.INT64): SYSTEM.INT32;
PROCEDURE ["C", "TestPeers.-ignore-sigpipe"] CIgnoreSigpipe;

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

PROCEDURE IgnoreBrokenPipe*;
BEGIN CIgnoreSigpipe
END IgnoreBrokenPipe;

END TestPeers.
