MODULE TlsTasks; (* Tls's connection calls, waiting through Tasks *)

(* Handshake, Read, Write, WriteAll and Close as in Tls, but where Tls
   on a non-blocking descriptor gives wouldBlock, these wait through
   Tasks (AwaitReadableFor, AwaitWritableFor) and make the same call
   again, so other tasks run meanwhile. One OS thread can then serve
   many connections: a task accepting, and a task per connection
   (PLAN.md, "Tasks"). A separate module, so a program that doesn't use
   Tasks doesn't import it.

   Every connection given here must be on a non-blocking descriptor; a
   blocking one halts (97), since a wait in the kernel stops every
   task. The check is made on each call, since the program may change
   the mode, so a closed descriptor halts too.

   Deadlines: a connection given a deadline (Tls.Connection.SetDeadline)
   waits here only until then, and the call returns FALSE with kind
   timedOut. A call that can finish without waiting does, even past the
   deadline. A timed-out call is simply not made again, as libtls
   allows, so the connection stays usable: set a later deadline and call
   again, even in the middle of a handshake (PLAN.md, Phase 6). Or end
   it: Close sends close_notify, which a stalled handshake doesn't need,
   so Discard.

   A Connection is for one task at a time. Errors are Tls.Error, as from
   Tls, and never wouldBlock.

   Each task needs stack enough for OpenSSL's handshake: PLAN.md, Phase
   6, gives what was measured and the size recommended (stackSize). *)

IMPORT Tasks, Tls;

CONST
  (* Stack for a task that makes TLS calls here (Tasks.Start): a
     handshake, server or client, EC or RSA, ran in 16 KiB, poc's least,
     and wrote about 8 KiB of it (PLAN.md, Phase 6); this leaves room
     for the task's own work. Only the pages a task touches cost
     memory. *)
  stackSize* = 65536;

(* Halts unless c's descriptor is non-blocking. *)
PROCEDURE Check(c: Tls.Connection);
BEGIN ASSERT(c.NonBlocking(), 97)
END Check;

(* After a call on c gave wouldBlock: waits for c's descriptor as
   c.error.want says, until c's deadline. FALSE, with c.error timedOut,
   if the deadline came first. A deadline already past still looks
   once. *)
PROCEDURE Await(c: Tls.Connection; what: ARRAY OF CHAR): BOOLEAN;
  VAR left: LONGINT; read, ready: BOOLEAN;
BEGIN
  read := c.error.want = Tls.wantRead;
  left := c.TimeLeft();
  IF left < 0 THEN
    IF read THEN Tasks.AwaitReadable(c.fd) ELSE Tasks.AwaitWritable(c.fd) END;
    ready := TRUE
  ELSIF read THEN ready := Tasks.AwaitReadableFor(c.fd, left)
  ELSE ready := Tasks.AwaitWritableFor(c.fd, left)
  END;
  IF ~ready THEN c.TimedOut(what) END;
  RETURN ready
END Await;

(* Whether the call that just failed on c is to be made again: it gave
   wouldBlock, and the wait for what then succeeded. *)
PROCEDURE Again(c: Tls.Connection; what: ARRAY OF CHAR): BOOLEAN;
BEGIN RETURN (c.error.kind = Tls.wouldBlock) & Await(c, what)
END Again;

(* Tls.Connection.Handshake, waiting. *)
PROCEDURE Handshake*(c: Tls.Connection): BOOLEAN;
BEGIN
  Check(c);
  WHILE ~c.Handshake() DO
    IF ~Again(c, "handshake") THEN RETURN FALSE END
  END;
  RETURN TRUE
END Handshake;

(* Tls.Connection.Read, waiting until there is something to read. *)
PROCEDURE Read*(c: Tls.Connection; VAR buf: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
BEGIN
  Check(c);
  WHILE ~c.Read(buf, pos, len, n) DO
    IF ~Again(c, "read") THEN RETURN FALSE END
  END;
  RETURN TRUE
END Read;

(* Tls.Connection.Write, waiting until it can write. *)
PROCEDURE Write*(c: Tls.Connection; buf-: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
BEGIN
  Check(c);
  WHILE ~c.Write(buf, pos, len, n) DO
    IF ~Again(c, "write") THEN RETURN FALSE END
  END;
  RETURN TRUE
END Write;

(* Writes all len bytes from buf[pos..], waiting as it must; on failure
   n says how many were written. *)
PROCEDURE WriteAll*(c: Tls.Connection; buf-: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
  VAR m: LONGINT;
BEGIN
  Check(c);
  n := 0;
  WHILE ~c.WriteAll(buf, pos + n, len - n, m) DO
    INC(n, m);
    IF ~Again(c, "write") THEN RETURN FALSE END
  END;
  INC(n, m);
  RETURN TRUE
END WriteAll;

(* Tls.Connection.Close, waiting while close_notify can't be sent. If
   c's deadline passes first, c is discarded and the result is FALSE,
   kind timedOut: either way c is closed afterwards. Not checked for a
   blocking descriptor, on which Tls's Close never gives wouldBlock, so
   a connection already closed may be closed here again. *)
PROCEDURE Close*(c: Tls.Connection): BOOLEAN;
BEGIN
  IF c.Close() THEN RETURN TRUE END;
  WHILE c.error.kind = Tls.wouldBlock DO
    IF ~Await(c, "close") THEN c.Discard; RETURN FALSE END;
    IF c.Close() THEN RETURN TRUE END
  END;
  RETURN FALSE
END Close;

END TlsTasks.
