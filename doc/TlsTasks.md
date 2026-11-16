# TlsTasks: Tls's connection calls, waiting through Tasks

<!-- Made by doc/mkref.py from TlsTasks.Mod; edit the source, then make doc. -->

Handshake, Read, Write, WriteAll and Close as in Tls, but where Tls on a non-blocking descriptor gives wouldBlock, these wait through Tasks (AwaitReadableFor, AwaitWritableFor) and make the same call again, so other tasks run meanwhile. One OS thread can then serve many connections: a task accepting, and a task per connection (PLAN.md, "Tasks"). A separate module, so a program that doesn't use Tasks doesn't import it.

Every connection given here must be on a non-blocking descriptor; a blocking one halts (97), since a wait in the kernel stops every task. The check is made on each call, since the program may change the mode, so a closed descriptor halts too.

Deadlines: a connection given a deadline (Tls.Connection.SetDeadline) waits here only until then, and the call returns FALSE with kind timedOut. A call that can finish without waiting does, even past the deadline. A timed-out call is simply not made again, as libtls allows, so the connection stays usable: set a later deadline and call again, even in the middle of a handshake (PLAN.md, Phase 6). Or end it: Close sends close_notify, which a stalled handshake doesn't need, so Discard.

A Connection is for one task at a time. Errors are Tls.Error, as from Tls, and never wouldBlock.

Each task needs stack enough for OpenSSL's handshake: PLAN.md, Phase 6, gives what was measured and the size recommended (stackSize).

## Constants

```oberon
stackSize* = 65536;
```

Stack for a task that makes TLS calls here (Tasks.Start): a handshake, server or client, EC or RSA, ran in 16 KiB, poc's least, and wrote about 8 KiB of it (PLAN.md, Phase 6); this leaves room for the task's own work. Only the pages a task touches cost memory.

## Procedures

#### Handshake

```oberon
PROCEDURE Handshake*(c: Tls.Connection): BOOLEAN;
```

Tls.Connection.Handshake, waiting.

#### Read

```oberon
PROCEDURE Read*(c: Tls.Connection; VAR buf: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
```

Tls.Connection.Read, waiting until there is something to read.

#### Write

```oberon
PROCEDURE Write*(c: Tls.Connection; buf-: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
```

Tls.Connection.Write, waiting until it can write.

#### WriteAll

```oberon
PROCEDURE WriteAll*(c: Tls.Connection; buf-: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
```

Writes all len bytes from buf[pos..], waiting as it must; on failure n says how many were written.

#### Close

```oberon
PROCEDURE Close*(c: Tls.Connection): BOOLEAN;
```

Tls.Connection.Close, waiting while close_notify can't be sent. If c's deadline passes first, c is discarded and the result is FALSE, kind timedOut: either way c is closed afterwards. Not checked for a blocking descriptor, on which Tls's Close never gives wouldBlock, so a connection already closed may be closed here again.
