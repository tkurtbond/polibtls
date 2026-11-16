# PLAN.md

polibtls: an Oberon-2 binding to libtls (LibreTLS 3.8.1 on Linux) for
poc, the Peaseblossom Oberon Compiler, to be used later by a Gemini
server. AGENTS.md has the operational notes; this file is the design,
the decisions and the roadmap. Append to the relevant section as work
goes; mark a finished phase `[done]`, and strike through an open
question once it is decided, saying what was decided and when.

## Goal and scope

The binding is done when a poc program can, using polibtls, posockets
(a separate library; see "Sockets: posockets") and poc's runtime:

1. load a server certificate and key (several, chosen by SNI);
2. do the TLS handshake on each connection posockets accepts, given
   only its descriptor;
3. accept, but not require, a client certificate, and report its
   SHA-256 fingerprint, subject and validity dates, without verifying
   it against any CA (Gemini's client certificates are self-signed and
   trusted on first use);
4. read a request line of at most 1024 bytes plus CRLF, write a
   response header and body, and close with a TLS close_notify, which
   Gemini requires;
5. serve many connections at once in one OS thread, each in its own
   poc `Tasks` task, with non-blocking sockets, so one slow client
   stops no other;
6. act as a client too (connect, verify or pin the server's
   certificate), for tests and for a later Gemini client or proxy.

In scope: libtls's configuration, server and client contexts, the
`_socket` and `_fds` forms of accept and connect, handshake, read,
write, close, and peer certificate and connection queries, all on
descriptors the caller supplies. Sockets themselves (listening,
accepting, connecting, non-blocking mode, closing) are posockets' job,
and polibtls doesn't import it. Out of scope for now, though nothing
should rule them out: OCSP and CRLs, session tickets and session files,
`tls_accept_cbs`/`tls_connect_cbs` (C calling Oberon for I/O), ALPN,
DHE parameters, and the BSDs (OpenBSD's own libtls has the same API, so
porting polibtls should take little work; posockets will take more). The Gemini
server itself, URL parsing and the `text/gemini` format belong to the
later project, not here.

## Gemini's requirements on TLS

From the specification (AGENTS.md, "Reference material"); to be
re-read before Phase 7:

- TLS 1.2 or higher is required; 1.3 is preferred. libtls's default
  protocols are already `TLS_PROTOCOL_TLSv1_2|TLS_PROTOCOL_TLSv1_3`,
  and LibreTLS 3.8.1 maps the 1.0 and 1.1 bits onto 1.2's
  (`/usr/include/tls.h`), so nothing older can be asked for.
- Clients send SNI; a server with several capsules picks a key pair by
  it (`tls_config_add_keypair_file`) and can read it back
  (`tls_conn_servername`).
- Servers commonly use self-signed certificates, and clients pin them
  (TOFU). Client certificates are likewise self-signed and identify a
  user by fingerprint: the server config needs
  `tls_config_verify_client_optional` with
  `tls_config_insecure_noverifycert`, and the server reads
  `tls_peer_cert_provided`, `tls_peer_cert_hash`,
  `tls_peer_cert_subject`, `tls_peer_cert_notbefore`/`notafter`.
  `noverifycert` is enough for libtls to accept an unknown self-signed
  client certificate, and an expired one is accepted too (Phase 0,
  item 4), so the server judges expiry itself if it cares.
- The request is a single absolute URL, at most 1024 bytes, then CRLF.
  The response is `<2-digit status> <meta>` CRLF, then for 2x a body,
  then the server closes the connection; a TLS close_notify must be
  sent (`tls_close`) so a client can tell a complete body from a
  truncated one.
- The default port is 1965.

## Design

### Modules

| Module | Role |
|---|---|
| `TlsThin` (+ `TlsThin.c`) | libtls one to one: handles as `SYSTEM.ADDRESS`, ints as `SYSTEM.INT32`, `ssize_t` and `time_t` as `SYSTEM.INT64`. No policy. |
| `Tls` | the thick layer: `Config`, `Context`, `Connection`, `Error`, `Certificate` info, string copying, `Close` and finalizers, halts on misuse. |
| `Tls` (+ `Tls.c`) | `Tls.c`: whether a descriptor is non-blocking (`fcntl`), and a monotonic clock in ms for deadlines (Phase 6). |
| `TlsTasks` | handshake/read/write/close loops that turn `Tls`'s `wouldBlock` into `Tasks.AwaitReadableFor`/`AwaitWritableFor` until the connection's deadline, then make the same call again (Phase 6). |

The library is `polibtls`, holding all of them; it records `-ltls` so a
program passes no flags for it. `Tasks` integration is a separate
module, `TlsTasks`, so a program that never uses `Tasks` doesn't import
it (decided in Phase 6, as posockets' `SocketTasks`).

polibtls deals in descriptors only: a descriptor is a `LONGINT`, as
`Tasks.AwaitReadable` takes it, and the caller gets it from posockets,
from `socketpair` in a test, or from anything else that makes one.
polibtls never imports posockets, so a program that has its descriptors
from elsewhere doesn't link it.

### Integer model

`-OC`, as polibfyaml: `INTEGER` 32 bits and `LONGINT` 64, so sizes and
counts in the thick layer are plain `LONGINT` and need no conversion to
`size_t`. The thin layer uses explicit widths only, so it would also be
right under `-O2`. Whether to install an `-O2` variant too, as pofltk
does, is an open question; nothing in the design depends on it.

### Handles and lifetime

- `Config`, `Context` and `Connection` are Oberon objects holding their
  libtls pointer, 0 once freed. `Close` frees and zeroes; every method
  halts on a closed object (`Halt codes`). A finalizer calls the same
  free, as a backstop only.
- ~~libtls requires a `Config` to outlive every context configured with
  it.~~ LibreTLS reference-counts a `tls_config` (Phase 0, 2026-11-15):
  `tls_configure` and every accepted connection (`tls_server_conn`)
  take a reference, and `tls_config_free` drops one. A config freed
  right after `tls_configure`, then used for handshakes, was clean
  under valgrind. So `Config.Close` after `Configure` is safe, and
  halt 94 is not needed for configs.
- A `Connection` is made by `tls_accept_socket`/`_fds` from a server
  `Context`, and is freed by `tls_free` on its own. **The server
  context must outlive the handshake of every connection accepted from
  it** (Phase 0): freed after `tls_accept_socket` and before
  `tls_handshake`, the handshake segfaulted, because OpenSSL's
  servername callback (`tls_servername_cb`, `tls_server.c:120`) reads
  the server context and its SNI list. Freed after the handshake, the
  connection read, wrote and closed cleanly under valgrind. So a
  `Connection` keeps a pointer to its `Context`, so the collector keeps
  the context, and `Context.Close` while a `Connection` from it is
  still open halts (code 94, now free for this; to settle in Phase 4).
  Settled (Phase 4): a `Context` counts its open connections, and
  `Close` with any open halts 94. Its finalizer never halts: the
  collector finalizes the newest object first, so a context's
  connections, which keep it reachable, go before it; should one not,
  the context is marked and the last connection to close frees it.
  A `Connection`'s finalizer frees it without close_notify, since by
  then the program may have closed the descriptor and its number may
  be another's.
- A `Connection` keeps its descriptor, for the `Tasks` loops: `Close`
  does `tls_close` (close_notify, looping on `WANT_*`), then
  `tls_free`, and leaves the descriptor open: whoever made it closes it
  (`posockets`' `Close`). Confirmed (Phase 0): after `tls_close` and
  after `tls_free` of an accepted connection the descriptor is still
  open. `tls_close` closes only a descriptor libtls opened itself,
  which only `tls_connect` by host name does (`ctx->socket`,
  `tls.c:1005`); the binding doesn't bind it.
- Strings libtls returns (`tls_error`, `tls_peer_cert_hash`, subject,
  issuer, `tls_conn_version`, `tls_conn_cipher`,
  `tls_conn_servername`) are copied into a new `POINTER TO ARRAY OF
  CHAR` at once, since libtls owns them and may free them on the next
  call. An absent one (NULL) is NIL, not "".
  Confirmed for errors (Phase 0): a config's error string is freed when
  the next failing setter replaces it (valgrind: invalid read through
  the old pointer), and a later *successful* setter leaves the old text
  in place. A context's error is cleared only on entry to
  `tls_handshake`, `tls_read`, `tls_write` and `tls_close`; a successful
  `tls_connect_socket` left an earlier error standing. So the text is
  read only right after the call that failed, and a non-NULL
  `tls_error` alone never means a call failed.
- What libtls is given: file names and option strings are copied by
  libtls (its `tls_config_set_*` functions `strdup` or load at once;
  to confirm for each one bound). `*_mem` key material is copied by
  libtls; the binding then zeroes its own copy. Confirmed from
  LibreTLS 3.8.1's source (Phase 0): every `*_mem` setter goes through
  `tls_set_mem` (`memdup`), and keys are freed with `freezero`. A
  `*_file` setter also reads the key into libtls's memory, where it
  stays until `tls_config_clear_keys`; a server that called it after
  `tls_configure` still handshook, so `Configure` calls it. Done
  (Phase 4): a server `Context.Configure` clears the config's keys
  whether it succeeds or not, so the config serves no further server
  context until its key pairs are set again (a second `Configure` then
  fails, "private/public key mismatch"). A client's keys aren't
  cleared: libtls loads them in `tls_connect_socket`, so a config
  serves any number of client connections. Read and write buffers
  are only used during the call, so an `ARRAY OF CHAR`/`ARRAY OF
  SYSTEM.BYTE` passed by `VAR` (never by value, to avoid a pointless
  copy) is fine.

### Errors

As polibfyaml: a call that can fail for outside reasons returns
`BOOLEAN`, and the object keeps the last error (its read-only `error`
field, `NIL` after a call that succeeded; Phase 3) (`Error`: libtls's
message, copied, plus a kind: `config`, `handshake`, `io`, `closed`,
`system` with `errno`). `ASSERT`/`HALT` are for programmer errors only.
~~`system` with `errno`~~: LibreTLS sets `errno` to 0 on leaving
`tls_handshake`, `tls_read`, `tls_write` and `tls_close` ("to prevent
callers from performing incorrect error handling", tls.c), so after a
failed write to a gone peer it is 0, not `EPIPE`, and the text
("write failed: Broken pipe") is all there is (Phase 2). A config
setter leaves it (`ENOENT` for a missing CA file), but its text says
the same. So the binding doesn't read `errno` at all; the kinds are
`config`, `handshake`, `io` and `closed`, with libtls's text.
~~A peer that closes early (`tls_read` returning 0) is not an error: it
is end of data.~~ (Phase 4) `Read` at the end of data, after the peer's
close_notify, returns `FALSE` with kind `closed`, "connection closed by
peer", as posockets' `Read` does, so a read loop is `WHILE c.Read(...)`
and the error says which end it was. A peer that goes without
close_notify is kind `io`: OpenSSL 3 reports it ("unexpected eof while
reading"), so LibreTLS's own `TLS_EOF_NO_CLOSE_NOTIFY` path, for
OpenSSL's older behaviour, isn't reached. A truncation is thus never
mistaken for a complete response.
Phase 6 adds two kinds. `wouldBlock`: a call on a non-blocking
descriptor that must wait, with `want` (`wantRead` or `wantWrite`)
saying for what; its `Error` is one of two shared, preallocated
objects, so a poll loop allocates nothing. `timedOut`: a `TlsTasks`
call whose connection's deadline passed, "<what> timed out", where what
is handshake, read, write or close.

### I/O

- `Read(c, VAR buf, pos, len, VAR n): BOOLEAN` and `Write(c, buf, pos,
  len, VAR n)`, offsets into an open array, so no slice copies.
  `WriteAll` loops over short writes. `ReadLine(c, VAR line, max)` reads
  to CRLF with a limit, for Gemini's request (later, maybe, in the
  server project).
- Blocking mode first (Phase 4). ~~On a blocking descriptor libtls
  never returns `WANT_*`.~~ It does (Phase 0): LibreTLS clears
  `SSL_MODE_AUTO_RETRY` (`tls.c:576`), so a blocking client's
  `tls_read` returned `TLS_WANT_POLLIN` after TLS 1.3's session tickets
  (twice per connection), and `tls_read(3)` says to repeat the same
  call at once. So the blocking calls loop on `WANT_*` too, without
  waiting. Non-blocking mode (Phase 6): the `Tasks` loops
  wait and retry. Without `Tasks`, a non-blocking call returns a
  `wouldBlock` result with which direction to wait for, so a program
  with its own `poll` loop can still use the binding.
  Done in Phase 6: `Tls`'s calls follow the descriptor's mode, read
  with `fcntl` only when libtls asks to wait, so the program may change
  it at any time: on a blocking one they retry at once, on a
  non-blocking one they return `FALSE`, kind `wouldBlock`. `Close` that
  would block doesn't free, so it can be called again; `Discard` frees
  without close_notify. LibreTLS sets `SSL_MODE_ENABLE_PARTIAL_WRITE`
  and `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER` (`tls.c:576-579`), so a
  `Write` made again after `wouldBlock` must give the same bytes and
  length, though not at the same address.
- `SIGPIPE`: writing to a socket the peer has closed raises it and
  kills the program by default. Whether LibreTLS uses `MSG_NOSIGNAL`
  (it writes through OpenSSL's socket BIO, which uses `write`, so
  probably not) was to be confirmed in Phase 0; it doesn't, below. Linux has no
  `SO_NOSIGPIPE`, and `MSG_NOSIGNAL` can't reach OpenSSL's writes, so
  the fix is process-wide: ignoring `SIGPIPE`, after which the write
  fails with `EPIPE`. That is posockets' to offer (a server needs it
  for plain sockets too), not polibtls's; polibtls's tests ignore it
  through their C helper (Testing). Confirmed (Phase 0): a `tls_write`
  to a peer that had exited killed the process with signal 13; with
  `SIGPIPE` ignored it returned -1, "write failed: ... Broken pipe".
  A server's `tls_close` after its peer has gone fails the same way
  ("shutdown failed: ... Broken pipe"), which `Close` reports but
  doesn't treat as worse than a missing close_notify.

### Sockets: posockets

Decided 2026-11-15 (with the user): sockets are a separate poc library,
**posockets**, in its own repo (`~/Repos/Oberon/posockets`, created
2026-11-15), whose AGENTS.md and PLAN.md hold its design, because the Gemini server
needs sockets apart from TLS (plain TCP, maybe Unix-domain sockets, a
proxy) and other Oberon programs can use it. poc's runtime has none, and
libtls's `tls_connect` covers only a client's simplest case. What
polibtls and the Gemini server need from it, as a starting point for
its PLAN.md:

- `Listen(host, port, backlog, VAR listeners)`: `getaddrinfo`, one
  descriptor per address family, `SO_REUSEADDR`, `IPV6_V6ONLY`; port 0
  for the kernel's choice, and `LocalPort(fd)` to read it back.
- `Accept(fd, VAR client, VAR peer)`, the peer's address as text.
- `Connect(host, port, VAR fd)`.
- `SetNonBlocking(fd)`, `Close(fd)`, `Shutdown(fd, how)`.
- `Pair(VAR a, b)` (`socketpair`).
- `IgnoreBrokenPipe` (`SIGPIPE`, above).
- Non-blocking accept and connect that wait through `Tasks`
  (`AwaitReadable`/`AwaitWritable`), as polibtls's loops do; posockets'
  own design decides whether that is a separate module.
- Descriptors are `LONGINT`; errors are a `BOOLEAN` result plus
  `errno` and its text, never a halt.

polibtls's library never imports posockets. Its tests use it only from
Phase 5, as a test-only dependency taken from posockets' installed
library; until then, and for the socket pair in every phase, they use a
small C helper in `test/` (Testing).

posockets' PLAN.md took this list and settled the shape on 2026-11-15;
what differs from the list above:

- Sockets are a `Socket` object, not a bare descriptor; polibtls takes
  the descriptor from `s.fd` (read-only), and posockets' `Close` sets
  it to -1. posockets registers no finalizer on sockets, so a
  descriptor never closes under a `Connection` still using it.
- Ports are `INTEGER`s, never service names. `LocalAddress(s, VAR a)`
  replaces `LocalPort(fd)`. With port 0, `Listen` gives both families
  the same port, so a test reads it back once.
- `Close` on a socket that a `SocketTasks` call is waiting on halts.
  polibtls's own waits aren't counted, so closing the descriptor while
  a TLS loop waits on it is still the caller's bug, unchecked.
- Deadlines come from the timed descriptor wait now in poc's `Tasks`
  (Tasks, below), not from a watchdog that shuts the socket
  down. A deadline set on a posockets `Socket` covers only
  `SocketTasks`' own waits, never polibtls's.

### Tasks

poc's `Tasks` (`rtl/llvm/Tasks.Mod`) is cooperative over coroutines in
one OS thread: a task runs until it calls something that can block,
and a blocking call of any other module stops every task. So a server
built on it must put every socket in non-blocking mode and turn each
`TLS_WANT_POLLIN`/`POLLOUT` into `Tasks.AwaitReadable`/`AwaitWritable`
on the connection's descriptor, then retry the same call with the same
arguments (libtls requires that). The accept loop is a task that awaits
the listening socket. Each task has its own `mmap`'d stack:
OpenSSL's handshake uses an unknown amount of stack, to be measured in
Phase 6 (deepest use under valgrind or by a guard-page probe) and
recorded with the stack size the binding recommends. Measured in Phase
6: about 8 KiB, and 16 KiB, poc's least, is enough;
`TlsTasks.stackSize` is 64 KiB.

**Deadlines.** A Gemini server must cut off a client that stalls in
the handshake or never sends its request, but `Tasks.AwaitReadable`/
`AwaitWritable` wait without limit, and a task blocked in one can't
also wait on `Tasks.After`. Decided in posockets on 2026-11-15, and
added to poc's `Tasks` the same day (Peaseblossom commit 73109d2,
after 0.12.0, first released in 0.13.0; its `doc/developer/tasks.md`,
decision 15): `Tasks.AwaitReadableFor(fd, ms: LONGINT): BOOLEAN` and
`AwaitWritableFor`, `TRUE` when `fd` is ready, `FALSE` when `ms` passed
first. If both are due at one look the timer wins; an `ms` that isn't
positive polls once, then `Yield`s; a negative descriptor is trap 20.
polibtls's `WANT_*`
loops then take a deadline themselves: each wait passes the time
remaining, and a wait that runs out returns a `timedOut` error, as
posockets' does. libtls requires a retried call to have the same
arguments, and a timed-out call is simply not retried, so this fits
its rules; whether the `Connection` is still usable after a timeout in
the middle of a handshake, or must only be closed, is to be found in
Phase 6. Found: it is usable (Phase 6). Done as
`Connection.SetDeadline(ms)` (from now; 0 for none), read by
`TimeLeft`, and `TlsTasks` waits only that long. A server can still cut a connection off from another task
with posockets' `Shutdown`, which wakes the waiting TLS loop with an
error and ends the connection; with the timed wait it is no longer
needed for deadlines.

### Halt codes

`ASSERT(cond, n)` exits with status 10 and prints `assertion failed
(n)`. polibtls uses n in 90..99, apart from Peaseblossom's runtime
(10..20), polibfyaml's 61..65, pofltk's 70..78 and posockets' 80..89
(moved from 70..79 on 2026-11-15, which clashed with pofltk's):

| n | Meaning |
|---|---|
| 90 | `tls_init` failed (called once, from `Tls`'s body) |
| 91 | a closed `Config`, `Context` or `Connection` used |
| 92 | ~~the wrong kind of context (accept on a client, connect on a server, I/O on a server context)~~ unused: since Phase 4 a `Context` is a server's and a client's context is its `Connection`, so the types rule it out; kept free |
| 93 | a buffer range out of bounds (pos/len outside the array) |
| 94 | a server `Context` closed while a `Connection` accepted from it is still open (libtls reference-counts configs, so a closed `Config` needs no halt; Phase 0) |
| 95 | a negative descriptor given to accept or connect |
| 96 | libtls couldn't allocate a config or context (`tls_config_new`, `tls_server`, `tls_client` returned NULL), as `NEW` halts when out of memory |
| 97 | a connection on a blocking descriptor given to `TlsTasks` (a wait in the kernel would stop every task); checked on each call, so a closed descriptor halts too |
| 98 | a negative time given to `Connection.SetDeadline` |

## Testing

- `test/Check.Mod` and one main module per concern, as polibfyaml.
  Halt tests one per code.
- Certificates: the makefile makes them with `openssl` into
  `build/certs/`: a CA and a server key pair signed by it (for a
  verifying client), a self-signed server pair, two self-signed client
  pairs, an expired one, and a pair for a second SNI name. ECDSA P-256
  and RSA 2048 both, since Gemini clients meet both.
- `test/TestPeers.c`, a C helper linked only into the tests (as a `.o`
  with no `.sym`, which `poc -build` accepts): `socketpair`, setting a
  descriptor non-blocking, closing it, ignoring `SIGPIPE`, and a TLS
  peer in a thread of its own for the blocking tests (Phase 4), and a
  command run as a child process (`Spawn`, `Wait`: `/bin/sh -c`, its
  input given through a pipe and its output read back; Phase 5). It is a few lines each, so the
  tests of Phases 1 to 4 need nothing outside this repo, and polibtls
  can be built and tested before posockets exists.
- Handshakes without the network: a socket pair from `TestPeers` and
  `tls_accept_socket`/`tls_connect_socket`, the two sides in two tasks
  of one program (non-blocking), or the Oberon side and a C peer
  thread (blocking; Phase 4).
- TCP (Phase 5 on): posockets, installed, as a test-only dependency:
  the makefile passes its library path to the tests that need it, and
  skips them, saying so, when it isn't installed. Done in Phase 5:
  `POSOCKETS` (default `POCLIBDIR`) is where to look, and the tests in
  `TCPTESTS` are built and run only if its `posockets.library`
  manifest says `poc <version>` of the poc in use, since poc refuses a
  library another poc built; a mismatch is a skip, not a build failure.
- Interoperability: `openssl s_client`/`s_server` against the binding,
  OpenBSD's `nc` against it, and gmni (`/usr/local/sw/src/lang/C/gmni`,
  built into `build/`) against the example server, if it builds here.
  These need a listening port on `127.0.0.1`, port 0.
- OpenBSD's `nc` is Fedora's `netcat` package (not installed on
  2026-11-15; `sudo dnf install netcat`). It is built on the same
  libtls, so it is a second peer that isn't OpenSSL's own code:
  `nc -c` connects with TLS, `nc -l -c -C <cert> -K <key>` listens, and
  `-R <ca>`, `-H <hash>` (pin a fingerprint), `-T noverify`, and
  `-e <name>` (SNI) cover what the tests need. It is optional: Fedora's
  `nmap-ncat` also provides `/usr/bin/nc` through alternatives, and it is
  OpenSSL's, not libtls's, so the makefile finds OpenBSD's `nc` by
  checking that the binary links `libtls.so` (`ldd`), not by its name,
  and a test that needs it prints `skip - <label>` when it is absent,
  as pofltk's `Check.Skip` does. The flags above are to be confirmed
  against its `nc(1)` once installed.
- `make valgrind`: every test, with `poc-gc.supp` and whatever OpenSSL
  suppressions Phase 0 shows are needed, plus the still-reachable check
  by allocator.
- Lessons from posockets' tests (its report to this project,
  2026-11-15), to be re-checked here when a test depends on them:
  - memcheck can't follow poc's coroutines and reports thousands of
    false errors, so tests that use `Tasks` run under
    `valgrind --tool=none --track-fds=yes` (posockets' `TASKTESTS`).
    The memory checks then come only from tests without tasks.
  - `Tasks` keeps a self-pipe of two descriptors open until exit:
    call `Tasks.WakeDescriptor()` before counting descriptors, and
    allow for both in the leak check.
  - Loopback buffers are big enough that 300 KB never blocked a
    write, so a test meant to make the `WANT_*` loops wait asks for
    small `SO_SNDBUF`/`SO_RCVBUF` (posockets' `TestHelp.SmallBuffers`
    uses 4096), and is checked once with `strace` to show it waits.
  - On Linux, a connect times out (hangs, rather than being refused)
    when it goes to a loopback listener with backlog 0 whose one queue
    slot is already taken.
  - posockets writes with `MSG_NOSIGNAL`, but libtls's writes don't,
    so a TLS server still calls `Sockets.IgnoreBrokenPipe`.
  - `Sockets.Shutdown(s, shutBoth)` from another task wakes a task
    waiting in `AwaitReadable` on that socket with end of stream.
    That gives Phase 6 a way to cut off a TLS wait apart from a
    deadline.

## Roadmap

### Phase 0: spike and confirmations [done]

Started and finished 2026-11-15. Throwaway programs under `/usr/local/sw/tmp`;
results go into AGENTS.md, "Confirmed facts", and the sections above.

1. ~~poc links with `-ltls` and calls `tls_init`, `tls_config_new`,
   `tls_server`, `tls_config_set_keypair_file`, `tls_config_error`,
   `tls_free`, `tls_config_free`; valgrind clean.~~ Done 2026-11-15,
   poc 0.12.0.
2. ~~A full handshake and one exchange over a `socketpair`, in C first
   (the reference) and then from Oberon, blocking, with a self-signed
   server certificate and `tls_config_insecure_noverifycert` on the
   client.~~ Done 2026-11-15 with poc 0.13.0 (the checkout's): in C
   with a forked client, then from Oberon both blocking (forked client)
   and non-blocking (server and client as two `Tasks` over a
   posockets `Pair`, six waits). TLS 1.3 both ways; SNI chose the
   second key pair for `other.example`. Blocking calls still return
   `WANT_*` (I/O).
3. ~~Lifetimes.~~ Done: configs are reference-counted; the server
   context must outlive its connections' handshakes; neither
   `tls_close` nor `tls_free` closes a given descriptor; error strings
   last until the next failing call on the object (Handles and
   lifetime).
4. ~~Client certificates.~~ Done: with `verify_client_optional` and
   `insecure_noverifycert`, a self-signed client certificate is
   accepted, an expired one (notAfter 2020-02-01) too, and none is
   fine (`tls_peer_cert_provided` 0). `tls_peer_cert_hash` gives
   `SHA256:` and 64 lowercase hex digits, the same digits as
   `openssl x509 -fingerprint -sha256`. Without
   `insecure_noverifycert`, a self-signed client certificate fails the
   handshake ("certificate verify failed"; the client sees "tlsv1
   alert unknown ca"), so a Gemini server always sets both.
5. ~~Non-blocking.~~ Done, both ends non-blocking in one process: the
   handshake gave `WANT_POLLIN` on both sides for three rounds; a read
   with nothing to read gave `WANT_POLLIN`; a 64 KB write into a 4 KB
   `SO_SNDBUF` gave `WANT_POLLOUT` having written nothing, and the same
   call retried after the client drained completed all 65536 bytes;
   both closes returned 0 at once.
6. ~~`SIGPIPE`.~~ Done: it kills the process; ignored, the write fails
   with `EPIPE` (I/O).
7. ~~What OpenSSL leaves at exit.~~ Done, under valgrind: nothing lost
   and no errors, but `tls_init` alone leaves 431,784 bytes in 6,757
   blocks still reachable (OpenSSL's initialisation and its cache of
   fetched algorithms), the same after 1, 10 or 100 configured server
   contexts, and an explicit `OPENSSL_cleanup()` frees none of it.
   After handshakes it is 502,518 bytes, the same after 1, 10 or 50.
   It is fixed process-wide state, not a per-object leak, so Phase 1's
   still-reachable check suppresses blocks allocated under
   `libcrypto`/`libssl` (by object, `match-leak-kinds: reachable`),
   and a test that makes many contexts checks that the figure doesn't
   grow.
8. ~~Which `*_mem` setters copy their buffer.~~ Done, from the source:
   all of them (Handles and lifetime).

Also found: LibreTLS defines `TLS_PROTOCOL_TLSv1_0`, `_1_1` and `_1_2`
all as `1 << 3` (`/usr/include/tls.h`), so it offers only TLS 1.2 and
1.3; Phase 3's `SetProtocols` takes a string through
`tls_config_parse_protocols` and never names the constants. A poc
`SYSTEM.INT64` result is not assignable to `LONGINT` even under `-OC`;
`SYSTEM.VAL(LONGINT, ...)` converts it (as in posockets).
LibreTLS 3.8.1's source is in `/usr/local/sw/src/lang/C/libretls`.

### Phase 1: project skeleton [done]

`GNUmakefile` adapted from polibfyaml's (library `polibtls`, `LIBMODS`,
`TESTS`, `HALTTESTS`, `valgrind`, `install`/`uninstall`, certificates
in `build/certs`), `.gitignore` (`build/`), `.gitattributes`,
`test/Check.Mod`, `test/poc-gc.supp`, `test/vg-reachable.sh`, a
`LICENSE` (BSD 3-Clause, as Peaseblossom and polibfyaml have), and a
stub `README.md`.

Done 2026-11-15, with poc 0.13.0 from the checkout:

- The makefile follows posockets' (itself from polibfyaml's), with
  `TASKTESTS`, `VALGRIND_TASKS` and `test/vg-fds.sh` already in place
  for Phase 6, and libtls's `pkg-config` flags recorded in the library.
- `test/make-certs.sh` makes the pairs "Testing" lists, ECDSA P-256
  and RSA 2048 each, and checks that the CA verifies its server and
  that the expired pair has expired. openssl 3's `req -x509` puts its
  configuration's CA extensions on every certificate, so each leaf is
  given `basicConstraints=critical,CA:FALSE`; `req -x509 -CA` signs a
  leaf in one step.
- The library is a stub: `TlsThin` binds `tls_init` and `TLS_API`
  (from `TlsThin.c`, proving the C part is built in), and `Tls`'s body
  calls `tls_init`, halting with 90 if it fails. `test/TestInit`
  checks both.
- OpenSSL's global state is allowed in `vg-reachable.sh` by stack, not
  by object: every still-reachable record after `tls_init` (431,784
  bytes, some 800 records) has `tls_init` in its stack, given
  valgrind's `--num-callers=60` (the default 12 cuts it off). Matching
  by object wouldn't work here anyway: with debuginfo installed,
  valgrind names source files, not `libcrypto.so`. libtls's own default
  config, made by `tls_init`, is allowed with it. A program that leaks
  a `tls_config` on purpose fails the check.
- The user confirmed the BSD 3-Clause license on 2026-11-15.

### Phase 2: thin layer [done]

`TlsThin` and `TlsThin.c`: the functions the thick layer will call in
Phases 3 to 7, each checked with `nm -D`, and the constants. `TestThin`
calls each with good and bad arguments.

Done 2026-11-15. `TlsThin` binds 38 libtls functions, wraps each, and
names configs and contexts as `Config` and `Context`
(`SYSTEM.ADDRESS`); `TlsThin.c` gives the `#define` values through one
`constant(which)`, read once into read-only variables. `TestThin`
covers the config errors, a server config with two key pairs and
optional client certificates, a client config with a CA file and TLS
1.3 only, wrong-kind errors (`tls_accept_socket` on a client), three
handshakes over a socket pair (verified with a client certificate;
SNI; no server name, by the `_fds` calls) with the peer-certificate
and connection queries, and a write to a gone peer. Found:

- **libtls zeroes `errno`** on leaving its I/O calls; see "Errors".
  `errno` isn't bound.
- **A `VAR` parameter is an out pointer** to a `["C"]` procedure:
  `VAR cctx: SYSTEM.ADDRESS` for `tls_accept_socket`'s `struct tls **`,
  `VAR protocols: SYSTEM.INT32` for `tls_config_parse_protocols`'s
  `uint32_t *`, so nothing needs C.
- **Every string argument is copied or only read during the call**
  (LibreTLS source): the key pair and CA file setters load the file at
  once, `tls_config_set_ciphers` keeps a copy, and `tls_connect_*`
  `strdup`s the server name. So a value `ARRAY OF CHAR`, copied into
  the wrapper's frame, is safe to pass. An empty server name is passed
  as `NULL`.
- **SNI picks the added key pair**: with `self` set and `other` added,
  a client asking for other.example gets `other`'s certificate.
- **Non-blocking handshakes over a socket pair finish in one program
  without `Tasks`**, each side called in turn until neither wants to
  poll, so memcheck can check these tests.
- **OpenSSL fills caches lazily after `tls_init`**: 73,303 bytes in 149
  records after `TestThin`'s handshakes (fetched algorithms, key
  decoders, and the thread's error queue), the same after four times as
  many connections. `test/vg-reachable.sh` allows them by the OpenSSL
  function in their stacks; a connection context left unfreed is still
  caught. Phase 0's "about 70 KB more after handshakes" was this.

### Phase 3: configuration [done]

`Tls.Config`: `NewConfig`, `SetKeypairFile`, `AddKeypairFile` (SNI),
`SetCaFile`, `SetProtocols` (from a string, through
`tls_config_parse_protocols`), `SetCiphers`, `VerifyClientOptional`,
`InsecureNoVerifyCert`/`Name`/`Time`, `Close`, ~~`ErrorText`~~. Tests:
missing and malformed files, a key that doesn't match its certificate.

Done 2026-11-15. `Config` is an object with a read-only `error`
field in place of `ErrorText`: the `Error` (kind `config` and libtls's
text, copied) of its last call that can fail, `NIL` if that call
succeeded. The options with no result leave it alone. `TestConfig`
checks every setter with good and bad files and strings, and that a
config never closed is freed by its finalizer (without the finalizer,
`vg-reachable.sh` flags seven records from `tls_config_new`);
`HaltConfigClosed` checks halt 91. `NewConfig` halts with 96 if libtls
can't allocate (see "Halt codes"). Found (C probe and LibreTLS 3.8.1
source):

- **The key pair setters check only the certificate.** They read both
  files at once, but parse only the certificate (for its public key's
  hash): a missing file, a certificate that isn't PEM, or a key given
  as the certificate fails there ("failed to open certificate file",
  "failed to open key file", "failed to load certificate"). A
  malformed key, or one not matching its certificate, passes, and
  `tls_configure` fails ("failed to read private key", "failed to load
  private key", "private/public key mismatch"). So that test moves to
  Phase 4.
- **A CA file is parsed only when verifying a peer**: one that isn't
  PEM passes `tls_config_set_ca_file`. Phase 4 tests what the
  handshake says.
- **Every config setter that fails sets text**, apart from an
  out-of-memory `strdup`; `tls_config_set_ciphers` says "no ciphers
  for '...'". `tls_config_parse_protocols` takes no config, so
  `SetProtocols` gives its own text, "invalid protocols".
- **`SetCiphers` affects TLS 1.2 only**: LibreTLS calls only
  `SSL_CTX_set_cipher_list`, never `SSL_CTX_set_ciphersuites`.

### Phase 4: contexts and blocking I/O [done]

`Tls.Context` (`NewServer`, `NewClient`, `Configure`), and
`Tls.Connection` (`AcceptSocket`, `ConnectSocket`, `Handshake`, `Read`,
`Write`, `WriteAll`, `Close`), over blocking descriptors from
`TestPeers`' socket pair. Two tasks in one program can't both block in libtls
(a blocking call stops every task), so the peer runs in another
process: a child `fork`ed by a test helper in C, or `openssl s_client`.
Decide which in the phase.

Done 2026-11-15 (LibreTLS 3.8.1, OpenSSL 3.5.8, poc 0.13.0 from the
checkout); `TestBlocking` and five halt tests, clean under valgrind.

- **The peer is a thread, not a process** (neither of the above): a
  C TLS peer in `TestPeers.c` (`StartClient`, `StartServer`, `Join`),
  blocking in a thread of its own. One process keeps one valgrind log
  and leak report, and needs no `openssl` at run time. The thread
  never touches the Oberon heap: its strings and data are copied into
  C memory first, since the collector scans only the main thread's
  stack. Each blocking call it makes loops on `WANT_*`. glibc 2.34 on
  has pthreads in libc, so no `-lpthread`.
- **No client `Context`.** A libtls client context is the connection
  itself (`tls_connect_socket` on it), and `tls_reset` frees its
  config and `SSL_CTX`, so a reusable `NewClient` would be a config by
  another name. So `Tls.ConnectSocket(config, fd, servername, VAR
  conn)` makes a client context, configures it and connects; on
  failure `conn` is closed and `conn.error` says why. The server side
  is `NewServer`, `Configure` and `Context.AcceptSocket(fd, VAR
  conn)`. Halt 92 is left unused.
- **Error kinds**: `handshake` for `Configure`, `AcceptSocket`,
  `ConnectSocket` and `Handshake`; `io` for `Read`, `Write` and
  `Close`; `closed` for `Read` at end of data (Errors). A `Read` or
  `Write` that does the handshake reports its failure as `io`.
- **Where each failure shows**: a malformed or mismatched server key at
  `Configure` ("failed to read private key", "failed to load private
  key", "private/public key mismatch"); a CA file that isn't PEM at
  `ConnectSocket` ("ssl verify memory setup failure", from
  `tls_configure_ssl_verify` in `tls_connect_common`); a server signed
  by another CA at `Handshake` ("certificate verification failed:
  unable to get local issuer certificate"); a server not of the name
  asked for at `Handshake` ("name \`other.example' not present in
  server certificate"), after which the server's side of the handshake
  has succeeded; accepting on an unconfigured context at
  `AcceptSocket` ("ssl failure").
- **`Close` after a failure fails too**: after a failed verification
  OpenSSL is still in the handshake, and after a read that met an end
  without close_notify the connection is broken, so `tls_close` says
  "shutdown failed: ...". `Close` returns `FALSE` with kind `io` and
  frees the connection all the same; a second `Close` does nothing and
  returns `TRUE`. A gone peer is no reason for a server to do anything
  but close.
- `Read` and `Write` with `len` 0 do nothing and succeed, without
  calling libtls (whose `tls_read` would return 0, end of data).
  `pos`/`len` outside the buffer halt 93; a negative descriptor (or
  one beyond `int`) halts 95.
- A 200,000-byte `WriteAll` from the server, more than the socket
  pair buffers, arrives whole.

### Phase 5: TCP, with posockets [done]

Needs posockets' first version (its own repo and plan, from "Sockets:
posockets" above), which is the work to do between Phases 4 and 5.
Then: the makefile's test-only use of it, and tests of a TLS server on
`127.0.0.1` and `::1`, port 0, with the binding's client and with
`openssl s_client`. Anything polibtls needed from posockets that it
lacked goes into posockets' PLAN.md, not here.

Done 2026-11-15 (LibreTLS 3.8.1, OpenSSL 3.5.8, poc 0.13.0 from the
checkout, posockets a20f33f); `TestTcp`, clean under valgrind, and
skipped, saying so, without a posockets this poc built (Testing).

- For each of `127.0.0.1` and `::1`: `Sockets.Listen` on port 0 gives
  one listener, and `LocalAddress` the kernel's port. Each case makes
  a blocking `Sockets.Connect` to it, which the kernel completes into
  the listener's queue, then `Accept`s, so one thread holds both ends
  before any TLS starts; `Accept`'s peer address is the host
  connected from.
- Over those connections: an Oberon server (`server-ec`, `server-rsa`)
  with a C libtls client from `TestPeers`; an Oberon client with
  `ConnectSocket`, verifying a C libtls server; and an Oberon server
  with `openssl s_client` in a child process, sending a Gemini request
  line and reading the response. Every client verifies the server
  against `ca-K` by the address it connected to, which libtls and
  s_client (`-verify_ip`) check against the certificate's IP names.
  s_client's `-quiet` implies `-ign_eof`: it sends its input, then
  reads until the server's close_notify, and exits 0.
- With the other kind's CA, s_client (`-verify_return_error`) rejects
  the server ("unable to get local issuer certificate") and exits
  nonzero, and the server's `Handshake` fails, kind `handshake`:
  "handshake failed: error:0A000418:SSL routines::tlsv1 alert unknown
  ca" (TLS 1.3, so the server learns of it in its handshake).
- s_client is started before the blocking `Accept`, and its input
  goes through a pipe at once, so nothing waits on it; the test first
  checks that `openssl version` runs, since otherwise `Accept` would
  wait for ever.
- Nothing was missing from posockets: `Listen`, `LocalAddress`,
  `Connect`, `Accept`, `Close` and `IgnoreBrokenPipe` were all it
  needed, with `s.fd` handed to `Tls`.

### Phase 6: non-blocking I/O with Tasks [done]

The `WANT_*` loops; the accept loop as a task (posockets' accept); many concurrent clients
in one test (some slow, one that never finishes its handshake) with a
deadline per connection, on `Tasks`' timed wait (Tasks, "Deadlines";
`Tasks.After` can't serve, since a task in `AwaitReadable` can't also
wait on a channel). Measure the stack a handshake
needs. Decide whether this is `TlsTasks` or part of `Tls`.

Done 2026-11-15 (LibreTLS 3.8.1, OpenSSL 3.5.8, poc 0.13.0 installed,
posockets 059b47d); `TestTasks` and `TestTcpTasks`, with the
descriptor check under valgrind (memcheck can't follow coroutines),
and halt tests `HaltBlocking` (97) and `HaltDeadline` (98).

- **A separate `TlsTasks`**, as posockets' `SocketTasks`: `Tls`
  doesn't import `Tasks`, and its calls on a non-blocking descriptor
  return `wouldBlock` with the direction (I/O). `TlsTasks.Handshake`,
  `Read`, `Write`, `WriteAll` and `Close` make the `Tls` call, and on
  `wouldBlock` wait with `AwaitReadableFor`/`AwaitWritableFor` for the
  time the connection has left (without limit when it has no
  deadline), then call again. A call that can finish without waiting
  does, even past the deadline.
- **Without Tasks** (`TestTasks`, "alone"): driven by hand in turns,
  each end's first `Handshake` gives `wouldBlock`, `wantRead`, as does
  a `Read` with nothing sent; repeating the calls finishes the
  handshake, the exchange and both `Close`s.
- **A timeout in the middle of a handshake leaves the connection
  usable**: a server with a 100 ms deadline and a client that stalls
  400 ms in its handshake times out ("handshake timed out"), then with
  a new deadline and another `TlsTasks.Handshake` finishes it and
  serves the request. A timed-out call is simply not made again, as
  libtls allows. A server that gives up instead calls `Discard`, since
  close_notify means nothing in a handshake not finished.
- **Timeouts in reading and writing**: a client that pauses 400 ms
  before its request times the server's `Read` out; one that stops
  reading a 4 MB response times `WriteAll` out part way, `n` saying how
  much was written, then `TlsTasks.Close` gives "close timed out" and
  discards the connection, after which `Close` returns `TRUE`.
- **Many clients** (`TestTasks`): 8 connections over socket pairs at
  once, every second one slow (it starts 100 ms late and sends its
  request a byte at a time, 10 ms apart), one silent, which the server's 500 ms deadline
  cuts off; every other one is served and checked byte for byte.
- **The accept loop as a task** (`TestTcpTasks`, on `127.0.0.1` and
  `::1`): a non-blocking listener, an accepting task looping on
  `SocketTasks.Accept` with a 50 ms deadline so it can see a stop flag,
  and a handler task per connection (`AcceptSocket`, a 500 ms deadline,
  handshake, request line, `20 text/gemini` response, `Close`). Six
  Oberon clients in tasks (`SocketTasks.Connect`, verifying the server
  by address against `ca-ec`), one silent client, cut off, and
  `openssl s_client` in a child process, all served.
- **Stack**: a probe ran one handshake and exchange, with the side
  measured in a task of a given size, the other in 1 MiB, the client
  presenting a certificate: server or client, `self-ec` or `self-rsa`,
  each succeeded in 16 KiB, the least poc gives (smaller is raised to
  it), with its guard page below (a recursion past it in a 16 KiB task
  was SIGSEGV). In a 1 MiB stack, which starts zeroed, the deepest
  nonzero word was 8200 bytes below the top, three pages touched, for
  either side and either key. Every test also passed with
  `stackSize` set to 16 KiB, so verifying a CA chain fits too.
  `TlsTasks.stackSize` is 64 KiB, leaving room for the task's own
  work; only touched pages cost memory.
- `Tls.c` (new) gives whether a descriptor is non-blocking and a
  monotonic clock in ms; their C names avoid libtls's `tls_` prefix.

### Phase 7: certificates and connection info

`PeerCertProvided`, `PeerCertHash`, `PeerCertSubject`/`Issuer`,
`PeerCertNotBefore`/`NotAfter` (seconds since the epoch, `HUGEINT`),
`PeerCertContainsName`, `ConnVersion`, `ConnCipher`,
`ConnServername`. Tests with each client certificate from Phase 1, and
SNI choosing between two server key pairs.

### Phase 8: examples and interoperability

`examples/GeminiHello.Mod`: a server on a given port answering every
request with `20 text/gemini` and a fixed page, recording the client
certificate's fingerprint if any, with TLS close_notify. And
`examples/GeminiFetch.Mod`: a client that sends a URL and prints the
response, pinning the server's fingerprint. Tested against each other,
`openssl s_client`, OpenBSD's `nc` (each way, when installed), and
gmni. They use posockets for listening and connecting, so they are
built only when it is installed. These are the starting point for the
server project, not the server.

### Phase 9: documentation and install

`README.md` as the user's guide (the API, an example, the halt codes,
the stack size for tasks), `make install` checked from a program
outside the repo, and AGENTS.md's status brought up to date.

## Open questions

- ~~Should sockets be polibtls's own module or a separate library?~~
  A separate library, posockets (2026-11-15, with the user): "Sockets:
  posockets".
- Install an `-O2` variant as well as `-OC`?
- ~~`Tasks` integration: a separate module, or in `Tls`?~~ A separate
  module, `TlsTasks` (Phase 6).
- ~~Phase 4's blocking tests: a forked peer, or `openssl s_client`?~~
  Neither: a C peer in a thread (Phase 4).
- Should the binding read and validate Gemini's request line (CRLF,
  1024 bytes, no BOM), or leave that to the server project? Leaning
  towards the server project, with only a bounded `ReadLine` here.
- Certificate generation for users (a self-signed pair on first run is
  what most Gemini servers do): in the server, not the binding, since
  libtls can't make certificates; it would need OpenSSL's API directly.
