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
| `Tls` (+ `Tls.c`) | `Tls.c`: whether a descriptor is non-blocking (`fcntl`). Deadlines (Phase 6) take poDateTime's monotonic clock, `Clocks.Monotonic`, since 2026-11-16 ("poDateTime's clock and StopRequests"). |
| `TlsCerts` | a certificate's hashes and validity from PEM text, in Oberon: SHA-256, base64, a DER walk to the public key and the validity ("The peer's public key" and "A certificate's validity", 2026-11-18). |
| `TlsMake` (+ `TlsMake.c`) | private keys and certificates made through libcrypto, into files: EC P-256 or RSA keys, self-signed or CA-signed certificates ("Making keys and certificates", 2026-11-18). |
| `TlsTasks` | handshake/read/write/close loops that turn `Tls`'s `wouldBlock` into `Tasks.AwaitReadableFor`/`AwaitWritableFor` until the connection's deadline, then make the same call again (Phase 6). |

The library is `polibtls`, holding all of them; it records `-ltls` so a
program passes no flags for it. `Tasks` integration is a separate
module, `TlsTasks`, so a program that never uses `Tasks` doesn't import
it (decided in Phase 6, as posockets' `SocketTasks`).

polibtls needs poDateTime (`~/Repos/Oberon/poDateTime`), installed and
built by the same poc, for its monotonic clock; the library records
`needs podatetime`.

polibtls deals in descriptors only: a descriptor is a `LONGINT`, as
`Tasks.AwaitReadable` takes it, and the caller gets it from posockets,
from `socketpair` in a test, or from anything else that makes one.
polibtls never imports posockets, so a program that has its descriptors
from elsewhere doesn't link it.

### Integer model

`-OC`, as polibfyaml: `INTEGER` 32 bits and `LONGINT` 64, so sizes and
counts in the thick layer are plain `LONGINT` and need no conversion to
`size_t`. The thin layer uses explicit widths only, so it would also be
right under `-O2`. No `-O2` variant is installed, as pofltk installs
one: every program using polibtls so far (pogemini, pogeminilib and
the other po* libraries) is built with `-OC`, so one waits until a
program built with `-O2` needs it (Open questions, 2026-11-19).

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
  `WriteAll` loops over short writes. ~~`ReadLine(c, VAR line, max)`
  reads to CRLF with a limit, for Gemini's request (later, maybe, in
  the server project).~~ Not here: the server reads its request line
  itself (Open questions, 2026-11-19).
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
| 92 | ~~the wrong kind of context (accept on a client, connect on a server, I/O on a server context)~~ unused since Phase 4, when a `Context` became a server's and a client's context its `Connection`, so the types rule it out. From Phase 7: a `Connection`'s info (`PeerCert...`, `Version`, `Cipher`, `Servername`) asked before its handshake is done |
| 93 | a buffer range out of bounds (pos/len outside the array) |
| 94 | a server `Context` closed while a `Connection` accepted from it is still open (libtls reference-counts configs, so a closed `Config` needs no halt; Phase 0) |
| 95 | a negative descriptor given to accept or connect |
| 96 | libtls couldn't allocate a config or context (`tls_config_new`, `tls_server`, `tls_client` returned NULL), as `NEW` halts when out of memory |
| 97 | a connection on a blocking descriptor given to `TlsTasks` (a wait in the kernel would stop every task); checked on each call, so a closed descriptor halts too |
| 98 | a negative time given to `Connection.SetDeadline` |
| 99 | a hash array shorter than `TlsCerts.HashLength` ("The peer's public key") |

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
  input given through a pipe and its output read back; Phase 5), which
  since 2026-11-16 is `test/Child.Mod`'s, through pounix ("pounix for
  the tests' child processes"). It is a few lines each, so the
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
  OpenBSD's `nc` against it, and clients on TLS stacks other than
  OpenSSL against the example server: gemget (Go's crypto/tls) and
  `gnutls-cli` (GnuTLS). These need a listening port on `127.0.0.1`,
  port 0. Done in Phase 8 (`TestGemini`). gmni (BearSSL): ~~possibly
  later, since Fedora has no BearSSL package~~ done 2026-11-19 ("gmni,
  on BearSSL").
- OpenBSD's `nc` is Fedora's `netcat` package (`sudo dnf install
  netcat`; `netcat-1.238-1.fc44` installed 2026-11-15, as
  `/usr/bin/netcat`). It is built on the same
  libtls, so it is a second peer that isn't OpenSSL's own code:
  `nc -c` connects with TLS, `nc -l -c -C <cert> -K <key>` listens, and
  `-R <ca>`, `-H <hash>` (pin a fingerprint), `-T noverify`, and
  `-e <name>` (SNI) cover what the tests need. It is optional: Fedora's
  `nmap-ncat` also provides `/usr/bin/nc` through alternatives, and it is
  OpenSSL's, not libtls's, so the makefile finds OpenBSD's `nc` by
  checking that the binary links `libtls.so` (`ldd`), not by its name,
  and a test that needs it prints `skip - <label>` when it is absent,
  as pofltk's `Check.Skip` does. Confirmed in Phase 8 with nc 1.238
  built from Fedora's source: `-c`, `-l`, `-C`, `-K`, `-R`, `-e`, and
  `-N` and `-v` (`-H` and `-T` not used). `TestGemini` looks for it as
  `$LIBTLS_NC`, `netcat` or `nc`.
- `make valgrind`: every test, with `poc-gc.supp` and whatever OpenSSL
  suppressions Phase 0 shows are needed, plus the still-reachable check
  by allocator.
- Lessons from posockets' tests (its report to this project,
  2026-11-15), to be re-checked here when a test depends on them:
  - ~~memcheck can't follow poc's coroutines and reports thousands of
    false errors, so tests that use `Tasks` run under
    `valgrind --tool=none --track-fds=yes` (posockets' `TASKTESTS`).
    The memory checks then come only from tests without tasks.~~
    No longer so: see "Full memcheck for the task tests".
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

### Phase 7: certificates and connection info [done]

`PeerCertProvided`, `PeerCertHash`, `PeerCertSubject`/`Issuer`,
`PeerCertNotBefore`/`NotAfter` (seconds since the epoch, `HUGEINT`),
`PeerCertContainsName`, `ConnVersion`, `ConnCipher`,
`ConnServername`. Tests with each client certificate from Phase 1, and
SNI choosing between two server key pairs.

Done 2026-11-15 (LibreTLS 3.8.1, OpenSSL 3.5.8, poc 0.13.0);
`TestInfo`, clean under valgrind, and `HaltInfoEarly` (92).

- **Methods of `Connection`**: `PeerCertProvided`, `PeerCertHash`,
  `PeerCertSubject`, `PeerCertIssuer`, `PeerCertNotBefore`,
  `PeerCertNotAfter` (`HUGEINT`), `PeerCertContainsName`, and
  `Version`, `Cipher`, `Servername` (the `Conn` prefix dropped, as
  methods of a connection). Strings are `Tls.String` copies, `NIL` where
  libtls has none (no certificate; no SNI); the times are -1 without a
  certificate. libtls fills them (`conninfo`) at the end of the
  handshake and frees them only in `tls_free` (LibreTLS
  tls_conninfo.c, tls.c), so they are read live, and copied.
- **Only after the handshake** (`tls_conn_version(3)`): asking before
  halts (92), after `Close` (91). libtls makes the handshake inside the
  first `tls_read` or `tls_write` if `tls_handshake` wasn't called, so a
  `Connection` counts it done after a successful `Handshake`, a `Read`
  that got data or the end of it, or a `Write` that wrote; tested with
  the handshake made in `Read` and `Write` alone.
- **Each certificate as openssl says** (`test/cert-info.sh`, by
  `TestPeers.Spawn`): for client1, client2, self and expired, EC and
  RSA, the server's `PeerCertHash` is `SHA256:` and the lowercase hex
  SHA-256 of the DER, the subject and issuer are
  `X509_NAME_oneline`'s form (`/CN=polibtls test client1`, as openssl's
  `-nameopt compat`), and the times are openssl's dates in seconds. An
  expired certificate (to 2020-02-01, 1580515200) is accepted with
  `VerifyClientOptional` and `InsecureNoVerifyCert`; the server checks
  `PeerCertNotAfter` itself if it cares. Each check was seen to fail
  with a wrong expectation.
- **SNI**: a server with `SetKeypairFile(self-K)` and
  `AddKeypairFile(other-K)` presents other-K to a client asking for
  `other.example` (which then verifies that name), and self-K, the
  first, for `localhost`, an unknown name, an IP address or none. The
  server's `Servername` is the name asked for, and `NIL` for an IP
  address or none: libtls's client sends no SNI for an address. The
  client's `Servername` is the name it gave, `NIL` for `""`.
- **`PeerCertContainsName`**: the server's certificate names
  `localhost`, `127.0.0.1` and `::1`, not `127.0.0.2` or `""`; a client
  certificate without subject alternative names matches its common
  name. libtls looks at the common name only when there are no
  alternative names (RFC 6125, 6.4.4; tls_verify.c).
- **Version and Cipher** agree on both ends: `TLSv1.3` with
  `TLS_AES_256_GCM_SHA384` by default, `TLSv1.2` with
  `ECDHE-ECDSA-AES256-GCM-SHA384` for a client limited to `tlsv1.2`,
  which still presents its certificate.

### Phase 8: examples and interoperability [done]

`examples/GeminiHello.Mod`: a server on a given port answering every
request with `20 text/gemini` and a fixed page, recording the client
certificate's fingerprint if any, with TLS close_notify. And
`examples/GeminiFetch.Mod`: a client that sends a URL and prints the
response, pinning the server's fingerprint. Tested against each other,
`openssl s_client`, OpenBSD's `nc` (each way, when installed), gemget
and `gnutls-cli`. They use posockets for listening and connecting, so they are
built only when it is installed. These are the starting point for the
server project, not the server.

Done 2026-11-15 (LibreTLS 3.8.1, OpenSSL 3.5.8, poc 0.13.0, posockets
059b47d); `TestGemini`, clean under valgrind, and each
example checked under valgrind by hand.

- **`examples/GeminiHello.Mod`**: `GeminiHello [-n count] [-host host]
  port cert key [cert key ...]`. It listens on every local address
  (`Sockets.Listen`, both families) or on host, port 0 giving one the
  kernel chooses, and prints `port <n>` first, so a test learns it. The
  first pair is the default, each further pair for SNI. An accept task
  per listener (`SocketTasks.Accept`, waking every 200 ms to see
  whether to stop) and a task per connection (`TlsTasks`, stack
  `TlsTasks.stackSize`, a 10 s deadline from handshake to
  close_notify); a request line is read up to CR LF within 1026
  bytes. It answers `20 text/gemini` with a page naming the URL and
  the client certificate's fingerprint, or `59 bad request` for
  anything not `gemini://`, and logs a line per connection: the
  client's address, status, URL and fingerprint (`-` for none), or
  `failed:` and why. With `-n` it serves that many connections, joins
  their tasks, and exits; its descriptors are all closed at exit
  (valgrind `--tool=none --track-fds`).
- **`examples/GeminiFetch.Mod`**: `GeminiFetch [-pin hash | -ca file]
  [-cert file -key file] url`, blocking. It trusts the server by
  pinned fingerprint (checked before the request is sent; CA, name and
  time not checked, as a trust-on-first-use client), by CA (and the
  URL's host, IPv6 in brackets), or not at all, printing the
  fingerprint for next time. It prints the response raw, and accepts it
  only if it ended with close_notify (kind `closed`); exit 0 for a 2x
  status, 1 otherwise, 2 for usage. Clean under memcheck, with
  `vg-reachable.sh`, on success, a wrong pin and a refused connection.
- **`test/TestGemini.Mod`** runs both as child processes
  (`TestPeers.Spawn`, and `ReadLine` for a server's port, `Kill` if it
  doesn't finish): GeminiFetch by CA on `127.0.0.1` and `[::1]`, with
  a client certificate, by pin, and with a wrong pin (exit 1, the
  server's log shows the connection failing, no request); `openssl
  s_client` sending a non-Gemini URL (59); OpenBSD `nc` with a client
  certificate; gemget, with and without a client certificate; and
  `gnutls-cli` verifying the server by CA, with a client certificate
  (each skipped, saying so, when not found: `$GEMGET` or `gemget`,
  `$GNUTLS_CLI` or `gnutls-cli`); then GeminiFetch against servers that never send
  close_notify (below), which it must refuse after printing what came.
  The server's log must name each request and certificate. Every
  server runs under `timeout(1)`. It imports no module of polibtls,
  so the tests now link libtls themselves (`TESTLINK`), for
  `TestPeers.c`.
- **OpenBSD `nc` 1.238** (first built from Fedora's netcat source in a
  session directory; then `netcat-1.238-1.fc44`, installed, passed the
  same checks as `/usr/bin/netcat`): as a
  client, `nc -c -R ca -e name -C cert -K key host port` sends its
  input, reads until the server's close_notify and exits 0, and
  GeminiHello logs the fingerprint of its certificate. As a server
  (`nc -c -l -C cert -K key`, `-v` printing `Listening on <host>
  <port>`, port 0 allowed) it can't end a Gemini response: without
  `-N` it waits for the network input to end, so it and a client
  waiting for close_notify wait on each other; with `-N` it ends with
  `shutdown(SHUT_WR)` and no `tls_close`, which GeminiFetch rejects as
  truncated ("unexpected eof while reading"). `TestGemini` finds a
  libtls `nc` as `$LIBTLS_NC`, `netcat` or `nc`, by `ldd`, and skips
  its checks without one.
- **`openssl s_server` 3.5.8 never sends close_notify**: at the end of
  its input (or on `q`) it closes the descriptor before `SSL_shutdown`,
  whose write then fails with `EBADF` (strace). So GeminiFetch rejects
  its responses as truncated, as it should. It also sends its input as
  it comes, so a response sent before the request arrives leaves the
  request unread, and the close resets the connection; `TestGemini`
  delays the response a second. `-accept 127.0.0.1:0` prints `ACCEPT
  127.0.0.1:<port>` (not with `-quiet`).
- **A lingering close** (`SocketTasks.LingeringClose`, from posockets). `gnutls-cli` sends its
  own close_notify as soon as its input ends, right after the request.
  The server never read it, so closing the socket with it unread made
  the kernel send a reset, and `gnutls-cli`, not yet done reading,
  lost the response ("Error in the pull function", ECONNRESET). So
  after its close_notify GeminiHello shuts down its sending side and
  reads, discarding, until the client closes or 2 s pass, and only
  then closes. A server that may get data after its last read needs
  this. At first GeminiHello did it itself; posockets already had it,
  as `SocketTasks.LingeringClose(s, ms)` (2026-11-16).
- **gemget 1.9.0** (Go's crypto/tls, `go install`): `gemget -o -
  [--header] [--cert f --key f] url`. It checks no server certificate,
  accepts a response without close_notify (so it isn't used for the
  truncation checks), and exits 1 for a non-2x status.
- **`gnutls-cli` 3.8.13** (`gnutls-utils`): `gnutls-cli
  --logfile=/dev/null --x509cafile ca [--x509certfile c --x509keyfile
  k] -p port host`, the request on standard input. It verifies the
  server by CA, by IP address too, and prints the response, exiting 0,
  once GeminiHello drains (above). `gnutls-serv` can't stand as a
  Gemini server: its echo mode never closes, `--http` waits for a
  blank line after the request, and with `-p 0` it prints `port 0`,
  not the port it got.
- ~~**gmni: possibly later.** It needs BearSSL, which Fedora doesn't
  package; it would have to be built from source.~~ Done 2026-11-19
  ("gmni, on BearSSL").

### Phase 9: documentation and install [done]

`README.md` as the user's guide (the API, an example, the halt codes,
the stack size for tasks), `make install` checked from a program
outside the repo, and AGENTS.md's status brought up to date.

Done 2026-11-16:

- **README.md** is the user's guide: building and installing, the
  three modules, an example (a Gemini server with one page, a task per
  connection), what a user must know (errors, close_notify as the end,
  who closes descriptors, closing order, lingering close, client
  certificates, non-blocking I/O and `TlsTasks.stackSize`, connection
  info after the handshake, valgrind), and the halt codes.
- **The reference** in `doc/`, made by `make doc` from each module's
  exported declarations and their comments, by posockets'
  `doc/mkref.py`, extended so that a section comment `(* --- Title
  ---` may carry an introduction (`Tls`'s "Connection info", whose
  halts are said there). The module taglines of `Tls` and `TlsThin`
  now say what they are for a user, not where PLAN.md describes them.
- **`make install` checked outside the repo**: installed into a
  scratch `POCLIBDIR`, the README's example built there with
  `poc -OC -library-path <it> -library-path ~/.local/lib/poc`, with
  no link flags (the library records `-ltls`), and ran: GeminiFetch
  with a client certificate, `gnutls-cli`, gemget and OpenBSD's `nc`
  each got the page, and the fingerprints were the certificates'.
  The main module's body accepts outside any task and starts a task
  per connection, which works. `make uninstall` then left nothing.
- **GeminiHello uses posockets' `SocketTasks.LingeringClose`** in
  place of its own drain (Phase 8).

### Phase 10: the BSDs [done]

Wanted since 2026-11-16, for pogemini (Open questions).

**Spike on OpenBSD, 2026-11-16**: jherek, OpenBSD 7.9 amd64, poc
0.13.0, its own libtls (`/usr/lib/libtls.so.33.2`, LibreSSL 4.3.0);
the working tree copied there, `gmake test`; posockets wasn't
installed there, so the TCP tests were skipped. Findings:

- **The library builds and links unchanged**, given `TLS_LIBS=-ltls`:
  OpenBSD has no `libtls.pc`, so `pkg-config libtls` fails.
- **The tests need `-lpthread`** (`TestPeers.c`'s threads; glibc has
  them in libc), and so do `HaltInfoEarly` and any halt test that
  imports TestPeers, whose rule had no `TESTLINK`.
- **`test/make-certs.sh` needs OpenSSL 3**: LibreSSL's `openssl` has no
  `genpkey -quiet`, `req -CA`/`-CAkey`, or `req -not_before`/
  `-not_after`. For the spike the certificates were made on Linux and
  copied.
- **`test/cert-info.sh` is Linux-only** (`sha256sum`, `date -d`), and
  LibreSSL prints `subject= /CN=...`, with a space. With `openssl dgst
  -sha256`, `date -j -u -f "%b %e %H:%M:%S %Y GMT"` and the space
  stripped, TestInfo passed in full: hashes, subjects, issuers,
  validity times, SNI, versions, ciphers and a handshake made inside
  Read and Write all match what libtls on OpenSSL gave.
- **TestInit, TestThin, TestConfig, TestTasks and every halt test
  passed unchanged**: deadlines, timeouts mid-handshake, WANT_* on
  non-blocking descriptors, the error texts they check.
- **An end without close_notify is not an error from Read**: OpenBSD's
  libtls makes `tls_read` return 0 for it, the same as for
  close_notify, so `Read` reports kind `closed`, "connection closed by
  peer", in both cases; only the following `tls_close` fails, kind `io`,
  "EOF without close notify". On OpenSSL 3 `Read` itself fails
  ("unexpected eof while reading") and `Close` fails too ("shutdown
  failed"). So the one test that holds on both is: **a peer's data is
  complete only if `Read` reports `closed` and then `Close`
  succeeds.** GeminiFetch already requires both. `Tls.closed`'s comment
  ("the peer sent close_notify"), README's "Things to know" and
  TestBlocking's two abrupt checks must say this; whether Read should
  itself confirm close_notify (by closing) is a design question for
  the port.

**Decided, with the user, 2026-11-16: Read decides.** At the end of
data (`tls_read` returning 0), `Read` calls `tls_close` itself, which
sends our close_notify and fails if the peer sent none, and reports
kind `closed` only if it succeeds, else kind `io` with libtls's text.
So `closed` means close_notify on every system, and a caller (a Gemini
client) needs no second test. The handle isn't freed, so connection
info can still be read; later `Read`s give the same result, and
`Close` sends nothing more, frees, and returns that same answer.
`tls_close` giving WANT_* on a non-blocking descriptor makes `Read`
give `wouldBlock` and retry the close when called again, so
`TlsTasks.Read` needs no change. On Linux nothing visible changes
(`tls_read` there fails first on an end without close_notify), and
`make test` and `make valgrind` pass; TestBlocking's abrupt checks
accept either library's text, and it checks that a second `Read` after
close_notify gives `closed` again.
Checked on jherek the same day: TestBlocking (abrupt `Read` now fails,
kind `io`, "EOF without close notify") and TestTasks pass.

**libtls on FreeBSD and NetBSD, 2026-11-16**: neither has one in base
or installed (alerik, FreeBSD 15.1, OpenSSL 3.5.6 in base; artos,
NetBSD 11.0, OpenSSL 3.5.7 in base). Both package LibreTLS 3.8.1, the
version Fedora has, on the base OpenSSL with no other dependency:
FreeBSD's `security/libretls`, NetBSD pkgsrc's `security/libretls`
(`tls.h`, `libtls.so.28` and `libtls.pc` under `/usr/pkg`). Each also
packages LibreSSL (FreeBSD 4.3.3, with `libressl-libtls`; NetBSD
4.1.0), which would be a second libcrypto beside the base one.
LibreTLS is the choice: the same libtls and OpenSSL 3 as on Linux, so
OpenBSD stays the one system whose libtls behaves differently.

Keep libtls rather than switching to OpenSSL or LibreSSL.

**The port, 2026-11-16 [done].** `gmake test` passes on FreeBSD 15.1
amd64 (alerik: LibreTLS 3.8.1 package, OpenSSL 3.5.6), NetBSD 11.0
amd64 and i386 (artos, yishana: pkgsrc LibreTLS 3.8.1, OpenSSL 3.5.7)
and OpenBSD 7.9 amd64 and i386 (jherek, cymoril: base libtls, LibreSSL
4.3.0), all with poc 0.13.0 and posockets 059b47d installed into a
directory of the run, so the TCP tests and examples ran too; and still
on Linux, with `make valgrind`. Skipped there, saying so: gemget
everywhere, `gnutls-cli` except on alerik and cymoril, OpenBSD's `nc`
except on OpenBSD (where base `nc` links libtls), and `openssl` as a
peer on OpenBSD. What changed:

- **GNUmakefile**: libtls's flags from `pkg-config libtls`, and `-ltls`
  when there is no `libtls.pc` (OpenBSD); FreeBSD's and NetBSD's give
  `-I`/`-L` (and NetBSD's an `-R`) under `/usr/local` or `/usr/pkg`,
  recorded in the library as before, so a program still passes none.
  The tests link `-lpthread`, and halt tests use `TESTLINK` and
  `-import-path test`, since some import TestPeers.
- **i386**: `ssize_t` is 32 bits, and poc won't pass a `LONGINT`
  length as a 32-bit `SYSTEM.ADDRESS`, so `tls_read` and `tls_write`
  go through `TlsThin.c` taking and returning `int64_t`, as do
  `tls_peer_cert_notbefore`/`notafter` (`time_t`). `TlsThin.Read` and
  `Write` take `buflen: SYSTEM.INT64`. Tls is unchanged.
- **`test/make-certs.sh`** runs on OpenSSL 3 and LibreSSL alike: its
  own configuration file, `x509 -req` to sign the server's certificate,
  `ca -startdate/-enddate` for the expired one, no `genpkey -quiet`,
  and `-sha256` named everywhere: **LibreSSL's `x509 -req` signs with
  SHA-1 by default**, and GnuTLS (`gnutls-cli` on cymoril) rejected the
  server's certificate as insecure. The script now checks every
  certificate is signed with SHA-256.
- **`test/cert-info.sh`**: the hash from `openssl x509 -fingerprint
  -sha256`, the times converted by awk, LibreSSL's `subject= ` space
  stripped; the same output as before on Linux.
- **`openssl` as a peer only if it is OpenSSL's** (`TestPeers.Openssl`,
  from `openssl version`): LibreSSL's `s_client` has no `-verify_ip`
  and exits at once, which left TestTcp's blocking `Accept` waiting for
  ever; its `s_server` lacks `-naccept` and `-accept host:port`. Those
  checks print `skip - ...` (`Check.Skip`) on OpenBSD.
- **Finding OpenBSD's `nc`**: `ldd | grep -q` killed `ldd` with SIGPIPE,
  and OpenBSD's shell put "signal 13" in the captured path; grep now
  reads everything.
- **A socket pair on NetBSD holds 8 KiB** (send and receive buffers of
  8192, `getsockopt`), less than one TLS record, so with a peer that
  reads nothing OpenSSL never finishes a record, and TestTasks' write
  timeout found 0 bytes written. `TestPeers.Pair` raises each end's
  send buffer to 64 KiB, FreeBSD's default, never lowering it
  (Linux's is larger). TCP buffers are much larger, so this is the
  tests' concern only.

### poDateTime's clock and StopRequests [done]

Peaseblossom's PLAN.md, "Ongoing library enhancements" 7, step 3
(2026-11-16, poc 0.14.0): the programs built on poc take poDateTime's
clocks and poc's `StopRequests` in place of their own C.

- **Deadlines take `Clocks.Monotonic`**, poDateTime's monotonic clock,
  a `Durations.Duration` in ns, in place of `Tls.c`'s
  `clock_gettime(CLOCK_MONOTONIC)` in ms. `Tls`'s interface is
  unchanged: `Connection.deadline` is still monotonic ms. `Tls.c` keeps
  only whether a descriptor is non-blocking. TestTasks times itself by
  `Clocks.Monotonic` too, rather than poc's internal
  `TaskWaiting.Now`.
- **poDateTime is a dependency of the library**, recorded as `needs
  podatetime` in its manifest, from `PODATETIME` (default `POCLIBDIR`).
  Unlike posockets, it can't be skipped: make stops, saying so, if
  there is none built by the poc in use (checked by its manifest, as
  posockets'). It goes after `build/lib` on the library path, so an
  installed polibtls in the same directory never hides this checkout's;
  building the library with only `PODATETIME` on the path compiles its
  own modules all the same. `make install` and the README's example,
  built outside the repo against the installed library, were checked
  with it.
- **GeminiHello stops cleanly** on SIGINT or SIGTERM: it calls
  `StopRequests.Catch`, and each accept task, which already woke every
  `Tick` (200 ms) to look at `stop`, also stops once
  `StopRequests.Latest()` isn't `none`. Then the connections it has
  finish, and it exits 0. A notifier posting a `Tasks.Event` isn't
  needed, since the accept loop wakes anyway. Without `-n` it used to
  serve until killed.
- **TestGemini's `StopHello`** runs GeminiHello without `-n`, makes one
  request with GeminiFetch, and, with OpenSSL's `s_client`, another
  whose request is sent 2 s after it starts; 1 s in, `TestPeers.Kill`
  sends SIGTERM (to `timeout(1)`, which passes it on and exits as its
  child did). The request in progress must be answered, the server
  must exit 0, and both must be logged. With `StopRequests.Catch`
  commented out, three of its checks fail (exit -1, the request in
  progress lost), so it tests what it means to.
- polibtls itself catches no signal: stopping is a program's business.

Linux: `make test` (460 checks) and `make valgrind` pass. The BSDs:
`gmake test` passes on alerik (FreeBSD 15.1), artos and yishana
(NetBSD 11.0, amd64 and i386), jherek and cymoril (OpenBSD 7.9, amd64
and i386), each with poc 0.14.0 and posockets and poDateTime installed
from a `git archive` of 161a1a4 and 5ae9a47. timeout(1) passes SIGTERM
on there too: `StopHello`'s checks pass on all five, its
in-progress request skipped on OpenBSD for want of OpenSSL's s_client.

### pounix for the tests' child processes [done]

pounix's Phase 7 (2026-11-16, poc 0.14.0): the tests start their child
processes through pounix (`~/Repos/Oberon/pounix`), as pogemini's do,
in place of `TestPeers.c`'s own fork, pipes and poll.

- **`test/Child.Mod`** has what `TestPeers` had for this: `Spawn`
  (`/bin/sh -c` through `UnixProcesses`, its input through a pipe, its
  output and errors through another), `Wait`, `ReadLine` (a byte at a
  time, each waited for through `UnixFiles.WaitReadable`), `Kill`
  (SIGTERM) and `Openssl`. `Wait` keeps polibtls's meaning: as much as
  fits in `got`, with no `0X` after it, and the whole length.
- **`Kill` does nothing for a child that never started**, where the C
  would have signalled process -1. And the child no longer inherits an
  ignored `SIGPIPE` (`TestPeers.IgnoreBrokenPipe`): `UnixProcesses`
  restores the default before `exec`, so openssl and the examples run
  as from a shell.
- **pounix is a test-only dependency**, from `POUNIX` (default
  `POCLIBDIR`), and like poDateTime it can't be skipped: make stops,
  saying so, if there is none built by the poc in use, except for
  `install`, `uninstall`, `doc` and `clean`, which build no test.
- `TestPeers.c` keeps the socket pair, `SIGPIPE` and the threaded TLS
  peer, and no longer needs `_GNU_SOURCE`.

Linux: `make test` (460 checks, as before) and `make valgrind` pass.
The BSDs: `gmake test` passes on alerik, artos, yishana, jherek and
cymoril (403 to 454 checks, as before; skips only for clients a host
lacks and for OpenSSL's openssl on OpenBSD), with pounix from this
work's tree and poDateTime and posockets from a `git archive` of
5ae9a47 and 08b6e48; `TestPeers.c` builds there without `_GNU_SOURCE`.

### Full memcheck for the task tests [done]

2026-11-18: memcheck follows poc's coroutines since Peaseblossom's
bug 21 (their stacks registered with valgrind) was fixed, 2026-11-15
(found in pogeminilib, Phase 4). So `TestTasks` and `TestTcpTasks` no
longer run under `--tool=none`:

- `TASKTESTS` and `VALGRIND_TASKS` are gone; every test runs under
  `VALGRIND`, which loses `--error-exitcode`, since valgrind 3.27.1
  counts each descriptor open at exit as an error and Tasks' self-pipe
  is two. `test/vg-errors.sh` (from pogeminilib, as in posockets)
  passes a log only if its error count equals its descriptors open at
  exit; `vg-fds.sh` judges those descriptors, as before.
- A test needing suppressions of its own has them in
  `test/<name>.supp`, as posockets' `TestFileServer` does for the
  collector's conservative scan of task stacks (`Value8` in
  `DrainMarkStack`). None here needs one: `TestTasks` and
  `TestTcpTasks` have the self-pipe's 2 errors and nothing else, and
  pass the reachable and descriptor checks.

`make test` and `make valgrind` pass.

### The peer's public key [done]

2026-11-18, for pogeminilib's trust on first use (its PLAN.md,
"Trust"): a client pins the SHA-256 of the server's
SubjectPublicKeyInfo, as Lagrange does, so that a certificate renewed
with the same key is still trusted. libtls hashes only the whole
certificate (`tls_peer_cert_hash`), so `Connection.PeerKeyHash` and a
new module, `TlsCerts`, compute it, written as `PeerCertHash` is
(`SHA256:` and lowercase hex).

- **In Oberon, not through libcrypto** (with the user). Each host's
  libtls links its base libcrypto (Fedora's `libcrypto.so.3`, FreeBSD's
  `.so.35`, NetBSD's `.so.16`, OpenBSD's `.so.57`), but on NetBSD
  `pkg-config libtls` gives `-L/usr/pkg/lib`, so `-lcrypto` there could
  link pkgsrc's OpenSSL as well where it is installed (as on terhali):
  two libcryptos in one program. `TlsCerts` needs none: base64, a walk
  of the DER (Certificate, TBSCertificate, an optional `[0]` version,
  five elements, then the SubjectPublicKeyInfo, hashed whole, tag and
  length included), and SHA-256 on `SYSTEM.CARD32`, whose arithmetic
  wraps, with `SYSTEM.ROT`/`LSH` and XOR, AND and NOT as `SET`
  operations. It also reads a certificate file, so pogeminilib's
  identities can have their hash without openssl on `PATH`.
- **`tls_peer_cert_chain_pem`** gives the peer's chain as PEM, its own
  certificate first (LibreTLS 3.8.1's `tls_conninfo_cert_pem`), on a
  client and a server, `size` bytes with no 0X, NULL with no
  certificate; libtls's memory, so `PeerKeyHash` copies it at once.
  `TlsThin.PeerCertChainPem` binds it (`size_t` as `SYSTEM.ADDRESS`).
- **Outside data never halts**: text that isn't a certificate, base64
  that's broken, DER cut short or changed give `FALSE` (`NIL` from
  `PeerKeyHash`). A range outside the array halts (93) and so does a
  hash array too short (99, new).
- **Tests.** `TestCerts`: SHA-256 against FIPS 180-4's examples
  (empty, "abc", 448 bits, a million "a"), lengths 55 to 65, 119, 120
  and 128 and bytes 0 to 255 against openssl; both hashes of every test
  certificate against openssl; a chain and leading text; bad PEM; the
  DER of self-ec cut at every length (`FALSE`) and each byte changed to
  five values (no halt, any key found within the DER). `make-certs.sh`
  makes `renewed-K`, a second certificate on self-K's key: same key
  hash, another certificate hash. `cert-info.sh` gives the key hash by
  `openssl x509 -pubkey | openssl pkey -pubin -outform DER | openssl
  dgst -sha256`, taking dgst's last field, since OpenSSL 3 prints
  `SHA2-256(stdin)= ` before it; LibreSSL 4.3.0 does all of it.
  `TestInfo` checks `PeerKeyHash` on both ends, and `NIL` without a
  client certificate. `HaltCertsRange` (93), `HaltHashShort` (99).
- Under valgrind `TestCerts` has 21 errors (17 before "A certificate's
  validity"), suppressed by
  `poc-gc.supp`: its megabyte forces collections, and the collector's
  stack scan reads unwritten words (`MarkCandidate`).

`make test` and `make valgrind` pass on Linux, and `gmake test` on
FreeBSD 15.1 amd64, NetBSD 11.0 amd64 and i386 and OpenBSD 7.9 amd64
and i386 (alerik, artos, yishana, jherek, cymoril; poc 0.14.0).

**`GeminiFetch` pins the key** (the user, 2026-11-18): `-pin` is now
`PeerKeyHash`, as a client trusting on first use should pin, and it
prints the key's hash to pin when it trusts nothing. `TestGemini` pins
GeminiHello's key, refuses its certificate's hash as a pin (exit 1, no
request sent), and runs its two cut-short servers, `openssl s_server`
and `nc`, on renewed-K pinned by self-K's key.

### A certificate's validity [done]

2026-11-18, for pogeminilib's identities, whose open question (its
PLAN.md, "An identity's hash and expiry from its file") the user
decided as "(a)": polibtls gives a certificate file's hash
(`TlsCerts.CertHash`, there already) and its expiry, so pogeminilib
needs neither openssl at run time nor C. libtls gives only a peer's
times (`tls_peer_cert_notbefore`, `_notafter`), not a file's.

- **`TlsCerts.Validity`** (PEM) and **`Times`** (DER) give notBefore
  and notAfter in seconds since the epoch, `HUGEINT`, as
  `PeerCertNotBefore` and `PeerCertNotAfter` do. The DER walk is now
  one procedure, `Element`, which finds the TBSCertificate's k-th
  element after the optional version: 3 the validity, 5 the
  SubjectPublicKeyInfo (`PublicKey`).
- **RFC 5280's times only** (4.1.2.5): UTCTime `YYMMDDHHMMSSZ`, its
  year 1950 to 2049, and GeneralizedTime `YYYYMMDDHHMMSSZ`, both UTC
  with seconds and no fraction; any other length, tag or character
  gives `FALSE`. Ranges are checked (month 1 to 12, day 1 to 31, hour
  to 23, minute to 59, second to 60, a leap second counting as the
  next), but not a day past the month's end. Days by Hinnant's
  `days_from_civil`, as `cert-info.sh` has it.
- **Tests.** `TestCerts` checks both times of every test certificate
  against `cert-info.sh`'s (openssl's); `make-certs.sh` now makes
  renewed-K for 10000 days, so its notAfter, past 2049, is a
  GeneralizedTime (2054, `openssl asn1parse`); expired-K's notAfter is
  1580515200. In self-ec's DER, notBefore is changed to the epoch,
  2049, 1950, a leap day and a leap second, and to times out of range,
  without `Z`, with a letter or a space, and to the GeneralizedTime tag
  at UTCTime's length, each `FALSE`; the DER cut at every length gives
  `FALSE`, and each byte changed no halt.

`make test` and `make valgrind` pass on Linux (`TestCerts` 21
suppressed collector errors, no others), and `gmake test` on alerik,
artos, yishana, jherek and cymoril, `GeminiFetch`'s renewed-K fetch by
`openssl s_server` on the first three and by `nc` on OpenBSD, each
host having the one.

### Making keys and certificates [done]

2026-11-18, decided with the user: polibtls makes private keys and
certificates itself, through libcrypto, so that pogemini's first run
(its `GemCert`) and the tests need no `openssl` executable, no shell
script and no care over which options OpenSSL's and LibreSSL's
`openssl` both take. libtls can't make either. The alternative, P-256
and ECDSA written in Oberon, was put aside: several sessions of
elliptic-curve arithmetic, no RSA, and a weak key would work without a
sign; libcrypto's are the same code that later uses the key in TLS.
Reading certificates stays in Oberon (`TlsCerts`); TLS itself still
goes only through libtls ("Keep libtls", Phase 10).

**The probe, 2026-11-18.** A 49-line C program made a self-signed
P-256 pair (CN and SANs `localhost`, `127.0.0.1`, `::1`,
`basicConstraints` critical `CA:FALSE`, a subject key identifier,
ecdsa-with-SHA256, a random 16-byte serial) with
`EVP_PKEY_CTX_new_id`/`EVP_PKEY_keygen` and the `X509_*`,
`X509V3_EXT_conf_nid` and `PEM_write_*` calls, on Fedora (OpenSSL 3.5)
and jherek (LibreSSL 4.3.0): it compiled with `-Wall` and no warning,
deprecation or other, on both; `openssl verify` took each certificate;
and each system's libtls loaded both systems' pairs
(`tls_config_set_keypair_file`, `tls_configure`). `EVP_PKEY_Q_keygen`
is OpenSSL 3's only, so it isn't used.

**One libcrypto.** "The peer's public key" kept libcrypto out because
`-lcrypto` could link a second one: NetBSD's `pkg-config libtls` gives
`-L/usr/pkg/lib`, where pkgsrc's OpenSSL may be (terhali). None of the
five test hosts has a second today (2026-11-18: FreeBSD's and NetBSD's
only OpenSSL is base's, 3.5.6 and 3.5.7, OpenBSD's LibreSSL 4.3.0), but
the makefile links, by its path, the libcrypto that libtls's own shared
library loads, as `ldd` names it: `/lib64/libcrypto.so.3` (Fedora),
`/lib/libcrypto.so.35` (FreeBSD), `/usr/lib/libcrypto.so.16` (NetBSD),
`/usr/lib/libcrypto.so.57.2` (OpenBSD), each `ldd` in its own format;
plain `-lcrypto` if none is found. Headers can't be chosen so: the C
part is compiled with libtls's `-I`, which could find another
OpenSSL's. So each call compares the library's name and major version
(`OpenSSL_version`, "OpenSSL 3", "LibreSSL 4") with the headers' and
fails, saying so, if they differ; a patch release of the same one,
after a system update, is fine.

**Design.**

- **Files only, no handles.** `EcKey` and `RsaKey` make a key into a
  file; `SelfSigned` and `Signed` make a certificate into a file from a
  key file (and a CA's certificate and key files). Every libcrypto
  object lives within one C call, so there is nothing to close or
  finalize, and a private key never enters Oberon memory, as AGENTS.md's
  "Secrets" asks.
- **Outside data never halts**: a name, a time, a size or a file can
  come from a configuration, so each call returns a BOOLEAN and
  `VAR error: Tls.String`, NIL on success. No new halt code (polibtls's
  90..99 are all taken).
- **Keys**: P-256, named curve; RSA of 2048 to 16384 bits. PKCS#8 PEM,
  unencrypted, mode 0600. **A key is never replaced**: written to a
  temporary file made by `mkstemp`, then `link`ed to its name, which
  fails if the name exists, since a lost key loses what clients pinned.
  A certificate is replaced (`rename`), since renewing one on the same
  key is the point of `KeyHash`; mode 0644. Each is `fsync`ed first; a
  failure leaves no file behind.
- **Certificates**: version 3, a random positive 16-byte serial,
  SHA-256, a subject of one CN (UTF-8), the issuer's subject as issuer,
  notBefore and notAfter in seconds since the epoch (`HUGEINT`, as
  `TlsCerts.Validity` gives them; `ASN1_TIME_set` picks UTCTime or
  GeneralizedTime as RFC 5280 says). `basicConstraints` critical, CA
  or not; a CA's `keyUsage` critical `keyCertSign,cRLSign`; a subject
  key identifier always, an authority key identifier when signed by a
  CA. Subject alternative names from a string of names separated by
  spaces: each an IPv4 or IPv6 address if it parses as one, else a DNS
  name of letters, digits, `-`, `.` and `*`; anything else fails. These
  are built as structures, not through the configuration language, so
  a name can't add an entry of another kind.
- **Reading a key never prompts**: an encrypted key file fails (a
  passphrase callback that gives none), where libcrypto's default would
  ask on the terminal.
- **A CA's key must be its certificate's** (`X509_check_private_key`),
  or `Signed` fails.

**Built, 2026-11-18** (`src/TlsMake.Mod`, `src/TlsMake.c`, tested by
`test/TestMake.Mod`). The C part is two functions, `TlsMake.-key` and
`TlsMake.-cert`, each starting with `ERR_clear_error` and the version
check and giving its message in a buffer of the caller's (512
characters): what failed, then libcrypto's first queued reason
("library: reason") or `strerror`. The Oberon part checks what it can
without libcrypto (every string 0X-terminated, RSA's size, an empty CN,
notAfter before notBefore, `Signed` without a CA file); libcrypto finds
the rest, as a CN over 64 characters (`X509_NAME_add_entry_by_txt`
fails, "string too long"). The makefile finds libtls's shared library
in libtls's `-L` directories, then `/usr/lib64` and `/usr/lib`, and
takes the first word of `ldd`'s output beginning `/` and naming
libcrypto; the library records it as `-link /lib64/libcrypto.so.3`
on Fedora, and a test program loads only that one.

TestMake makes, for EC and for RSA, a CA, a server certificate it
signs (`localhost 127.0.0.1 ::1`), self-signed server and client
certificates, one expired in 2020 (UTCTime) and a renewal of the
self-signed one, with its key, for 10000 days (GeneralizedTime), into
`build/made/`, and checks, all passing on Fedora:

- `TlsCerts.Validity` reads back the times given; the renewal has the
  same `KeyHash` and another `CertHash`; key files are `-rw-------`
  and certificate files `-rw-r--r--`;
- `openssl verify` takes the server's by the CA, and `openssl x509
  -text` shows the CA's `CA:TRUE` and `Certificate Sign, CRL Sign`, the
  server's `CA:FALSE`, `Version: 3`, an authority key identifier,
  `ecdsa-with-SHA256` or `sha256WithRSAEncryption`, and its names as
  `DNS:localhost, IP Address:127.0.0.1, IP Address:0:0:0:0:0:0:0:1`;
- libtls, over a socket pair, verifies the server by the CA as
  `localhost`, `127.0.0.1` and `::1` and rejects it as
  `other.example`; verifies a self-signed server by its own
  certificate as the CA file, through a wildcard name; rejects the
  expired one; and the server's `PeerCertHash` of the client's
  certificate is `TlsCerts.CertHash` of its file;
- each bad argument or file fails with its reason and leaves no file,
  temporary or not: a key file that exists (and the key is untouched),
  a missing directory, RSA of 1024 or 32768 bits, a missing key file, a
  certificate as the key file, a name with `_`, an address with a
  prefix, an empty CN, a CN of 65 characters (64 succeeds), times
  reversed, a string without 0X, a CA key not the CA's, and a key
  encrypted by `openssl genpkey -aes256`, which fails at once without
  asking for a passphrase, with standard input /dev/null.

Under valgrind, the first wrapping of a passphrase callback (reading
the encrypted key) leaves OpenSSL's ex_data index, registered once per
process (`ui_method_data_index_init`, under `pthread_once`, 112 bytes in
3 records), which `vg-reachable.sh` allows; a key read and left unfreed
on purpose shows as definitely lost, 19 errors, and fails
`vg-errors.sh` (checked 2026-11-18).

RSA key generation varies with the search for primes: `openssl
genpkey` took 0.23 s at 4096 bits and 2.79 s at 8192, once each, on
Fedora (2026-11-18).

**The BSDs, 2026-11-18.** `gmake test` passed, TestMake's every check
included, on alerik (FreeBSD 15.1 amd64), artos and yishana (NetBSD 11.0
amd64 and i386) and jherek and cymoril (OpenBSD 7.9 amd64 and i386),
poc 0.14.0, with only the skips there were before; each linked the
libcrypto its libtls loads: `/lib/libcrypto.so.35`,
`/usr/lib/libcrypto.so.16` and `/usr/lib/libcrypto.so.57.2`. On
OpenBSD, LibreSSL's `openssl verify`, `x509 -text` (`::1` as
`0:0:0:0:0:0:0:1` there too) and `genpkey -aes256` served the
cross-checks as OpenSSL's do.

### gmni, on BearSSL [done]

2026-11-19, with the user: gmni joins `TestGemini` as a fourth TLS
stack beside OpenSSL, libtls's LibreSSL and Go's and GnuTLS's:
BearSSL, which shares no code with any of them.

- **Building.** Fedora packages neither. BearSSL from its git
  repository (`git clone https://www.bearssl.org/git/BearSSL`, at
  7bea48e, in `/usr/local/sw/src/lang/C/bearssl`), built by `make`
  into `build/` (`libbearssl.a`; its README advises against the shared
  library, the ABI not being stable); nothing installed. gmni
  (`/usr/local/sw/src/lang/C/gmni`, 12de5cf) configured with
  `CFLAGS=-I.../bearssl/inc`, then `.build/config.mk`'s `LIBS` set to
  that `libbearssl.a` and `-Werror` dropped from it: GCC 16 warns
  about `calloc`'s arguments and an unused variable in `url.c`. The
  binary links only libc, installed as `~/local/rndbin/gmni`, on `PATH`.
- **The checks** (10, 11 in `ServeHello`): `gmni -4 -j always -E
  client1-rsa` on 127.0.0.1, then `gmni -6 -j fail -E client2-ec` on
  ::1, each asking for `localhost`; each page and the server's log must
  name the client certificate. The second passes only with the
  certificate the first trusted: with a changed fingerprint on file,
  `-j fail` refuses it (exit 6), checked by hand. RSA and EC client
  keys both work.
- **gmni's trust store** is `$XDG_DATA_HOME/gmni/known_hosts`, the
  SHA-512 of the whole certificate by host name, so the test gives it
  `build/gmni-data`, emptied first, as the certificates change with
  each build. The name must be absolute: gmni's `mkdirs` recurses on
  `dirname` until it reaches `/`, which a relative name never does, so
  it overflows its stack (exit 139).
- **No IPv6 literal**: `gemini://[::1]:port/` fails, "Name or service
  not known" (the brackets reach getaddrinfo), hence `localhost` with
  `-4`/`-6`.
- **No truncation check**: gmni ignores BearSSL's error after the last
  read, so like gemget it accepts a response without close_notify.
- Found as `$GMNI` or `gmni` on `PATH`, skipped otherwise; none of the
  BSD hosts has it.

Patched later the same day in the user's gmni checkout (uncommitted;
upstream calls gmni complete): `mkdirs` stops when a path is its own
dirname, `.` as well as `/`; and `strip_brackets` takes the brackets
off an IPv6 literal before `getaddrinfo`, SNI and the trust store, so
`gemini://[::1]:port/` reaches the server and is pinned as `::1`
(checked against pogemini serving `::1`). The tests keep `localhost`
with `-4`/`-6` and an absolute `XDG_DATA_HOME`, for unpatched copies.

## Open questions

- ~~Should sockets be polibtls's own module or a separate library?~~
  A separate library, posockets (2026-11-15, with the user): "Sockets:
  posockets".
- ~~Install an `-O2` variant as well as `-OC`?~~ Not until a program
  built with `-O2` needs one: pogemini, pogeminilib and the other po*
  libraries all use `-OC` (the user, 2026-11-19; "Integer model").
- ~~`Tasks` integration: a separate module, or in `Tls`?~~ A separate
  module, `TlsTasks` (Phase 6).
- ~~Phase 4's blocking tests: a forked peer, or `openssl s_client`?~~
  Neither: a C peer in a thread (Phase 4).
- ~~Should the binding read and validate Gemini's request line (CRLF,
  1024 bytes, no BOM), or leave that to the server project? Leaning
  towards the server project, with only a bounded `ReadLine` here.~~
  The server project, with no `ReadLine` here: pogemini read and
  checked the line itself (its Phases 1 and 2), and now pogeminilib
  does (`GeminiServer`, `GeminiUrls.CheckRequest`), reading through
  `TlsTasks.Read` (2026-11-19).
- ~~Should a lingering close (Phase 8) be in the binding, say in
  `TlsTasks`, or left to the server project?~~ Neither: it is about
  the socket, not TLS, and posockets has it,
  `SocketTasks.LingeringClose` (2026-11-16).
- ~~The BSDs, out of scope above, are now wanted: pogemini, the Gemini
  server, must run on FreeBSD, OpenBSD and NetBSD (the user,
  2026-11-16), so polibtls needs a port, as posockets had (its Phase 9).
  Which libtls on each (OpenBSD's in base; LibreTLS or LibreSSL on
  FreeBSD and NetBSD), and how the tests' OpenSSL-specific findings
  (close_notify errors, the reachable memory valgrind sees) hold there,
  are to be found out; pogemini's PLAN.md, Phase 7. OpenBSD spike done
  (Phase 10): little to port, except that an end without close_notify
  shows only at Close there.~~ Ported (Phase 10, 2026-11-16):
  LibreTLS on FreeBSD and NetBSD, base libtls on OpenBSD.
- ~~Certificate generation for users (a self-signed pair on first run is
  what most Gemini servers do): in the server, not the binding, since
  libtls can't make certificates; it would need OpenSSL's API directly.~~
  In the binding, through libcrypto, `TlsMake` (2026-11-18, with the
  user): "Making keys and certificates".
