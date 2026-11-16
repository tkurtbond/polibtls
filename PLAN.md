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
| `TlsTasks` (maybe folded into `Tls`) | handshake/read/write/close loops that turn `TLS_WANT_POLLIN`/`POLLOUT` into `Tasks.AwaitReadable`/`AwaitWritable`. |

The library is `polibtls`, holding all of them; it records `-ltls` so a
program passes no flags for it. Whether `Tasks` integration is a
separate module (so a program that never uses `Tasks` doesn't import
it) is an open question for Phase 6.

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
  `tls_configure` still handshook, so `Configure` calls it. Read and write buffers
  are only used during the call, so an `ARRAY OF CHAR`/`ARRAY OF
  SYSTEM.BYTE` passed by `VAR` (never by value, to avoid a pointless
  copy) is fine.

### Errors

As polibfyaml: a call that can fail for outside reasons returns
`BOOLEAN`, and the object keeps the last error (`Error`: libtls's
message, copied, plus a kind: `config`, `handshake`, `io`, `closed`,
`system` with `errno`). `ASSERT`/`HALT` are for programmer errors only.
A peer that closes early (`tls_read` returning 0) is not an error: it
is end of data.

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
recorded with the stack size the binding recommends.

**Deadlines.** A Gemini server must cut off a client that stalls in
the handshake or never sends its request, but `Tasks.AwaitReadable`/
`AwaitWritable` wait without limit, and a task blocked in one can't
also wait on `Tasks.After`. Decided in posockets on 2026-11-15, and
added to poc's `Tasks` the same day (Peaseblossom commit 73109d2,
after 0.12.0, so in no release yet; its `doc/developer/tasks.md`,
decision 15): `Tasks.AwaitReadableFor(fd, ms: LONGINT): BOOLEAN` and
`AwaitWritableFor`, `TRUE` when `fd` is ready, `FALSE` when `ms` passed
first. If both are due at one look the timer wins; an `ms` that isn't
positive polls once, then `Yield`s; a negative descriptor is trap 20.
Until the next poc release, Phase 6 builds against the Peaseblossom
checkout. polibtls's `WANT_*`
loops then take a deadline themselves: each wait passes the time
remaining, and a wait that runs out returns a `timedOut` error, as
posockets' does. libtls requires a retried call to have the same
arguments, and a timed-out call is simply not retried, so this fits
its rules; whether the `Connection` is still usable after a timeout in
the middle of a handshake, or must only be closed, is to be found in
Phase 6. A server can still cut a connection off from another task
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
| 92 | the wrong kind of context (accept on a client, connect on a server, I/O on a server context) |
| 93 | a buffer range out of bounds (pos/len outside the array) |
| 94 | a server `Context` closed while a `Connection` accepted from it is still open (libtls reference-counts configs, so a closed `Config` needs no halt; Phase 0) |
| 95 | a negative descriptor given to accept or connect |

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
  descriptor non-blocking, closing it, ignoring `SIGPIPE`, and (if
  Phase 4 chooses it) forking a peer. It is a few lines each, so the
  tests of Phases 1 to 4 need nothing outside this repo, and polibtls
  can be built and tested before posockets exists.
- Handshakes without the network: a socket pair from `TestPeers` and
  `tls_accept_socket`/`tls_connect_socket`, the two sides in two tasks
  of one program (non-blocking) or two processes (blocking).
- TCP (Phase 5 on): posockets, installed, as a test-only dependency:
  the makefile passes its library path to the tests that need it, and
  skips them, saying so, when it isn't installed.
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

### Phase 1: project skeleton

`GNUmakefile` adapted from polibfyaml's (library `polibtls`, `LIBMODS`,
`TESTS`, `HALTTESTS`, `valgrind`, `install`/`uninstall`, certificates
in `build/certs`), `.gitignore` (`build/`), `.gitattributes`,
`test/Check.Mod`, `test/poc-gc.supp`, `test/vg-reachable.sh`, a
`LICENSE` (BSD 3-Clause, as Peaseblossom and polibfyaml have: confirm
with the user), and a stub `README.md`.

### Phase 2: thin layer

`TlsThin` and `TlsThin.c`: the functions the thick layer will call in
Phases 3 to 7, each checked with `nm -D`, and the constants. `TestThin`
calls each with good and bad arguments.

### Phase 3: configuration

`Tls.Config`: `NewConfig`, `SetKeypairFile`, `AddKeypairFile` (SNI),
`SetCaFile`, `SetProtocols` (from a string, through
`tls_config_parse_protocols`), `SetCiphers`, `VerifyClientOptional`,
`InsecureNoVerifyCert`/`Name`/`Time`, `Close`, `ErrorText`. Tests:
missing and malformed files, a key that doesn't match its certificate.

### Phase 4: contexts and blocking I/O

`Tls.Context` (`NewServer`, `NewClient`, `Configure`), and
`Tls.Connection` (`AcceptSocket`, `ConnectSocket`, `Handshake`, `Read`,
`Write`, `WriteAll`, `Close`), over blocking descriptors from
`TestPeers`' socket pair. Two tasks in one program can't both block in libtls
(a blocking call stops every task), so the peer runs in another
process: a child `fork`ed by a test helper in C, or `openssl s_client`.
Decide which in the phase.

### Phase 5: TCP, with posockets

Needs posockets' first version (its own repo and plan, from "Sockets:
posockets" above), which is the work to do between Phases 4 and 5.
Then: the makefile's test-only use of it, and tests of a TLS server on
`127.0.0.1` and `::1`, port 0, with the binding's client and with
`openssl s_client`. Anything polibtls needed from posockets that it
lacked goes into posockets' PLAN.md, not here.

### Phase 6: non-blocking I/O with Tasks

The `WANT_*` loops; the accept loop as a task (posockets' accept); many concurrent clients
in one test (some slow, one that never finishes its handshake) with a
deadline per connection, on `Tasks`' timed wait (Tasks, "Deadlines";
`Tasks.After` can't serve, since a task in `AwaitReadable` can't also
wait on a channel). Measure the stack a handshake
needs. Decide whether this is `TlsTasks` or part of `Tls`.

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
- `Tasks` integration: a separate module, or in `Tls`?
- Phase 4's blocking tests: a forked peer, or `openssl s_client`?
- Should the binding read and validate Gemini's request line (CRLF,
  1024 bytes, no BOM), or leave that to the server project? Leaning
  towards the server project, with only a bounded `ReadLine` here.
- Certificate generation for users (a self-signed pair on first run is
  what most Gemini servers do): in the server, not the binding, since
  libtls can't make certificates; it would need OpenSSL's API directly.
