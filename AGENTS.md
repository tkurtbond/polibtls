# AGENTS.md

polibtls is an Oberon-2 binding to libtls, as LibreTLS provides it on
Linux, compiled with poc, the Peaseblossom Oberon Compiler. Its first
user is to be a server for the Gemini protocol, in a later project, so
the binding is shaped by what a Gemini server needs: a server context
with one or more key pairs, TLS on connections it is given as
descriptors, optional self-signed client certificates, and non-blocking
I/O that works with poc's cooperative `Tasks`. Sockets themselves are a
separate library, **posockets** (`~/Repos/Oberon/posockets`, created
2026-11-15; PLAN.md, "Sockets: posockets"), which polibtls never imports.
PLAN.md is the design and roadmap; this file
is operational notes for an agent working in this repo, not a design
doc.

Two sibling projects are this one's model; read their `AGENTS.md`
before redesigning anything, since most of their text is confirmed
behaviour of poc that applies here unchanged:

- **polibfyaml** (`~/Repos/Oberon/polibfyaml`): an Oberon-2 binding to a
  C library with poc. Its thin/thick split, `GNUmakefile`, tests, halt
  tests, valgrind setup and conventions are copied here.
- **pofltk** (`~/Repos/Oberon/pofltk`): a later and larger binding.
  Its "Confirmed facts" (calling between Oberon and C, the collector)
  are newer than polibfyaml's, checked up to poc 0.11.2.

## Status

As of 2026-11-16, Phases 0 to 9 of PLAN.md are done: Phase 0's
results are under "Confirmed facts" and in PLAN.md's design sections,
the project skeleton builds and passes `make test` and
`make valgrind`, `TlsThin` binds what Phases 3 to 7 need, tested
by `TestThin` over a socket pair, and `Tls.Config` is done
(`TestConfig`, `HaltConfigClosed`), as are a server `Tls.Context` and
`Tls.Connection` with blocking I/O (`TestBlocking`, against a C peer in
a thread, and five halt tests), and TLS over TCP from posockets
(`TestTcp`: C peers and `openssl s_client`, on `127.0.0.1` and `::1`),
and non-blocking I/O with Tasks and deadlines in `TlsTasks`
(`TestTasks` over socket pairs, `TestTcpTasks` with an accept task,
`HaltBlocking`, `HaltDeadline`), and connection info and the peer's
certificate (`TestInfo`, `HaltInfoEarly`), and the examples, a
Gemini server and client, tested against each other, `openssl
s_client`/`s_server`, OpenBSD's `nc`, gemget (Go) and `gnutls-cli`
(`TestGemini`; gmni possibly later, for want of BearSSL), and the
user's guide (README.md), the reference made from the source comments
(`doc/`, `make doc`), and `make install`, checked by building the
README's example outside the repo. Phase 10, the BSDs, is done too:
`gmake test` passes on FreeBSD, NetBSD and OpenBSD, amd64 and i386
("Testing on the BSD hosts"). The Gemini server, pogemini, is a
project of its own. Since 2026-11-16 deadlines take poDateTime's
monotonic clock, and the example server GeminiHello stops cleanly on
SIGINT or SIGTERM through poc's `StopRequests` (PLAN.md, "poDateTime's
clock and StopRequests": Peaseblossom's "Ongoing library enhancements"
7, step 3).

**poc 0.14.0 or later, and poDateTime, pounix and posockets built by
the same poc.** poc 0.13.0 was the first release with
`Tasks.AwaitReadableFor`/`AwaitWritableFor` (Phase 6's deadlines);
0.14.0 (`peaseblossom-0.14.0-1.fc44`, Peaseblossom a410135, installed
as `/usr/bin/poc` since 2026-11-16) is the first with `StopRequests`,
which GeminiHello uses. A poc library works only with the poc that
built it, so the poDateTime the library needs (`PODATETIME`, default
`POCLIBDIR`), the pounix the tests run commands through (`POUNIX`,
the same default) and the posockets the TCP tests use must come from
the same poc: all were installed in `~/.local/lib/poc` with 0.14.0 on
2026-11-16. After a poc upgrade, reinstall them, each from a `git
archive` of its commit by `make install`: without poDateTime or
pounix, make stops, saying so (`make install` needs only poDateTime);
without posockets, `TestTcp` is skipped. A plain
`make test` then builds and runs everything.

## Reference material

| What | Where |
|---|---|
| Installed LibreTLS | `libretls-3.8.1-7.fc44`, `-devel`, `-static`: `/usr/include/tls.h`, `/usr/lib64/libtls.so.28`; `pkg-config --cflags --libs libtls` = `-ltls` |
| libtls manual | `man 3 tls_init` and the other 88 `tls_*` pages in `/usr/share/man/man3`; `man 7 README` in `/usr/share/doc/libretls` for how LibreTLS differs from LibreSSL's libtls |
| libtls upstream | https://man.openbsd.org/tls_init.3 ; LibreTLS releases at https://causal.agency/libretls/ (source not yet saved locally: fetch it to `/usr/local/sw/src/lang/C/libretls` when a question needs the code) |
| poc | installed from the Peaseblossom RPM: `/usr/bin/poc` (0.14.0 since 2026-11-16), its runtime `poc-rtl` under `/usr/lib/poc`; `poc(1)`, `/usr/share/doc/peaseblossom/` |
| poc source | `~/Repos/Oberon/Peaseblossom` (`doc/users-guide.md`, `doc/reference-guide.md`, `doc/developer/language-extensions.md`; the runtime in `rtl/llvm/`, notably `Tasks.Mod`, `TaskWaiting.Mod` and `doc/developer/tasks.md`) |
| poDateTime | `~/Repos/Oberon/poDateTime`: `Clocks.Monotonic`, a `Durations.Duration` in ns, which `Tls` takes for deadlines |
| Oberon-2 report | `~/Reference/Computer/Languages/Oberon/Oberon2.pdf`; plain text `Oberon2-layout.text`, `Oberon2-no-layout.text` |
| Gemini protocol | the specification at `gemini://geminiprotocol.net/docs/protocol-specification.gmi` (https mirror: https://geminiprotocol.net/docs/protocol-specification.gmi) |
| A libtls command-line peer | OpenBSD's `nc` (`-c` for TLS), Fedora's `netcat` package, installed since 2026-11-15 as `/usr/bin/netcat` (1.238); optional. `/usr/bin/nc` may instead be nmap's `ncat` (OpenSSL), so tell them apart by `ldd ... \| grep libtls`. PLAN.md, "Testing" |
| Gemini clients on other TLS stacks | gemget 1.9.0 (Go, `~/go/bin/gemget`) and `gnutls-cli` 3.8.13 (`gnutls-utils`), used by `TestGemini`; gmni at `/usr/local/sw/src/lang/C/gmni` (BearSSL, not packaged in Fedora): possibly later |

LibreTLS loads root certificates from OpenSSL's default locations, not
LibreSSL's single bundle file (its README(7)). A Gemini server does not
verify client certificates against any CA, so this rarely matters, but
a client test that verifies a server must set its own CA file.

## Build

`GNUmakefile`, adapted from polibfyaml's and posockets': `make`,
`make test`, `make valgrind`, `make doc`, `make clean`,
`make install`/`uninstall` into `POCLIBDIR` (`~/.local/lib/poc` by
default), with `POC` from `PATH`, output under `build/` via
`-output-dir`, `.NOTPARALLEL`, and `POC_LIBRARY_PATH` unexported so an
installed copy is never tested in place of this checkout. libtls's
flags reach the C part through `-c-flag` and the link through `-link`,
recorded in the library, so a program using polibtls passes none
(`pkg-config` gives no compile flags and `-ltls` on Linux; `-I`/`-L`
under `/usr/local` on FreeBSD and `/usr/pkg`, with `-R`, on NetBSD; and
OpenBSD has no `libtls.pc`, so the makefile falls back to `-ltls`).
Tests also link `-lpthread`. poDateTime comes from `PODATETIME`
(default `POCLIBDIR`), after `build/lib` on the library path, so an
installed polibtls there never hides this checkout's; pounix, for the
tests only, from `POUNIX`. Add a module to
`LIBMODS`, in import order; a `src/<Module>.c` beside it is compiled
into the library on its own.

The integer size model is `-OC`, as in polibfyaml (PLAN.md,
"Integer model"). Every C-boundary signature uses explicit widths
(`SYSTEM.INT32` for `int`, `SYSTEM.INT64` for `ssize_t` and `time_t`,
`SYSTEM.ADDRESS` for pointers and `size_t`), so the thin layer means the
same under either model.

## Test

One main module per concern
in `test/`, printing `ok   - <label>` / `FAIL - <label>` through a shared
`test/Check.Mod` and ending with `All checks passed.` or `<N> check(s)
failed.`, listed in `TESTS`;
halt tests `test/Halt*.Mod` listed in `HALTTESTS` as `name:code`. **poc's
`ASSERT(x, n)` exits with status 10**, printing `assertion failed (n)`,
not with `n`.

Tests need certificates. `test/make-certs.sh` makes them with
`openssl` into `build/certs/` (the `certs` target, part of `make`),
never committed: a private key in the repo, even a test one, gets
copied into real use. Its header lists the pairs: `ca`, `server`
(signed by `ca`), `self`, `other` (other.example, for SNI), `client1`,
`client2` and `expired`, each as `-ec` and `-rsa`, as `NAME.crt` and
`NAME.key`. Tests run from `test/`, so they name them as
`../build/certs/NAME.crt`. It and `test/cert-info.sh` run on OpenSSL 3
and LibreSSL alike: keep to options both have, and name the digest
(`-sha256`), since LibreSSL's `x509 -req` defaults to SHA-1.

Most tests need no network: `test/TestPeers.c`, a C helper linked only
into the tests, makes a `socketpair` for the server and client ends,
and `tls_accept_socket`/`tls_connect_socket` run a handshake between
them inside one program: with non-blocking ends, using `Tasks` so both
sides make progress; with blocking ends, against a C TLS peer in a
thread of its own (`TestPeers.StartClient`/`StartServer`/`Join`), which
copies everything it is given into C memory, since the collector scans
only the main thread's stack.
So polibtls builds and tests without posockets up to Phase 4. From
Phase 5, TCP tests (`TCPTESTS`) use the installed posockets in
`POSOCKETS` (default `POCLIBDIR`) as a test-only dependency, and are
skipped, saying so, unless its manifest names the poc in use; they bind
`127.0.0.1` and `::1` on port 0 and read back the port the kernel
chose, so two runs never collide. `Child.Spawn`/`Wait`
(`test/Child.Mod`, over pounix's `UnixProcesses`) run a command, such
as `openssl s_client`, as a child process for interoperability tests;
start it before a blocking `Accept`, and check first that the command
runs at all, or `Accept` waits for ever. `Child.ReadLine` reads a
running child's line (a server's port), waiting through
`UnixFiles.WaitReadable`, and `Kill` ends it. The examples that use posockets (`EXAMPLEPROGS`,
GeminiHello and GeminiFetch) are built with the TCP tests, and
`TestGemini` runs them; it finds OpenBSD's `nc` as `$LIBTLS_NC`,
`netcat` or `nc`, whichever links libtls, and skips its checks without
one (`make test LIBTLS_NC=/path/to/nc`). `openssl` serves as a peer
only if it is OpenSSL's (`Child.Openssl`): LibreSSL's lacks
`s_client -verify_ip` and `s_server -naccept`, so on OpenBSD those
checks print `skip - ...` (`Check.Skip`). Tests link libtls themselves
(`TESTLINK`), since `TestPeers.c` calls it.

Run anything touching ownership or lifetime under valgrind, with
polibfyaml's `test/poc-gc.supp` copied here: poc's collector scans the
stack conservatively and reads uninitialised words. Check "still
reachable" too, not only "definitely lost", as polibfyaml's
`test/vg-reachable.sh` does: a libtls object never freed is pointed to
from poc's heap and so shows as reachable. OpenSSL keeps some global
state for the life of the process: `vg-reachable.sh` allows a record
only if its stack passes through `tls_init` (all 431,784 bytes after
`tls_init` do), which needs valgrind's `--num-callers=60`; a libtls
object leaked on purpose is caught (checked 2026-11-15). After
handshakes OpenSSL fills caches lazily (about 73 KB: fetched
algorithms, key decoders, the thread's error queue), allowed by the
OpenSSL functions in their stacks, which are listed in the script. Tests that run
tasks get full memcheck too, since memcheck follows poc's coroutines
(Peaseblossom's bug 21, fixed 2026-11-15). There is no
`--error-exitcode`, since valgrind counts Tasks' self-pipe as 2 errors:
`test/vg-errors.sh` passes a log only if its errors are all descriptors
open at exit. A test needing suppressions of its own has them in
`test/<name>.supp` (none does yet).

## Testing on the BSD hosts

Phase 10 ran `gmake test` on FreeBSD 15.1 amd64 (alerik), NetBSD 11.0
amd64 (artos) and i386 (yishana), and OpenBSD 7.9 amd64 (jherek) and
i386 (cymoril), each with poc 0.13.0, and again with 0.14.0 for the
move to poDateTime's clock (2026-11-16); rackhir (FreeBSD) builds
packages, so ask before using it. FreeBSD and NetBSD need the
`libretls` package (installed on all of these); OpenBSD's libtls is in
base. Log in by `ssh <host>`, put `/usr/pkg/bin:/usr/local/bin` on
`PATH`, and use `gmake`. Copy the working tree there (`tar` less
`build/` and `.git`) into a directory under `~/tmp`, with posockets,
poDateTime and pounix from a `git archive` each, installed by `gmake
install POCLIBDIR=<dir>` there and passed as `gmake test
POSOCKETS=<dir> PODATETIME=<dir> POUNIX=<dir>`; remove it all when
done, and never work in a checkout on the host. There is no valgrind
there. Judge a run by make's exit status and count `assertion failed`
lines as well as `FAIL`. Over ssh, end a stray test by `pkill -x
<name>`: `pkill -f` matches its own shell.

## Layout

- `src/TlsThin.Mod`: unexported `["C"]` procedures for libtls, each
  wrapped in an exported Oberon procedure. No ownership or error
  policy. `src/TlsThin.c`, its part in C: the `#define` values
  (`TLS_WANT_POLLIN`, `TLS_WANT_POLLOUT`, `TLS_PROTOCOL_*`, `TLS_API`),
  and anything whose type poc can't name portably (not `errno`:
  libtls clears it).
- `src/Tls.Mod`: the thick layer: `Config`, `Context` (a server's
  only, since a client's libtls context is its connection:
  `Tls.ConnectSocket` makes one), `Connection`, `Error`, and
  peer-certificate queries. It takes
  descriptors as `LONGINT` and never opens or closes one: whoever made
  a descriptor closes it. `src/Tls.c`, its part in C: whether a
  descriptor is non-blocking. Its clock is poDateTime's.
- `src/TlsTasks.Mod`: `Tls`'s connection calls waiting through
  `Tasks` until the connection's deadline, so `Tls` never imports
  `Tasks`; `stackSize`, the stack it recommends for a task.
- `test/`, `examples/`: as polibfyaml's, plus `test/TestPeers.c` (the
  tests' socket pair, non-blocking mode, `SIGPIPE`, and the threaded C
  TLS peer) and `test/Child.Mod` (commands as child processes, through
  pounix). The examples use posockets:
  `examples/GeminiHello.Mod`, a Gemini server, with tasks, and
  `examples/GeminiFetch.Mod`, a client, blocking, with pinning.
- `doc/`: the reference, `Tls.md`, `TlsTasks.md` and `TlsThin.md`,
  made by `doc/mkref.py` (copied from posockets, taught section
  introductions, `(* --- Title ---` with prose under it) from each
  module's exported declarations and the comments above them, and
  committed. After changing an exported name or its comment, run
  `make doc`; README.md's example is copied in by hand.
- `build/`: poc and clang output, and generated certificates
  (gitignored).
- `PLAN.md`: design, decisions, confirmed findings and open questions,
  by section. Append to the relevant section; mark a finished phase
  `[done]`, and strike through an open question once decided.

## Confirmed facts

Each was confirmed by a program that ran, with poc 0.12.0 and LibreTLS
3.8.1, on 2026-11-15 unless it says otherwise.

- **poc links and calls libtls directly.** A main module with
  `PROCEDURE ["C", "tls_init"] TlsInit(): SYSTEM.INT32;` and
  `tls_config_new`, `tls_server`, `tls_config_set_keypair_file`,
  `tls_config_error`, `tls_free`, `tls_config_free`, built with
  `poc -OC -link -ltls`, ran correctly, and valgrind reported nothing.
- **An `ARRAY OF CHAR` argument to a `["C"]` procedure arrives as a
  `const char *`** (also pofltk's finding): the file names reached
  libtls, whose error came back as "failed to open certificate file
  '/nonexistent.crt': No such file or directory".
- **libtls's error strings can be read from Oberon** with `SYSTEM.GET`
  through the returned address, up to the `0X`. The thick layer must
  copy one at once: libtls frees or replaces it on the next call on
  the same object (`tls_error(3)`; to be confirmed in Phase 0).

From Phase 0 (C reference and Oberon probes over a socket pair, LibreTLS
3.8.1, OpenSSL 3.5.8, poc 0.13.0 from the checkout; details in PLAN.md,
Phase 0):

- **A `tls_config` is reference-counted**; closing it after
  `tls_configure` is safe.
- **A server context must outlive the handshake of each connection
  accepted from it**: freed before, the handshake segfaults in
  `tls_servername_cb`; freed after, all is well.
- **libtls never closes a descriptor given to `tls_accept_socket` or
  `tls_connect_socket`**, not in `tls_close` nor in `tls_free`.
- **Blocking calls can return `TLS_WANT_POLLIN`/`POLLOUT`** (LibreTLS
  turns off `SSL_MODE_AUTO_RETRY`; TLS 1.3 session tickets cause it):
  retry the same call at once.
- **Error text lives until the next failing call on the object**, and
  successes don't clear it (a config's never; a context's only on entry
  to handshake, read, write and close). Copy it right after the failing
  call, and never take a non-NULL `tls_error` as failure.
- **`SIGPIPE` kills a process that writes to a gone peer** through
  libtls; with it ignored, the call fails with `EPIPE`.
- **With `verify_client_optional` and `insecure_noverifycert`**, a
  self-signed client certificate is accepted, expired or not;
  `tls_peer_cert_hash` is `SHA256:` and lowercase hex.
- **OpenSSL leaves a fixed amount still reachable at exit** (431,784
  bytes after `tls_init`, 502,518 after handshakes), not growing with
  contexts or connections, and `OPENSSL_cleanup()` doesn't free it.
- **Every `*_mem` setter copies its buffer** (LibreTLS source).
- **LibreTLS offers only TLS 1.2 and 1.3**: `TLS_PROTOCOL_TLSv1_0`,
  `_1_1` and `_1_2` are all `1 << 3`.
- **A `SYSTEM.INT64` result isn't assignable to `LONGINT`**, even under
  `-OC`; use `SYSTEM.VAL(LONGINT, x)`.
- **An out pointer can be passed as `SYSTEM.ADR(v)`** of a
  `SYSTEM.ADDRESS` variable to a `["C"]` procedure taking
  `SYSTEM.ADDRESS`, or, as `TlsThin` does, by declaring the parameter
  `VAR` (`VAR cctx: SYSTEM.ADDRESS` for `struct tls **`,
  `VAR p: SYSTEM.INT32` for `uint32_t *`; Phase 2).
- **libtls sets `errno` to 0** on leaving `tls_handshake`, `tls_read`,
  `tls_write` and `tls_close`, so a write to a gone peer leaves 0, not
  `EPIPE`; the error text is the only account (Phase 2, LibreTLS
  tls.c). `errno` isn't bound.
- **Every string libtls takes is copied or only read during the call**,
  so a value `ARRAY OF CHAR` is safe to pass (Phase 2).
- **The key pair setters parse only the certificate**; a bad or
  mismatched key fails at `tls_configure`, and a CA file is parsed only
  when verifying a peer (Phase 3, C probe and source).
- **poc can't index a string constant** (`certs[i]` with `CONST
  certs = "..."`: "'[' requires an array"); pass it as an `ARRAY OF
  CHAR` parameter. Found 2026-11-15, poc 0.13.0.

From Phase 4 (TestBlocking, valgrind-clean; details in PLAN.md,
Phase 4):

- **OpenSSL 3 makes an end without close_notify an error**: `tls_read`
  fails, "unexpected eof while reading", and a later `tls_close`
  fails, "shutdown failed". A clean end (close_notify) is `tls_read`
  returning 0, which `Read` reports as kind `closed`.
- **After a failed verification, `tls_close` fails** ("shutdown
  failed: ... "), since OpenSSL is still in the handshake; `Close` frees
  regardless.
- **A client's CA file is parsed in `tls_connect_socket`** ("ssl verify
  memory setup failure" for one that isn't PEM); a wrong CA or name
  fails in `tls_handshake`. With only the name wrong, the server's side
  of the handshake succeeds.
- **After `tls_config_clear_keys`, configuring another server context
  with the config fails** ("private/public key mismatch").
- **poc's collector finalizes the newest registered object first**,
  within a collection and at exit (GarbageCollectedHeap.Mod,
  FINALIZATION), so a connection is finalized before the context it
  keeps alive.

From Phase 5 (TestTcp, valgrind-clean; details in PLAN.md, Phase 5):

- **libtls and `openssl s_client -verify_ip` verify a server by IP
  address** against the certificate's IP names (`server-K` has
  127.0.0.1 and ::1): `servername` given as `"127.0.0.1"` or `"::1"`.
- **When a TLS 1.3 client rejects the server's certificate, the
  server's `Handshake` fails** ("handshake failed: ... tlsv1 alert
  unknown ca", from s_client).
- **`openssl s_client -quiet` sends its input, reads until the
  server's close_notify, and exits 0**, so it can stand as a one-shot
  Gemini client.

From Phase 6 (TestTasks, TestTcpTasks; details in PLAN.md, Phase 6):

- **A connection timed out in the middle of a handshake stays
  usable**: with a later deadline, another `Handshake` finishes it.
- **A handshake needs little stack**: server or client, EC or RSA,
  each ran in a 16 KiB task, poc's least, writing about 8 KiB; every
  test passed with 16 KiB. `TlsTasks.stackSize` is 64 KiB. A task stack
  has a guard page below it: overrunning it is SIGSEGV.
- **A retried `tls_write` must give the same bytes and length**, though
  the buffer may move (LibreTLS sets `SSL_MODE_ENABLE_PARTIAL_WRITE`
  and `SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER`, tls.c:576-579).
- **`tls_close` never waits for the peer's close_notify**: it calls
  `SSL_shutdown` once and gives `WANT_*` only when its own can't be
  written (LibreTLS tls.c).

From Phase 7 (TestInfo, valgrind-clean; details in PLAN.md, Phase 7):

- **Connection info exists only after the handshake** and lives until
  `tls_free`; the handshake may be made inside the first `tls_read` or
  `tls_write`.
- **libtls's client sends no SNI for an IP address**, so the server's
  `tls_conn_servername` is NULL; with two key pairs, the first is
  presented unless SNI names the other's.
- **Subjects and issuers are `X509_NAME_oneline`'s** `/CN=...`, the
  same as `openssl x509 -nameopt compat`; `test/cert-info.sh` gives a
  certificate's expected hash, names and times.
- **A certificate's common name counts only without subject
  alternative names** (`tls_check_name`, RFC 6125).

From Phase 8 (TestGemini; details in PLAN.md, Phase 8):

- **OpenBSD `nc` (1.238) as a TLS server can't end a Gemini response**:
  without `-N` it waits for the client's end, which waits for its
  close_notify; with `-N` it ends with `shutdown` and no close_notify.
  As a client it works (`nc -c -R ca -e name [-C cert -K key]`).
- **`openssl s_server` (3.5.8) never sends close_notify**: it closes the
  descriptor before `SSL_shutdown`. A client that requires close_notify,
  as Gemini's must, rejects every response from it as truncated.
- **A server must drain before it closes the socket**: `gnutls-cli`
  sends its close_notify right after the request; closed with that
  unread, the socket is reset, and the client loses the response.
  GeminiHello closes with posockets' `SocketTasks.LingeringClose`,
  which shuts down its sending side and reads until the client closes
  or 2 s pass.
- **gemget (Go) checks no server certificate and accepts a response
  without close_notify**; `gnutls-cli` verifies by CA, and
  `gnutls-serv` can't serve Gemini.
- **`openssl s_server -accept 127.0.0.1:0` prints `ACCEPT
  127.0.0.1:<port>`** (not with `-quiet`), and `nc -v -l ... 0` prints
  `Listening on <host> <port>` on standard error.

From the OpenBSD spike (jherek, OpenBSD 7.9, its libtls on LibreSSL
4.3.0, 2026-11-16; PLAN.md, Phase 10):

- **On OpenBSD, an end without close_notify makes `tls_read` return
  0**, like close_notify itself; only `tls_close` then fails ("EOF
  without close notify"). On OpenSSL 3 `tls_read` fails. So `Read`, at
  the end of data, calls `tls_close` itself and reports `closed` only if
  it succeeds (PLAN.md, Phase 10, "Read decides").
- **OpenBSD has no `libtls.pc`** (`-ltls` by hand), needs
  `-lpthread` for `TestPeers.c`, and its `openssl` (LibreSSL) can't run
  `make-certs.sh`; `cert-info.sh` uses GNU `sha256sum` and `date -d`
  (both scripts since made portable, in the port below).
  Everything else in the non-TCP tests passed unchanged.

From the port (all five BSD hosts, 2026-11-16; PLAN.md, Phase 10):

- **On i386 `ssize_t` is 32 bits, and poc won't pass a `LONGINT` as a
  32-bit `SYSTEM.ADDRESS`**, so lengths and `ssize_t`/`time_t` results
  cross through `TlsThin.c` as `int64_t`.
- **LibreSSL's `openssl x509 -req` signs with SHA-1 by default**, which
  GnuTLS rejects ("The certificate chain uses insecure algorithm").
- **A NetBSD socket pair holds 8 KiB**, less than one TLS record: a
  writer whose peer reads nothing completes no record, so nothing
  counts as written. `TestPeers.Pair` raises the send buffer to 64 KiB.
- **`ldd ... | grep -q` over OpenBSD's shell** can report "signal 13"
  (SIGPIPE to `ldd`) in captured output; let grep read everything.

### Carried from polibfyaml and pofltk, not yet re-checked here

- **Exported `["C"]` procedures can be called from other modules**
  since poc 0.3.1, but keep them unexported anyway and wrap each one,
  so a handle stays hidden and the wrapper can check for a closed one.
- **No call chaining**: a function result isn't a designator.
- **Comments nest, and `*)` ends a comment anywhere**: don't write C
  wildcards like `tls_config_*)` in comments.
- **`ORD` takes a `CHAR` or a `SET`, not a `BOOLEAN`.** Never pass a
  `BOOLEAN` across the C boundary; use an `int32_t` 0 or 1.
- **The collector doesn't move objects, scans module globals precisely
  and the stack conservatively, and never sees pointers held only in C
  memory.** Any Oberon memory libtls keeps a pointer to must also be
  reachable from an Oberon object that outlives the libtls object.
- **A value `ARRAY OF CHAR` parameter is copied into the callee's
  frame**, which dies on return. Never give libtls such a copy if it
  keeps the pointer; valgrind cannot see this bug (stack, not heap).
- **Finalizers** (`GarbageCollectedHeap.RegisterFinalizer`) run after
  the collection that finds the object unreachable, and for every
  registered object when the program ends by any path, so valgrind's
  leak report is meaningful. The collector can't see libtls's memory
  pressure, so explicit `Close` is the main cleanup and finalizers a
  backstop.
- **`Out` writes at once**; it buffers nothing.
- **Real literals are `REAL` unless written with `D`.**

## Conventions

- **Claim only what has been verified.** When a comment or decision
  depends on how libtls, OpenSSL or poc behaves, write a throwaway
  program, run it (under valgrind if lifetime is in question, and check
  actual values), and only then record the result: here under
  "Confirmed facts", and in PLAN.md. Throwaway programs go in a session
  directory under `/usr/local/sw/tmp` (`/tmp` is a RAM disk here),
  removed when done.
- **Before binding anything that takes a pointer**, find out from the
  manual and, where it is unclear, LibreTLS's source whether libtls
  copies it or keeps it.
- **Secrets.** Key material read into Oberon memory is overwritten with
  zeros as soon as libtls has it, and the binding prefers file names to
  memory where both exist. Never print a key, and never commit one.
- **The C parts** take and return only `int32_t`, `int64_t` and
  `intptr_t`, and mirror no C struct as an Oberon record. Their
  functions are named `<Module>.-<name>` with `__asm__` labels, as in
  polibfyaml and poc's own `Platform.c`.
- **Bind only what the thick layer calls**, and confirm a symbol exists
  (`nm -D /usr/lib64/libtls.so.28 | grep tls_...`) before binding it.
- **Cleanup is idempotent.** `Close` sets the handle to 0 when it frees,
  and does nothing if it is already 0, so an explicit `Close` and a
  finalizer never free twice.
- **Programmer errors halt** with the codes in PLAN.md, "Halt codes".
  Bad outside data (a peer that misbehaves, a missing certificate file,
  a network error) never halts; it comes back as a `BOOLEAN` result and
  an `Error`.
- **Comments explain why.**
- **Record decisions and findings in PLAN.md as they happen**: append
  to the relevant section, mark finished phases `[done]`, and strike
  through decided open questions.
- **Commit only when asked.** Commit messages are short and say why, as
  in polibfyaml and pofltk.
