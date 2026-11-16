# polibtls - an Oberon binding to libtls for poc

This software is developed with the aid of AI.

An Oberon-2 binding to libtls, as [LibreTLS](https://causal.agency/libretls/)
provides it on Linux, for poc, the
[Peaseblossom](https://github.com/tkurtbond/peaseblossom) Oberon compiler.
It is shaped by what a server for the
[Gemini protocol](https://geminiprotocol.net/) needs: a server context
with one or more key pairs, TLS on connections given to it as
descriptors, optional self-signed client certificates, and non-blocking
I/O that works with poc's cooperative `Tasks`.

**Status:** Phases 0 to 9 of [PLAN.md](PLAN.md) are done: the thin
layer `TlsThin`; `Tls`, with configs, server contexts and connections,
blocking and non-blocking I/O, the connection's info and the peer's
certificate; `TlsTasks`, for many connections in poc's `Tasks` with a
deadline each; and two examples, a Gemini server and client. It is
tested over socket pairs and over TCP, under valgrind, and against
`openssl`, OpenBSD's `nc`, gemget (Go's TLS) and `gnutls-cli`. PLAN.md
has the design and the findings it rests on; [AGENTS.md](AGENTS.md) has
the working notes.

## Requirements

- poc 0.13.0 or later, with its runtime library, on `PATH`; override
  with `make POC=/path/to/poc`.
- clang, which poc runs.
- LibreTLS (tested with 3.8.1 on OpenSSL 3.5.8; Fedora's `libretls`
  and `libretls-devel`), found through `pkg-config libtls`.
- openssl, the command, to make the tests' certificates.
- Optional: valgrind (`make valgrind`).
- Optional, for more of the Gemini tests, each skipped without it:
  OpenBSD's `nc` (Fedora's `netcat`), gemget (`go install
  github.com/makeworld-the-better-one/gemget@latest`) and
  `gnutls-cli` (Fedora's `gnutls-utils`).
- Optional: [posockets](https://github.com/tkurtbond/posockets),
  installed, built by the same poc, for the TCP tests; they are skipped
  without it. `make POSOCKETS=<dir>` if it isn't in `POCLIBDIR`.

## Building and installing

```sh
make            # the library, tests and test certificates, into build/
make test       # every test
make valgrind   # the tests under valgrind, with strict leak checks
make doc        # remake doc/ from the comments in src/
make install    # into ~/.local/lib/poc; POCLIBDIR=... to change
make uninstall
make clean
```

The tests' certificates and keys are made afresh in `build/certs/` and
are never committed.

A program then compiles against the installed library with
`poc -OC -library-path ~/.local/lib/poc Program.Mod`, and needs no
link flags: the library records `-ltls`. The library is built for
poc's `-OC` size model only. A library works only with the poc that
built it, so install again after upgrading poc.

## Using it

Three modules; most programs use `Tls`, and `TlsTasks` if they serve
many connections at once:

- **`Tls`**: a `Config` (key pairs, a CA file, protocols, ciphers,
  which checks to make of the peer), a server `Context` configured
  from one, and a `Connection`, which a server gets from
  `Context.AcceptSocket` and a client from `Tls.ConnectSocket`. Then
  `Handshake`, `Read`, `Write`, `WriteAll`, `Close`, and, after the
  handshake, the peer's certificate (`PeerCertHash`, its subject,
  issuer and dates) and what was agreed (`Version`, `Cipher`,
  `Servername`).
- **`TlsTasks`**: `Handshake`, `Read`, `Write`, `WriteAll` and `Close`
  on a connection whose descriptor is non-blocking, waiting through
  poc's `Tasks` so other tasks run meanwhile, until the connection's
  deadline (`Connection.SetDeadline`).
- **`TlsThin`**: libtls's functions one to one, without ownership or
  error handling; `Tls` is built on it.

The reference, [doc/Tls.md](doc/Tls.md),
[doc/TlsTasks.md](doc/TlsTasks.md) and
[doc/TlsThin.md](doc/TlsThin.md), describes every exported name; it is
made from the comments in `src/` by `make doc`.

### An example

A Gemini server with one page, a task per connection, on sockets from
[posockets](https://github.com/tkurtbond/posockets). It runs as shown
against the installed library (checked with GeminiFetch, `gnutls-cli`,
gemget and OpenBSD's `nc`); `examples/GeminiHello.Mod` is a fuller one.

```oberon
MODULE Tiny; (* A Gemini server with one page: a task per connection *)

IMPORT Out, Tasks, Sockets, SocketTasks, Tls, TlsTasks;

TYPE
  Handler = POINTER TO RECORD (Tasks.TaskDesc) s: Sockets.Socket END;

VAR ctx: Tls.Context;

PROCEDURE Append(VAR s: ARRAY OF CHAR; VAR n: LONGINT; t: ARRAY OF CHAR);
  VAR i: LONGINT;
BEGIN i := 0; WHILE t[i] # 0X DO s[n] := t[i]; INC(n); INC(i) END
END Append;

PROCEDURE (h: Handler) Run*;
  VAR c: Tls.Connection; buf: ARRAY 1100 OF CHAR; n, m: LONGINT;
    hash: Tls.String;
BEGIN
  IF ctx.AcceptSocket(h.s.fd, c) THEN
    c.SetDeadline(10000);  (* for all of it, handshake to close_notify *)
    (* the request: a real server reads up to CR LF, 1026 bytes at most *)
    IF TlsTasks.Read(c, buf, 0, 1026, n) THEN
      hash := c.PeerCertHash();  (* the client's identity, or NIL *)
      n := 0; Append(buf, n, "20 text/gemini"); buf[n] := 0DX; buf[n + 1] := 0AX;
      INC(n, 2); Append(buf, n, "# Hello"); buf[n] := 0AX; INC(n);
      IF hash # NIL THEN Append(buf, n, hash^); buf[n] := 0AX; INC(n) END;
      IF TlsTasks.WriteAll(c, buf, 0, n, m) & TlsTasks.Close(c) THEN
        (* read what the client still sends before closing, or the
           kernel may reset the connection under the response *)
        IF SocketTasks.LingeringClose(h.s, 2000) THEN END;
        RETURN
      END
    END;
    Out.String(c.error.text^); Out.Ln; c.Discard
  END;
  Sockets.Close(h.s)
END Run;

PROCEDURE Main;
  VAR cfg: Tls.Config; ls: ARRAY 1 OF Sockets.Socket; n: INTEGER;
    h: Handler; peer: Sockets.Address; err: Sockets.Error;
BEGIN
  cfg := Tls.NewConfig();
  IF ~cfg.SetKeypairFile("server.crt", "server.key") THEN
    Out.String(cfg.error.text^); Out.Ln; RETURN
  END;
  cfg.VerifyClientOptional; cfg.InsecureNoVerifyCert;  (* any client certificate *)
  ctx := Tls.NewServer();
  IF ~ctx.Configure(cfg) THEN Out.String(ctx.error.text^); Out.Ln; RETURN END;
  cfg.Close;
  Sockets.IgnoreBrokenPipe;
  IF ~Sockets.Listen("127.0.0.1", 1965, 16, TRUE, ls, n, err) THEN
    Out.String(err.text); Out.Ln; RETURN
  END;
  LOOP
    NEW(h);
    IF SocketTasks.Accept(ls[0], h.s, peer, err) THEN Tasks.Start(h, TlsTasks.stackSize) END
  END
END Main;

BEGIN
  Main
END Tiny.
```

```sh
poc -OC -library-path ~/.local/lib/poc Tiny.Mod   # polibtls and posockets there
./Tiny    # with server.crt and server.key here; then gemini://127.0.0.1/
```

### Things to know

- **Errors.** A call that can fail for reasons outside the program (a
  missing file, a peer that goes away or can't be verified) returns
  `FALSE`, and the object's `error` says why: `kind` (`config`,
  `handshake`, `io`, `closed`, `wouldBlock`, `timedOut`) and libtls's
  `text`. A programmer's mistake halts instead (below).
- **The end of a response.** `Read` returns `FALSE` with kind `closed`
  only when the peer ended with TLS close_notify. An end without it is
  an error (kind `io`, "unexpected eof while reading"), so a response
  cut short is never taken for a whole one: what Gemini relies on.
- **Descriptors are the program's.** polibtls takes a connected
  socket's descriptor and never closes it; close it after the
  connection's `Close` (or `Discard`). Ignore `SIGPIPE`
  (`Sockets.IgnoreBrokenPipe`), or writing to a peer that has gone
  kills the program.
- **Closing.** `Close` on each object frees its libtls memory at once;
  a finalizer does it otherwise, but the collector can't see libtls's
  memory, so don't rely on it. Close a server `Context` only after
  every connection accepted from it (halt 94). A `Config` may be
  closed once the contexts using it are configured; `Configure` erases
  its keys, so set them again to configure another context with it.
- **Lingering close.** A client may send its own close_notify straight
  after its request (`gnutls-cli` does). If the server then closes the
  socket with that unread, the kernel resets the connection, and the
  client may lose the response. Close with posockets'
  `SocketTasks.LingeringClose` (or read until the client closes).
- **Client certificates.** For Gemini's self-signed client
  certificates, set `VerifyClientOptional` and `InsecureNoVerifyCert`
  on the server's config, and know a client by `PeerCertHash`
  (`SHA256:` and lowercase hex). Dates aren't checked then;
  `PeerCertNotAfter` gives the expiry.
- **Non-blocking I/O.** On a non-blocking descriptor, `Tls`'s calls
  return kind `wouldBlock` and `error.want` says which way to wait;
  make the same call again (a `Write` with the same bytes).
  `TlsTasks` does this through `Tasks`. Start each task with
  `TlsTasks.stackSize` (64 KiB): a handshake needs about 8 KiB.
- **Connection info** (`PeerCert...`, `Version`, `Cipher`,
  `Servername`) exists only after the handshake, which may happen in
  the first `Read` or `Write`; asked before, it halts (92).
- **Under valgrind**, OpenSSL keeps some 430 to 500 KB reachable at
  exit (its global state, and caches filled during handshakes), the
  same however many connections were made; `test/vg-reachable.sh`
  tells it from a leak. memcheck can't
  follow poc's coroutines, so check a program with tasks with
  `valgrind --tool=none --track-fds=yes`, allowing for the two
  descriptors `Tasks` keeps open.

### Halt codes

`ASSERT(cond, n)` ends the program with status 10, printing
`assertion failed (n)`. polibtls uses 90 to 99:

| n | Meaning |
|---|---|
| 90 | `tls_init` failed, when `Tls` was loaded |
| 91 | a closed `Config`, `Context` or `Connection` used |
| 92 | a `Connection`'s info asked for before its handshake was done |
| 93 | a buffer range (pos, len) outside the array |
| 94 | a server `Context` closed while a connection accepted from it is open |
| 95 | a negative descriptor given to `AcceptSocket` or `ConnectSocket` |
| 96 | libtls couldn't allocate a config or context, as `NEW` halts |
| 97 | a connection on a blocking descriptor given to `TlsTasks` |
| 98 | a negative time given to `Connection.SetDeadline` |

## Examples

Built with the TCP tests, when posockets is there, into `build/`:

- `examples/GeminiHello.Mod`: a Gemini server answering every request
  with one page, which names the client's certificate if it sent one.
  `GeminiHello [-n count] [-host host] port cert key [cert key ...]`.
  A task per connection, through `TlsTasks`.
- `examples/GeminiFetch.Mod`: a Gemini client printing the response,
  which trusts the server by a pinned fingerprint or a CA.
  `GeminiFetch [-pin hash | -ca file] [-cert file -key file] url`.

```sh
build/GeminiHello 1965 server.crt server.key &
build/GeminiFetch gemini://localhost/   # prints the fingerprint to pin
```

`make test` runs them against each other, `openssl s_client` and
`s_server`, and, if found, OpenBSD's `nc` (one linked with libtls:
`netcat`, `nc`, or `make test LIBTLS_NC=/path/to/nc`), gemget
(`GEMGET=`) and `gnutls-cli` (`GNUTLS_CLI=`).

## License

BSD 3-Clause; see `LICENSE`.
