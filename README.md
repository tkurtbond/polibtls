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

**Work in progress.** The thin layer, `TlsThin`; in `Tls` the config,
server context and connection, with blocking and non-blocking I/O,
the connection's info and the peer's certificate; `TlsTasks`, for
many connections in poc's `Tasks` with a deadline each; and two
examples, a Gemini server and client, exist so far, tested over socket
pairs and over TCP, and against `openssl`, OpenBSD's `nc`, gemget and `gnutls-cli`; see
`PLAN.md` for the design and roadmap.

## Requirements

- poc 0.13.0 or later, with its runtime library, on `PATH`; override
  with `make POC=/path/to/poc`.
- clang, which poc runs.
- LibreTLS with its header, found through `pkg-config libtls`.
- openssl, the command, to make the tests' certificates.
- Optional: valgrind (`make valgrind`).
- Optional, for more of the Gemini tests, each skipped without it:
  OpenBSD's `nc` (Fedora's `netcat`), gemget (`go install
  github.com/makeworld-the-better-one/gemget@latest`) and
  `gnutls-cli` (Fedora's `gnutls-utils`).
- Optional: [posockets](https://github.com/tkurtbond/posockets),
  installed, built by the same poc, for the TCP tests; they are skipped
  without it. `make POSOCKETS=<dir>` if it isn't in `POCLIBDIR`.

## Building and testing

```sh
make            # the library, tests and test certificates, into build/
make test       # every test
make valgrind   # the tests under valgrind, with strict leak checks
make install    # into ~/.local/lib/poc; POCLIBDIR=... to change
make clean
```

The tests' certificates and keys are made afresh in `build/certs/` and
are never committed.

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
