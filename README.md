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

**Work in progress.** The thin layer, `TlsThin`, and in `Tls` the
config, server context and connection, with blocking I/O, exist so far,
tested over socket pairs and over TCP; see `PLAN.md` for the design and
roadmap.

## Requirements

- poc 0.13.0 or later, with its runtime library, on `PATH`; override
  with `make POC=/path/to/poc`.
- clang, which poc runs.
- LibreTLS with its header, found through `pkg-config libtls`.
- openssl, the command, to make the tests' certificates.
- Optional: valgrind (`make valgrind`).
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

## License

BSD 3-Clause; see `LICENSE`.
