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

**Work in progress.** The thin layer, `TlsThin`, and `Tls.Config`
exist so far; see `PLAN.md` for the design and roadmap.

## Requirements

- poc, with its runtime library, on `PATH`; override with
  `make POC=/path/to/poc`. Until poc 0.13.0 is released, a poc built
  from the Peaseblossom repository is needed (`AGENTS.md`, "Status").
- clang, which poc runs.
- LibreTLS with its header, found through `pkg-config libtls`.
- openssl, the command, to make the tests' certificates.
- Optional: valgrind (`make valgrind`).

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
