# TlsThin: libtls, one to one: the thin layer under Tls

<!-- Made by doc/mkref.py from TlsThin.Mod; edit the source, then make doc. -->

Each libtls function is an unexported ["C"] procedure wrapped in an exported Oberon one, so the thick layer, Tls, never names a C symbol. No ownership or error policy here: that is Tls's.

Types cross with explicit widths, so this module means the same under -OC or -O2: SYSTEM.INT32 for int (descriptors too) and uint32_t (the protocol bits, which fit in 31), SYSTEM.INT64 for ssize_t and time_t, SYSTEM.ADDRESS for pointers and size_t.

Strings: an ARRAY OF CHAR argument reaches libtls as a const char *, and must hold a 0X, which the caller ensures. libtls copies every string it is given here or reads it only during the call (LibreTLS 3.8.1's source: file names are loaded at once, ciphers and the server name strdup'd), so a value parameter's copy in the wrapper's frame is enough. A string libtls returns comes back as its address, 0 for NULL; libtls owns it and may free it on the next call on the same object, so the caller copies it at once.

Results: 0 for success and -1 for failure unless said otherwise; tls_error or tls_config_error then has the text, which is all there is: libtls sets errno to 0 on leaving tls_handshake, tls_read, tls_write and tls_close, so errno isn't bound.

## Types

```oberon
Config* = SYSTEM.ADDRESS;   (* struct tls_config * *)
Context* = SYSTEM.ADDRESS;  (* struct tls *, a context or a connection *)
```

## Variables

```oberon
api-: SYSTEM.INT32;              (* TLS_API *)
wantPollIn-: SYSTEM.INT32;       (* TLS_WANT_POLLIN *)
wantPollOut-: SYSTEM.INT32;      (* TLS_WANT_POLLOUT *)
protocolTLSv12-: SYSTEM.INT32;   (* TLS_PROTOCOL_TLSv1_2 *)
protocolTLSv13-: SYSTEM.INT32;   (* TLS_PROTOCOL_TLSv1_3 *)
protocolsAll-: SYSTEM.INT32;     (* TLS_PROTOCOLS_ALL *)
protocolsDefault-: SYSTEM.INT32; (* TLS_PROTOCOLS_DEFAULT *)
```

tls.h's values, from the C part, set by the body.

## Procedures

#### Init

```oberon
PROCEDURE Init*(): SYSTEM.INT32;
```

### Configuration

#### ConfigNew

```oberon
PROCEDURE ConfigNew*(): Config;
```

A new config, or 0 when out of memory.

#### ConfigFree

```oberon
PROCEDURE ConfigFree*(config: Config);
```

Drops a reference: libtls frees the config when no context holds one (PLAN.md, Phase 0).

#### ConfigError

```oberon
PROCEDURE ConfigError*(config: Config): SYSTEM.ADDRESS;
```

The address of the config's last error text, 0 for none. It stays until the next failing call on config; successes don't clear it.

#### ConfigSetKeypairFile

```oberon
PROCEDURE ConfigSetKeypairFile*(config: Config; certFile, keyFile: ARRAY OF CHAR): SYSTEM.INT32;
```

#### ConfigAddKeypairFile

```oberon
PROCEDURE ConfigAddKeypairFile*(config: Config; certFile, keyFile: ARRAY OF CHAR): SYSTEM.INT32;
```

Another key pair, chosen by SNI.

#### ConfigSetCaFile

```oberon
PROCEDURE ConfigSetCaFile*(config: Config; caFile: ARRAY OF CHAR): SYSTEM.INT32;
```

#### ConfigParseProtocols

```oberon
PROCEDURE ConfigParseProtocols*(VAR protocols: SYSTEM.INT32; protostr: ARRAY OF CHAR): SYSTEM.INT32;
```

Parses a protocol list such as "tlsv1.3" or "secure" into protocol bits. On failure it sets no error text anywhere.

#### ConfigSetProtocols

```oberon
PROCEDURE ConfigSetProtocols*(config: Config; protocols: SYSTEM.INT32): SYSTEM.INT32;
```

#### ConfigSetCiphers

```oberon
PROCEDURE ConfigSetCiphers*(config: Config; ciphers: ARRAY OF CHAR): SYSTEM.INT32;
```

#### ConfigVerifyClientOptional

```oberon
PROCEDURE ConfigVerifyClientOptional*(config: Config);
```

#### ConfigInsecureNoVerifyCert

```oberon
PROCEDURE ConfigInsecureNoVerifyCert*(config: Config);
```

#### ConfigInsecureNoVerifyName

```oberon
PROCEDURE ConfigInsecureNoVerifyName*(config: Config);
```

#### ConfigInsecureNoVerifyTime

```oberon
PROCEDURE ConfigInsecureNoVerifyTime*(config: Config);
```

#### ConfigClearKeys

```oberon
PROCEDURE ConfigClearKeys*(config: Config);
```

Erases the private keys config holds; safe after tls_configure.

### Contexts

#### Server

```oberon
PROCEDURE Server*(): Context;
```

A new server or client context, or 0 when out of memory.

#### Client

```oberon
PROCEDURE Client*(): Context;
```

#### Configure

```oberon
PROCEDURE Configure*(ctx: Context; config: Config): SYSTEM.INT32;
```

#### Free

```oberon
PROCEDURE Free*(ctx: Context);
```

Frees a context or connection; never closes its descriptors.

#### Error

```oberon
PROCEDURE Error*(ctx: Context): SYSTEM.ADDRESS;
```

The address of ctx's last error text, 0 for none. It stays until the next failing call on ctx, or the entry to Handshake, Read, Write or Close; other successes don't clear it.

### Connections

#### AcceptSocket

```oberon
PROCEDURE AcceptSocket*(ctx: Context; VAR cctx: Context; s: SYSTEM.INT32): SYSTEM.INT32;
```

A connection on socket s from server context ctx, in cctx.

#### AcceptFds

```oberon
PROCEDURE AcceptFds*(ctx: Context; VAR cctx: Context; fdRead, fdWrite: SYSTEM.INT32): SYSTEM.INT32;
```

#### ConnectSocket

```oberon
PROCEDURE ConnectSocket*(ctx: Context; s: SYSTEM.INT32; servername: ARRAY OF CHAR): SYSTEM.INT32;
```

Starts a client context ctx on socket s. servername is the name to verify and send by SNI; "" sends none and verifies no name (libtls's NULL).

#### ConnectFds

```oberon
PROCEDURE ConnectFds*(ctx: Context; fdRead, fdWrite: SYSTEM.INT32; servername: ARRAY OF CHAR): SYSTEM.INT32;
```

#### Handshake

```oberon
PROCEDURE Handshake*(ctx: Context): SYSTEM.INT32;
```

Handshake, Read, Write and Close may also return wantPollIn or wantPollOut, even on a blocking descriptor (PLAN.md, "I/O"): the same call must then be repeated with the same arguments.

#### Read

```oberon
PROCEDURE Read*(ctx: Context; buf, buflen: SYSTEM.ADDRESS): SYSTEM.INT64;
```

Up to buflen bytes into buf: the number read, 0 at end of data, -1, wantPollIn or wantPollOut.

#### Write

```oberon
PROCEDURE Write*(ctx: Context; buf, buflen: SYSTEM.ADDRESS): SYSTEM.INT64;
```

Up to buflen bytes from buf: the number written, -1, wantPollIn or wantPollOut.

#### Close

```oberon
PROCEDURE Close*(ctx: Context): SYSTEM.INT32;
```

Sends close_notify; leaves the descriptors open.

### The peer and the connection, after the handshake

#### PeerCertProvided

```oberon
PROCEDURE PeerCertProvided*(ctx: Context): SYSTEM.INT32;
```

1 if the peer gave a certificate, else 0.

#### PeerCertContainsName

```oberon
PROCEDURE PeerCertContainsName*(ctx: Context; name: ARRAY OF CHAR): SYSTEM.INT32;
```

1 if the peer's certificate is valid for name, else 0.

#### PeerCertHash

```oberon
PROCEDURE PeerCertHash*(ctx: Context): SYSTEM.ADDRESS;
```

"SHA256:" and the hash in lowercase hex.

#### PeerCertSubject

```oberon
PROCEDURE PeerCertSubject*(ctx: Context): SYSTEM.ADDRESS;
```

#### PeerCertIssuer

```oberon
PROCEDURE PeerCertIssuer*(ctx: Context): SYSTEM.ADDRESS;
```

#### PeerCertNotBefore

```oberon
PROCEDURE PeerCertNotBefore*(ctx: Context): SYSTEM.INT64;
```

Seconds since the epoch, or -1.

#### PeerCertNotAfter

```oberon
PROCEDURE PeerCertNotAfter*(ctx: Context): SYSTEM.INT64;
```

#### ConnVersion

```oberon
PROCEDURE ConnVersion*(ctx: Context): SYSTEM.ADDRESS;
```

#### ConnCipher

```oberon
PROCEDURE ConnCipher*(ctx: Context): SYSTEM.ADDRESS;
```

#### ConnServername

```oberon
PROCEDURE ConnServername*(ctx: Context): SYSTEM.ADDRESS;
```

The name the client sent by SNI, on a server's connection.
