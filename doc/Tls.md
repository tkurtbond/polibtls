# Tls: TLS configs, server contexts and connections on descriptors

<!-- Made by doc/mkref.py from Tls.Mod; edit the source, then make doc. -->

Objects own their libtls handle and free it in Close, which is idempotent; a finalizer calls the same Close as a backstop, since the collector can't see libtls's memory (PLAN.md, "Handles and lifetime"). Using an object after Close halts (91).

A call that can fail for reasons outside the program (a missing or malformed file, a string read from a configuration) returns a BOOLEAN, and the object's error field says why: the error of its last call that can fail, or NIL if that call succeeded. libtls's text is copied at once, since libtls frees it on its next failure (PLAN.md, "Errors").

I/O follows the descriptor's mode, looked up when libtls asks to wait (TLS_WANT_POLLIN/POLLOUT). On a blocking descriptor libtls asks even so, after TLS 1.3's session tickets, and the call is repeated at once until it is done (PLAN.md, "I/O"). On a non-blocking one the call returns FALSE with kind wouldBlock, and error.want says whether to wait for the descriptor to be readable or writable; then make the same call again (for Write, with the same bytes and length; the buffer may move). TlsTasks does that waiting through Tasks, with a deadline per connection (SetDeadline).

## Constants

```oberon
config* = 1;     (* a Config setter: a missing or malformed file, a bad string *)
handshake* = 2;  (* configuring a context, accepting, connecting or the handshake: a bad key, an unverifiable peer *)
io* = 3;         (* reading, writing or closing: the peer went away, or broke the protocol *)
closed* = 4;     (* Read found the end of data, and the peer's close_notify confirmed it *)
wouldBlock* = 5; (* a non-blocking descriptor isn't ready: wait as want says and call again *)
timedOut* = 6;   (* TlsTasks: the connection's deadline passed while waiting *)
```

Error kinds

```oberon
wantRead* = 1; wantWrite* = 2;
```

Error.want, when kind = wouldBlock

## Types

```oberon
String* = POINTER TO ARRAY OF CHAR;  (* always 0X-terminated *)
```

```oberon
Error* = POINTER TO ErrorDesc;
ErrorDesc* = RECORD
  kind-: INTEGER;  (* one of the kinds above *)
  want-: INTEGER;  (* wantRead or wantWrite if kind = wouldBlock, else 0 *)
  text-: String    (* libtls's message, or the binding's when libtls has none; never NIL *)
END;
```

```oberon
Config* = POINTER TO ConfigDesc;
ConfigDesc* = RECORD
  error-: Error            (* see the module comment *)
END;
```

A set of options for contexts, made by NewConfig. libtls counts its references from contexts (PLAN.md, "Handles and lifetime"), so a Config may be closed as soon as the contexts using it have been configured.

```oberon
Context* = POINTER TO ContextDesc;
ContextDesc* = RECORD
  error-: Error
END;
```

A server context, made by NewServer: it accepts connections with the key pairs and options of the Config it is configured with. There is no client context: a client's libtls context is its connection, so ConnectSocket makes both at once (PLAN.md, Phase 4).

```oberon
Connection* = POINTER TO ConnectionDesc;
ConnectionDesc* = RECORD
  fd-: LONGINT;
  deadline-: LONGINT;       (* monotonic ms (SetDeadline), 0 for none *)
  error-: Error
END;
```

A TLS connection over a descriptor that the program made and will close, after this Connection's Close: neither libtls nor the binding ever closes it.

## Procedures

### Config

#### Close

```oberon
PROCEDURE (c: Config) Close*;
```

Frees the libtls config; later calls do nothing. Contexts already configured with it keep their own reference.

#### NewConfig

```oberon
PROCEDURE NewConfig*(): Config;
```

A new config with libtls's defaults: TLS 1.2 and 1.3, its "secure" ciphers, and verification of the peer's certificate, name and dates. Halts (96) if libtls can't allocate it, as NEW would.

#### SetKeypairFile

```oberon
PROCEDURE (c: Config) SetKeypairFile*(certFile, keyFile: ARRAY OF CHAR): BOOLEAN;
```

The certificate (chain) and private key, both PEM files, that a server presents, or a client presents when the server asks. libtls reads both files at once, and checks the certificate now, but the key only when a context is configured with c, so a malformed key, or one not matching the certificate, makes that Configure fail instead (PLAN.md, Phase 3). The key stays in libtls's memory until then.

#### AddKeypairFile

```oberon
PROCEDURE (c: Config) AddKeypairFile*(certFile, keyFile: ARRAY OF CHAR): BOOLEAN;
```

A further key pair for a server, chosen when a client asks by SNI for a name in its certificate; the one from SetKeypairFile is the default. Checked as SetKeypairFile's.

#### SetCaFile

```oberon
PROCEDURE (c: Config) SetCaFile*(caFile: ARRAY OF CHAR): BOOLEAN;
```

The PEM file of CA certificates against which the peer's certificate is verified, in place of OpenSSL's default locations. libtls reads it at once but parses it only when verifying a peer: a file that isn't PEM is accepted here (PLAN.md, Phase 3).

#### SetProtocols

```oberon
PROCEDURE (c: Config) SetProtocols*(protocols: ARRAY OF CHAR): BOOLEAN;
```

The TLS versions allowed, as tls_config_parse_protocols(3) reads them: names separated by commas or colons, from "tlsv1.2", "tlsv1.3", "all", "secure", "default" and "legacy", each optionally preceded by "!" to remove it. LibreTLS offers only TLS 1.2 and 1.3.

#### SetCiphers

```oberon
PROCEDURE (c: Config) SetCiphers*(ciphers: ARRAY OF CHAR): BOOLEAN;
```

The cipher suites for TLS 1.2: "secure" (libtls's default), "compat", "legacy", "insecure", or an OpenSSL cipher list. TLS 1.3's are OpenSSL's own and not affected.

#### VerifyClientOptional

```oberon
PROCEDURE (c: Config) VerifyClientOptional*;
```

A server asks each client for a certificate, but accepts a client without one. With InsecureNoVerifyCert too, a self-signed client certificate is accepted, as Gemini needs (PLAN.md, Phase 0).

#### InsecureNoVerifyCert

```oberon
PROCEDURE (c: Config) InsecureNoVerifyCert*;
```

The peer's certificate is not verified against any CA.

#### InsecureNoVerifyName

```oberon
PROCEDURE (c: Config) InsecureNoVerifyName*;
```

A server's certificate need not name the server the client asked for.

#### InsecureNoVerifyTime

```oberon
PROCEDURE (c: Config) InsecureNoVerifyTime*;
```

The peer's certificate may be expired or not yet valid.

### Context

#### Close

```oberon
PROCEDURE (x: Context) Close*;
```

Frees the libtls context; later calls do nothing. Every connection accepted from it must have been closed first (94): libtls's server context must outlive their handshakes (PLAN.md, Phase 0).

#### NewServer

```oberon
PROCEDURE NewServer*(): Context;
```

A new server context, to be configured before it accepts. Halts (96) if libtls can't allocate it.

#### Configure

```oberon
PROCEDURE (x: Context) Configure*(c: Config): BOOLEAN;
```

Configures x with c's key pairs and options: here a malformed key, or one not matching its certificate, is found (kind handshake). Then, on success or failure, c's private keys are erased from libtls's memory (tls_config_clear_keys), since x has its own copy: so c serves no further server context unless its key pairs are set again (PLAN.md, Phase 4). c may be closed afterwards.

### Connection

#### AcceptSocket

```oberon
PROCEDURE (x: Context) AcceptSocket*(fd: LONGINT; VAR conn: Connection): BOOLEAN;
```

A server connection on descriptor fd, a connected socket, in conn; the handshake happens in Handshake, or else in the first Read or Write. FALSE (kind handshake, in x.error) only if libtls can't set it up.

#### ConnectSocket

```oberon
PROCEDURE ConnectSocket*(c: Config; fd: LONGINT; servername: ARRAY OF CHAR;
    VAR conn: Connection): BOOLEAN;
```

A client connection on descriptor fd, a connected socket, with c's options, in conn. servername is the name to verify the server's certificate against and to ask for by SNI; "" for neither. The handshake happens in Handshake, or else in the first Read or Write. On failure (a bad key pair or option in c: kind handshake) conn is closed and conn.error says why. c may be closed afterwards.

#### NonBlocking

```oberon
PROCEDURE (c: Connection) NonBlocking*(): BOOLEAN;
```

Whether c's descriptor is in non-blocking mode, now; FALSE if it isn't open.

#### Handshake

```oberon
PROCEDURE (c: Connection) Handshake*(): BOOLEAN;
```

Completes the handshake, if not yet done: the peer's certificate is verified as the config says. On a non-blocking descriptor, may give wouldBlock (see the module comment).

#### Read

```oberon
PROCEDURE (c: Connection) Read*(VAR buf: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
```

Reads up to len bytes (at least one) into buf[pos..], waiting for them, and n says how many. FALSE at the end of data, with n = 0: kind closed if the peer ended with close_notify, kind io if it ended without one, which a response cut short in transit also gives. Read sends close_notify back then, so Close has nothing left to send; later Reads give the same result. FALSE on failure (kind io, or handshake if the handshake was still to do and failed), and with wouldBlock on a non-blocking descriptor with nothing to read yet (or, at the end, no room for close_notify: call Read again). len = 0 reads nothing.

#### Write

```oberon
PROCEDURE (c: Connection) Write*(buf-: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
```

Writes up to len bytes from buf[pos..], at least one unless len = 0, and n says how many. On a non-blocking descriptor, may give wouldBlock with n = 0: then the same bytes, with the same len, are to be written again; libtls may hold some of them already.

#### WriteAll

```oberon
PROCEDURE (c: Connection) WriteAll*(buf-: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
```

Writes all len bytes from buf[pos..]; on failure n says how many were written. On wouldBlock, call again with pos + n and len - n.

#### Close

```oberon
PROCEDURE (c: Connection) Close*(): BOOLEAN;
```

Sends close_notify, if the handshake was done, and frees the libtls connection, leaving the descriptor open; later calls do nothing and return TRUE. FALSE (kind io) if close_notify couldn't be sent, as when the peer has gone: the connection is freed all the same. libtls doesn't wait for the peer's close_notify. On a non-blocking descriptor whose buffer is full, FALSE with wouldBlock, and the connection stays open: call Close again after waiting, or Discard. After Read has found the end of data, nothing is sent: Close frees, and returns TRUE if the peer's close_notify was confirmed, FALSE (kind io) if not, as Read said.

#### Discard

```oberon
PROCEDURE (c: Connection) Discard*;
```

Frees the libtls connection without close_notify, leaving the descriptor open, as for a peer that is cut off; later calls do nothing. The peer sees an end without close_notify, an error.

### Connection info

What the handshake settled, and the peer's certificate, read from libtls while the connection is open, after the handshake: before it (Handshake, or a Read or Write, hasn't succeeded) these halt (92), and after Close (91). libtls makes them at the end of the handshake and frees them with the connection, so the strings are copies, and NIL where libtls has none. A certificate a client presents isn't verified unless the server's config asks (VerifyClient...), so a Gemini server identifies a client by PeerCertHash alone (PLAN.md, Phase 7).

#### PeerCertProvided

```oberon
PROCEDURE (c: Connection) PeerCertProvided*(): BOOLEAN;
```

Whether the peer presented a certificate; the rest of the PeerCert calls give NIL or -1 if not.

#### PeerCertHash

```oberon
PROCEDURE (c: Connection) PeerCertHash*(): String;
```

"SHA256:" and the SHA-256 of the peer's certificate (DER), in lowercase hex: as a Gemini server knows a client, and a client pins a server.

#### PeerKeyHash

```oberon
PROCEDURE (c: Connection) PeerKeyHash*(): String;
```

"SHA256:" and the SHA-256 of the peer's public key, its SubjectPublicKeyInfo (DER), in lowercase hex, as TlsCerts.KeyHash: the same across a certificate renewed with the same key, so what a client pins a server by (PLAN.md, "The peer's public key"). NIL if there is no certificate, or it can't be read as far as its key.

#### PeerCertSubject

```oberon
PROCEDURE (c: Connection) PeerCertSubject*(): String;
```

The subject of the peer's certificate, in OpenSSL's one-line form, as "/CN=example.org".

#### PeerCertIssuer

```oberon
PROCEDURE (c: Connection) PeerCertIssuer*(): String;
```

The issuer of the peer's certificate, as PeerCertSubject; the same as the subject for a self-signed one.

#### PeerCertNotBefore

```oberon
PROCEDURE (c: Connection) PeerCertNotBefore*(): HUGEINT;
```

The start of the peer's certificate's validity, in seconds since 1970-01-01 UTC; -1 if there is none.

#### PeerCertNotAfter

```oberon
PROCEDURE (c: Connection) PeerCertNotAfter*(): HUGEINT;
```

The end of the peer's certificate's validity, as PeerCertNotBefore. Not checked by libtls when verification is off: a server that cares compares it with the time.

#### PeerCertContainsName

```oberon
PROCEDURE (c: Connection) PeerCertContainsName*(name: ARRAY OF CHAR): BOOLEAN;
```

Whether the peer's certificate names name, a host name or an IP address, in a subject alternative name or, without those, its common name; FALSE if there is no certificate.

#### Version

```oberon
PROCEDURE (c: Connection) Version*(): String;
```

The protocol version agreed, as "TLSv1.3".

#### Cipher

```oberon
PROCEDURE (c: Connection) Cipher*(): String;
```

The cipher suite agreed, in OpenSSL's naming, as "TLS_AES_256_GCM_SHA384".

#### Servername

```oberon
PROCEDURE (c: Connection) Servername*(): String;
```

On a server: the name the client asked for by SNI, NIL if it sent none (a client connecting by IP address sends none). On a client: the servername given to ConnectSocket, NIL for "".

### Deadlines, for TlsTasks

#### SetDeadline

```oberon
PROCEDURE (c: Connection) SetDeadline*(ms: LONGINT);
```

Gives c a deadline ms milliseconds from now, on the monotonic clock, or none if ms = 0: TlsTasks' calls on c that would wait past it return FALSE with kind timedOut. The deadline stays until it is set again, across calls. Halts (98) for a negative ms.

#### TimeLeft

```oberon
PROCEDURE (c: Connection) TimeLeft*(): LONGINT;
```

Milliseconds until c's deadline, 0 if it has passed, -1 if c has none.

#### TimedOut

```oberon
PROCEDURE (c: Connection) TimedOut*(what: ARRAY OF CHAR);
```

For TlsTasks: a wait on c's descriptor for what (an operation's name) passed c's deadline; c.error becomes "<what> timed out", kind timedOut.
