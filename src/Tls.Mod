MODULE Tls; (* The thick layer of polibtls (PLAN.md, "Modules") *)

(* Objects own their libtls handle and free it in Close, which is
   idempotent; a finalizer calls the same Close as a backstop, since the
   collector can't see libtls's memory (PLAN.md, "Handles and
   lifetime"). Using an object after Close halts (91).

   A call that can fail for reasons outside the program (a missing or
   malformed file, a string read from a configuration) returns a
   BOOLEAN, and the object's error field says why: the error of its
   last call that can fail, or NIL if that call succeeded. libtls's
   text is copied at once, since libtls frees it on its next failure
   (PLAN.md, "Errors").

   I/O follows the descriptor's mode, looked up when libtls asks to
   wait (TLS_WANT_POLLIN/POLLOUT). On a blocking descriptor libtls asks
   even so, after TLS 1.3's session tickets, and the call is repeated at
   once until it is done (PLAN.md, "I/O"). On a non-blocking one the
   call returns FALSE with kind wouldBlock, and error.want says whether
   to wait for the descriptor to be readable or writable; then make the
   same call again (for Write, with the same bytes and length; the
   buffer may move). TlsTasks does that waiting through Tasks, with a
   deadline per connection (SetDeadline). *)

IMPORT SYSTEM, GarbageCollectedHeap, TlsThin;

CONST
  (* Error kinds *)
  config* = 1;     (* a Config setter: a missing or malformed file, a bad string *)
  handshake* = 2;  (* configuring a context, accepting, connecting or the handshake: a bad key, an unverifiable peer *)
  io* = 3;         (* reading, writing or closing: the peer went away, or broke the protocol *)
  closed* = 4;     (* Read found the end of data: the peer sent close_notify *)
  wouldBlock* = 5; (* a non-blocking descriptor isn't ready: wait as want says and call again *)
  timedOut* = 6;   (* TlsTasks: the connection's deadline passed while waiting *)

  (* Error.want, when kind = wouldBlock *)
  wantRead* = 1; wantWrite* = 2;

TYPE
  String* = POINTER TO ARRAY OF CHAR;  (* always 0X-terminated *)

  Error* = POINTER TO ErrorDesc;
  ErrorDesc* = RECORD
    kind-: INTEGER;  (* one of the kinds above *)
    want-: INTEGER;  (* wantRead or wantWrite if kind = wouldBlock, else 0 *)
    text-: String    (* libtls's message, or the binding's when libtls has none; never NIL *)
  END;

  (* A set of options for contexts, made by NewConfig. libtls counts its
     references from contexts (PLAN.md, "Handles and lifetime"), so a
     Config may be closed as soon as the contexts using it have been
     configured. *)
  Config* = POINTER TO ConfigDesc;
  ConfigDesc* = RECORD
    handle: TlsThin.Config;  (* 0 once closed *)
    error-: Error            (* see the module comment *)
  END;

  (* A server context, made by NewServer: it accepts connections with
     the key pairs and options of the Config it is configured with.
     There is no client context: a client's libtls context is its
     connection, so ConnectSocket makes both at once (PLAN.md, Phase 4). *)
  Context* = POINTER TO ContextDesc;
  ContextDesc* = RECORD
    handle: TlsThin.Context;  (* 0 once closed *)
    open: LONGINT;            (* connections accepted from it and not yet closed *)
    orphaned: BOOLEAN;        (* finalized with open > 0: the last one to close frees it *)
    error-: Error
  END;

  (* A TLS connection over a descriptor that the program made and will
     close, after this Connection's Close: neither libtls nor the
     binding ever closes it. *)
  Connection* = POINTER TO ConnectionDesc;
  ConnectionDesc* = RECORD
    handle: TlsThin.Context;  (* 0 once closed *)
    server: Context;          (* accepted from it, NIL for a client; keeps it alive *)
    fd-: LONGINT;
    deadline-: LONGINT;       (* monotonic ms (SetDeadline), 0 for none *)
    shaken: BOOLEAN;          (* the handshake is done: the connection info may be read *)
    error-: Error
  END;

VAR
  (* The wouldBlock errors, one for each direction, shared since an
     Error can't be changed outside this module: a task waiting on a
     busy connection gets one every time, so none is allocated. *)
  wouldRead, wouldWrite: Error;

PROCEDURE ["C", "Tls.-nonblocking"] CNonBlocking(fd: SYSTEM.INT64): SYSTEM.INT32;
PROCEDURE ["C", "Tls.-now"] CNow(): SYSTEM.INT64;

(* A new String holding the 0X-terminated C string at adr, which must
   not be 0. *)
PROCEDURE CopyC(adr: SYSTEM.ADDRESS): String;
  VAR n, i: LONGINT; c: CHAR; s: String;
BEGIN
  n := 0;
  REPEAT SYSTEM.GET(adr + n, c); INC(n) UNTIL c = 0X;
  NEW(s, n);
  FOR i := 0 TO n - 1 DO SYSTEM.GET(adr + i, s[i]) END;
  RETURN s
END CopyC;

PROCEDURE NewString(text: ARRAY OF CHAR): String;
  VAR n, i: LONGINT; s: String;
BEGIN
  n := 0; WHILE (n < LEN(text)) & (text[n] # 0X) DO INC(n) END;
  NEW(s, n + 1);
  FOR i := 0 TO n - 1 DO s[i] := text[i] END;
  s[n] := 0X;
  RETURN s
END NewString;

(* An error of kind, with libtls's text at adr, or with fallback if adr
   is 0: tls_config_parse_protocols takes no config to put text in, and
   a setter whose strdup fails sets none. (Then a config's text may be an
   earlier failure's, which can't be told apart; out of memory only.) *)
PROCEDURE NewError(kind: INTEGER; adr: SYSTEM.ADDRESS; fallback: ARRAY OF CHAR): Error;
  VAR e: Error;
BEGIN
  NEW(e); e.kind := kind; e.want := 0;
  IF adr # 0 THEN e.text := CopyC(adr) ELSE e.text := NewString(fallback) END;
  RETURN e
END NewError;

(* An error of kind with libtls's text for context h, or fallback. *)
PROCEDURE ContextError(kind: INTEGER; h: TlsThin.Context; fallback: ARRAY OF CHAR): Error;
BEGIN RETURN NewError(kind, TlsThin.Error(h), fallback)
END ContextError;

(* --- Config --- *)

(* Records the result r of a config setter: clears c.error on success,
   and on failure copies libtls's text at once. *)
PROCEDURE (c: Config) Result(r: SYSTEM.INT32; fallback: ARRAY OF CHAR): BOOLEAN;
BEGIN
  IF r = 0 THEN c.error := NIL; RETURN TRUE
  ELSE c.error := NewError(config, TlsThin.ConfigError(c.handle), fallback); RETURN FALSE
  END
END Result;

(* Frees the libtls config; later calls do nothing. Contexts already
   configured with it keep their own reference. *)
PROCEDURE (c: Config) Close*;
  VAR h: TlsThin.Config;
BEGIN
  IF c.handle # 0 THEN
    h := c.handle; c.handle := 0;  (* dead before freed: never freed twice *)
    TlsThin.ConfigFree(h)
  END
END Close;

PROCEDURE FinalizeConfig(obj: SYSTEM.PTR);
  VAR c: Config;
BEGIN c := SYSTEM.VAL(Config, obj); c.Close
END FinalizeConfig;

(* A new config with libtls's defaults: TLS 1.2 and 1.3, its "secure"
   ciphers, and verification of the peer's certificate, name and dates.
   Halts (96) if libtls can't allocate it, as NEW would. *)
PROCEDURE NewConfig*(): Config;
  VAR c: Config; h: TlsThin.Config;
BEGIN
  h := TlsThin.ConfigNew();
  ASSERT(h # 0, 96);
  NEW(c); c.handle := h; c.error := NIL;
  GarbageCollectedHeap.RegisterFinalizer(c, FinalizeConfig);
  RETURN c
END NewConfig;

(* The certificate (chain) and private key, both PEM files, that a server
   presents, or a client presents when the server asks. libtls reads
   both files at once, and checks the certificate now, but the key only
   when a context is configured with c, so a malformed key, or one not
   matching the certificate, makes that Configure fail instead (PLAN.md,
   Phase 3). The key stays in libtls's memory until then. *)
PROCEDURE (c: Config) SetKeypairFile*(certFile, keyFile: ARRAY OF CHAR): BOOLEAN;
BEGIN
  ASSERT(c.handle # 0, 91);
  RETURN c.Result(TlsThin.ConfigSetKeypairFile(c.handle, certFile, keyFile),
    "cannot set the key pair")
END SetKeypairFile;

(* A further key pair for a server, chosen when a client asks by SNI for
   a name in its certificate; the one from SetKeypairFile is the
   default. Checked as SetKeypairFile's. *)
PROCEDURE (c: Config) AddKeypairFile*(certFile, keyFile: ARRAY OF CHAR): BOOLEAN;
BEGIN
  ASSERT(c.handle # 0, 91);
  RETURN c.Result(TlsThin.ConfigAddKeypairFile(c.handle, certFile, keyFile),
    "cannot add the key pair")
END AddKeypairFile;

(* The PEM file of CA certificates against which the peer's certificate
   is verified, in place of OpenSSL's default locations. libtls reads it
   at once but parses it only when verifying a peer: a file that isn't
   PEM is accepted here (PLAN.md, Phase 3). *)
PROCEDURE (c: Config) SetCaFile*(caFile: ARRAY OF CHAR): BOOLEAN;
BEGIN
  ASSERT(c.handle # 0, 91);
  RETURN c.Result(TlsThin.ConfigSetCaFile(c.handle, caFile), "cannot set the CA file")
END SetCaFile;

(* The TLS versions allowed, as tls_config_parse_protocols(3) reads them:
   names separated by commas or colons, from "tlsv1.2", "tlsv1.3", "all",
   "secure", "default" and "legacy", each optionally preceded by "!" to
   remove it. LibreTLS offers only TLS 1.2 and 1.3. *)
PROCEDURE (c: Config) SetProtocols*(protocols: ARRAY OF CHAR): BOOLEAN;
  VAR p: SYSTEM.INT32;
BEGIN
  ASSERT(c.handle # 0, 91);
  IF TlsThin.ConfigParseProtocols(p, protocols) # 0 THEN
    (* parsing is no call on c, so c's error text is someone else's *)
    c.error := NewError(config, 0, "invalid protocols");
    RETURN FALSE
  END;
  RETURN c.Result(TlsThin.ConfigSetProtocols(c.handle, p), "cannot set the protocols")
END SetProtocols;

(* The cipher suites for TLS 1.2: "secure" (libtls's default), "compat",
   "legacy", "insecure", or an OpenSSL cipher list. TLS 1.3's are
   OpenSSL's own and not affected. *)
PROCEDURE (c: Config) SetCiphers*(ciphers: ARRAY OF CHAR): BOOLEAN;
BEGIN
  ASSERT(c.handle # 0, 91);
  RETURN c.Result(TlsThin.ConfigSetCiphers(c.handle, ciphers), "cannot set the ciphers")
END SetCiphers;

(* A server asks each client for a certificate, but accepts a client
   without one. With InsecureNoVerifyCert too, a self-signed client
   certificate is accepted, as Gemini needs (PLAN.md, Phase 0). *)
PROCEDURE (c: Config) VerifyClientOptional*;
BEGIN
  ASSERT(c.handle # 0, 91);
  TlsThin.ConfigVerifyClientOptional(c.handle)
END VerifyClientOptional;

(* The peer's certificate is not verified against any CA. *)
PROCEDURE (c: Config) InsecureNoVerifyCert*;
BEGIN
  ASSERT(c.handle # 0, 91);
  TlsThin.ConfigInsecureNoVerifyCert(c.handle)
END InsecureNoVerifyCert;

(* A server's certificate need not name the server the client asked
   for. *)
PROCEDURE (c: Config) InsecureNoVerifyName*;
BEGIN
  ASSERT(c.handle # 0, 91);
  TlsThin.ConfigInsecureNoVerifyName(c.handle)
END InsecureNoVerifyName;

(* The peer's certificate may be expired or not yet valid. *)
PROCEDURE (c: Config) InsecureNoVerifyTime*;
BEGIN
  ASSERT(c.handle # 0, 91);
  TlsThin.ConfigInsecureNoVerifyTime(c.handle)
END InsecureNoVerifyTime;

(* --- Context --- *)

(* Frees the libtls context. *)
PROCEDURE (x: Context) Free;
  VAR h: TlsThin.Context;
BEGIN
  IF x.handle # 0 THEN h := x.handle; x.handle := 0; TlsThin.Free(h) END
END Free;

(* Frees the libtls context; later calls do nothing. Every connection
   accepted from it must have been closed first (94): libtls's server
   context must outlive their handshakes (PLAN.md, Phase 0). *)
PROCEDURE (x: Context) Close*;
BEGIN
  IF x.handle # 0 THEN ASSERT(x.open = 0, 94); x.Free END
END Close;

(* A context with open connections is reachable from them, so is found
   unreachable only with them; the collector finalizes the newest first,
   so they go before it. orphaned covers any other order. *)
PROCEDURE FinalizeContext(obj: SYSTEM.PTR);
  VAR x: Context;
BEGIN
  x := SYSTEM.VAL(Context, obj);
  IF x.open = 0 THEN x.Free ELSE x.orphaned := TRUE END
END FinalizeContext;

(* A new server context, to be configured before it accepts. Halts (96)
   if libtls can't allocate it. *)
PROCEDURE NewServer*(): Context;
  VAR x: Context; h: TlsThin.Context;
BEGIN
  h := TlsThin.Server();
  ASSERT(h # 0, 96);
  NEW(x); x.handle := h; x.open := 0; x.orphaned := FALSE; x.error := NIL;
  GarbageCollectedHeap.RegisterFinalizer(x, FinalizeContext);
  RETURN x
END NewServer;

(* Configures x with c's key pairs and options: here a malformed key, or
   one not matching its certificate, is found (kind handshake). Then, on
   success or failure, c's private keys are erased from libtls's memory
   (tls_config_clear_keys), since x has its own copy: so c serves no
   further server context unless its key pairs are set again (PLAN.md,
   Phase 4). c may be closed afterwards. *)
PROCEDURE (x: Context) Configure*(c: Config): BOOLEAN;
  VAR ok: BOOLEAN;
BEGIN
  ASSERT(x.handle # 0, 91); ASSERT(c.handle # 0, 91);
  ok := TlsThin.Configure(x.handle, c.handle) = 0;
  IF ok THEN x.error := NIL
  ELSE x.error := ContextError(handshake, x.handle, "cannot configure the context")
  END;
  TlsThin.ConfigClearKeys(c.handle);
  RETURN ok
END Configure;

(* --- Connection --- *)

PROCEDURE CheckFd(fd: LONGINT);
BEGIN ASSERT((fd >= 0) & (fd <= MAX(SYSTEM.INT32)), 95)
END CheckFd;

(* Frees the libtls connection without close_notify, and lets its
   server context go when it was the last. *)
PROCEDURE (c: Connection) Free;
  VAR h: TlsThin.Context;
BEGIN
  IF c.handle # 0 THEN
    h := c.handle; c.handle := 0; TlsThin.Free(h);
    IF c.server # NIL THEN
      DEC(c.server.open);
      IF c.server.orphaned & (c.server.open = 0) THEN c.server.Free END;
      c.server := NIL
    END
  END
END Free;

(* No close_notify from a finalizer: by then the program may have closed
   the descriptor, and its number may be another's. *)
PROCEDURE FinalizeConnection(obj: SYSTEM.PTR);
  VAR c: Connection;
BEGIN c := SYSTEM.VAL(Connection, obj); c.Free
END FinalizeConnection;

PROCEDURE NewConnection(h: TlsThin.Context; server: Context; fd: LONGINT): Connection;
  VAR c: Connection;
BEGIN
  NEW(c); c.handle := h; c.server := server; c.fd := fd; c.deadline := 0;
  c.shaken := FALSE; c.error := NIL;
  GarbageCollectedHeap.RegisterFinalizer(c, FinalizeConnection);
  RETURN c
END NewConnection;

(* A server connection on descriptor fd, a connected socket, in conn;
   the handshake happens in Handshake, or else in the first Read or
   Write. FALSE (kind handshake, in x.error) only if libtls can't set it
   up. *)
PROCEDURE (x: Context) AcceptSocket*(fd: LONGINT; VAR conn: Connection): BOOLEAN;
  VAR h: TlsThin.Context;
BEGIN
  ASSERT(x.handle # 0, 91); CheckFd(fd);
  h := 0; conn := NIL;
  IF TlsThin.AcceptSocket(x.handle, h, SYSTEM.VAL(SYSTEM.INT32, fd)) # 0 THEN
    x.error := ContextError(handshake, x.handle, "cannot accept the connection");
    RETURN FALSE
  END;
  x.error := NIL; INC(x.open);
  conn := NewConnection(h, x, fd);
  RETURN TRUE
END AcceptSocket;

(* A client connection on descriptor fd, a connected socket, with c's
   options, in conn. servername is the name to verify the server's
   certificate against and to ask for by SNI; "" for neither. The
   handshake happens in Handshake, or else in the first Read or Write.
   On failure (a bad key pair or option in c: kind handshake) conn is
   closed and conn.error says why. c may be closed afterwards. *)
PROCEDURE ConnectSocket*(c: Config; fd: LONGINT; servername: ARRAY OF CHAR;
    VAR conn: Connection): BOOLEAN;
  VAR h: TlsThin.Context;
BEGIN
  ASSERT(c.handle # 0, 91); CheckFd(fd);
  h := TlsThin.Client();
  ASSERT(h # 0, 96);
  conn := NewConnection(h, NIL, fd);
  IF TlsThin.Configure(h, c.handle) # 0 THEN
    conn.error := ContextError(handshake, h, "cannot configure the client")
  ELSIF TlsThin.ConnectSocket(h, SYSTEM.VAL(SYSTEM.INT32, fd), servername) # 0 THEN
    conn.error := ContextError(handshake, h, "cannot connect")
  ELSE RETURN TRUE
  END;
  conn.Free;
  RETURN FALSE
END ConnectSocket;

PROCEDURE Want(r: SYSTEM.INT64): BOOLEAN;
BEGIN RETURN (r = TlsThin.wantPollIn) OR (r = TlsThin.wantPollOut)
END Want;

(* Whether c's descriptor is in non-blocking mode, now; FALSE if it
   isn't open. *)
PROCEDURE (c: Connection) NonBlocking*(): BOOLEAN;
BEGIN RETURN CNonBlocking(c.fd) = 1
END NonBlocking;

(* Whether a libtls call that returned r is to be made again at once:
   when it asks to wait and c's descriptor is blocking. When it asks to
   wait on a non-blocking descriptor, c.error becomes wouldBlock, and the
   caller returns FALSE. *)
PROCEDURE (c: Connection) Again(r: SYSTEM.INT64): BOOLEAN;
BEGIN
  IF ~Want(r) THEN RETURN FALSE
  ELSIF ~c.NonBlocking() THEN RETURN TRUE
  ELSIF r = TlsThin.wantPollIn THEN c.error := wouldRead
  ELSE c.error := wouldWrite
  END;
  RETURN FALSE
END Again;

(* Completes the handshake, if not yet done: the peer's certificate is
   verified as the config says. On a non-blocking descriptor, may give
   wouldBlock (see the module comment). *)
PROCEDURE (c: Connection) Handshake*(): BOOLEAN;
  VAR r: SYSTEM.INT32;
BEGIN
  ASSERT(c.handle # 0, 91);
  REPEAT r := TlsThin.Handshake(c.handle) UNTIL ~c.Again(r);
  IF r = 0 THEN c.shaken := TRUE; c.error := NIL; RETURN TRUE
  ELSIF ~Want(r) THEN c.error := ContextError(handshake, c.handle, "handshake failed")
  END;
  RETURN FALSE
END Handshake;

PROCEDURE CheckRange(size, pos, len: LONGINT);
BEGIN ASSERT((pos >= 0) & (len >= 0) & (pos <= size) & (len <= size - pos), 93)
END CheckRange;

(* Reads up to len bytes (at least one) into buf[pos..], waiting for
   them, and n says how many. FALSE at the end of data (kind closed,
   n = 0), after the peer's close_notify, and on failure (kind io, or
   handshake if the handshake was still to do and failed), and with
   wouldBlock on a non-blocking descriptor with nothing to read yet.
   len = 0 reads nothing. *)
PROCEDURE (c: Connection) Read*(VAR buf: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
  VAR r: SYSTEM.INT64;
BEGIN
  ASSERT(c.handle # 0, 91); CheckRange(LEN(buf), pos, len);
  n := 0;
  IF len = 0 THEN RETURN TRUE END;
  REPEAT r := TlsThin.Read(c.handle, SYSTEM.ADR(buf[pos]), len) UNTIL ~c.Again(r);
  (* libtls makes the handshake first if it isn't done: data or the
     end of it means it is *)
  IF r >= 0 THEN c.shaken := TRUE END;
  IF r > 0 THEN n := SYSTEM.VAL(LONGINT, r); c.error := NIL; RETURN TRUE
  ELSIF Want(r) THEN (* wouldBlock, set by Again *)
  ELSIF r = 0 THEN c.error := NewError(closed, 0, "connection closed by peer")
  ELSE c.error := ContextError(io, c.handle, "read failed")
  END;
  RETURN FALSE
END Read;

(* Writes up to len bytes from buf[pos..], at least one unless len = 0,
   and n says how many. On a non-blocking descriptor, may give
   wouldBlock with n = 0: then the same bytes, with the same len, are to
   be written again; libtls may hold some of them already. *)
PROCEDURE (c: Connection) Write*(buf-: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
  VAR r: SYSTEM.INT64;
BEGIN
  ASSERT(c.handle # 0, 91); CheckRange(LEN(buf), pos, len);
  n := 0;
  IF len = 0 THEN RETURN TRUE END;
  REPEAT r := TlsThin.Write(c.handle, SYSTEM.ADR(buf[pos]), len) UNTIL ~c.Again(r);
  IF r > 0 THEN n := SYSTEM.VAL(LONGINT, r); c.shaken := TRUE; c.error := NIL; RETURN TRUE
  ELSIF ~Want(r) THEN c.error := ContextError(io, c.handle, "write failed")
  END;
  RETURN FALSE
END Write;

(* Writes all len bytes from buf[pos..]; on failure n says how many were
   written. On wouldBlock, call again with pos + n and len - n. *)
PROCEDURE (c: Connection) WriteAll*(buf-: ARRAY OF CHAR; pos, len: LONGINT;
    VAR n: LONGINT): BOOLEAN;
  VAR m: LONGINT;
BEGIN
  ASSERT(c.handle # 0, 91); CheckRange(LEN(buf), pos, len);
  n := 0;
  WHILE n < len DO
    IF ~c.Write(buf, pos + n, len - n, m) THEN RETURN FALSE END;
    INC(n, m)
  END;
  RETURN TRUE
END WriteAll;

(* Sends close_notify, if the handshake was done, and frees the libtls
   connection, leaving the descriptor open; later calls do nothing and
   return TRUE. FALSE (kind io) if close_notify couldn't be sent, as
   when the peer has gone: the connection is freed all the same. libtls
   doesn't wait for the peer's close_notify. On a non-blocking
   descriptor whose buffer is full, FALSE with wouldBlock, and the
   connection stays open: call Close again after waiting, or Discard. *)
PROCEDURE (c: Connection) Close*(): BOOLEAN;
  VAR r: SYSTEM.INT32; ok: BOOLEAN;
BEGIN
  IF c.handle = 0 THEN RETURN TRUE END;
  REPEAT r := TlsThin.Close(c.handle) UNTIL ~c.Again(r);
  IF Want(r) THEN RETURN FALSE END;
  ok := r = 0;
  IF ok THEN c.error := NIL ELSE c.error := ContextError(io, c.handle, "close failed") END;
  c.Free;
  RETURN ok
END Close;

(* Frees the libtls connection without close_notify, leaving the
   descriptor open, as for a peer that is cut off; later calls do
   nothing. The peer sees an end without close_notify, an error. *)
PROCEDURE (c: Connection) Discard*;
BEGIN c.Free
END Discard;

(* --- Connection info (PLAN.md, Phase 7) ---

   What the handshake settled, and the peer's certificate, read from
   libtls while the connection is open, after the handshake: before it
   (Handshake, or a Read or Write, hasn't succeeded) these halt (92), and
   after Close (91). libtls makes them at the end of the handshake and
   frees them with the connection, so the strings are copies, and NIL
   where libtls has none. A certificate a client presents isn't verified
   unless the server's config asks (VerifyClient...), so a Gemini server
   identifies a client by PeerCertHash alone. *)

PROCEDURE (c: Connection) CheckInfo;
BEGIN ASSERT(c.handle # 0, 91); ASSERT(c.shaken, 92)
END CheckInfo;

(* A copy of the C string at adr, or NIL if adr is 0. *)
PROCEDURE CopyOrNil(adr: SYSTEM.ADDRESS): String;
BEGIN IF adr = 0 THEN RETURN NIL ELSE RETURN CopyC(adr) END
END CopyOrNil;

(* Whether the peer presented a certificate; the rest of the PeerCert
   calls give NIL or -1 if not. *)
PROCEDURE (c: Connection) PeerCertProvided*(): BOOLEAN;
BEGIN c.CheckInfo; RETURN TlsThin.PeerCertProvided(c.handle) = 1
END PeerCertProvided;

(* "SHA256:" and the SHA-256 of the peer's certificate (DER), in
   lowercase hex: as a Gemini server knows a client, and a client pins
   a server. *)
PROCEDURE (c: Connection) PeerCertHash*(): String;
BEGIN c.CheckInfo; RETURN CopyOrNil(TlsThin.PeerCertHash(c.handle))
END PeerCertHash;

(* The subject of the peer's certificate, in OpenSSL's one-line form,
   as "/CN=example.org". *)
PROCEDURE (c: Connection) PeerCertSubject*(): String;
BEGIN c.CheckInfo; RETURN CopyOrNil(TlsThin.PeerCertSubject(c.handle))
END PeerCertSubject;

(* The issuer of the peer's certificate, as PeerCertSubject; the same
   as the subject for a self-signed one. *)
PROCEDURE (c: Connection) PeerCertIssuer*(): String;
BEGIN c.CheckInfo; RETURN CopyOrNil(TlsThin.PeerCertIssuer(c.handle))
END PeerCertIssuer;

(* The start of the peer's certificate's validity, in seconds since
   1970-01-01 UTC; -1 if there is none. *)
PROCEDURE (c: Connection) PeerCertNotBefore*(): HUGEINT;
BEGIN c.CheckInfo; RETURN SYSTEM.VAL(HUGEINT, TlsThin.PeerCertNotBefore(c.handle))
END PeerCertNotBefore;

(* The end of the peer's certificate's validity, as PeerCertNotBefore.
   Not checked by libtls when verification is off: a server that cares
   compares it with the time. *)
PROCEDURE (c: Connection) PeerCertNotAfter*(): HUGEINT;
BEGIN c.CheckInfo; RETURN SYSTEM.VAL(HUGEINT, TlsThin.PeerCertNotAfter(c.handle))
END PeerCertNotAfter;

(* Whether the peer's certificate names name, a host name or an IP
   address, in a subject alternative name or, without those, its common
   name; FALSE if there is no certificate. *)
PROCEDURE (c: Connection) PeerCertContainsName*(name: ARRAY OF CHAR): BOOLEAN;
BEGIN c.CheckInfo; RETURN TlsThin.PeerCertContainsName(c.handle, name) = 1
END PeerCertContainsName;

(* The protocol version agreed, as "TLSv1.3". *)
PROCEDURE (c: Connection) Version*(): String;
BEGIN c.CheckInfo; RETURN CopyOrNil(TlsThin.ConnVersion(c.handle))
END Version;

(* The cipher suite agreed, in OpenSSL's naming, as
   "TLS_AES_256_GCM_SHA384". *)
PROCEDURE (c: Connection) Cipher*(): String;
BEGIN c.CheckInfo; RETURN CopyOrNil(TlsThin.ConnCipher(c.handle))
END Cipher;

(* On a server: the name the client asked for by SNI, NIL if it sent
   none (a client connecting by IP address sends none). On a client:
   the servername given to ConnectSocket, NIL for "". *)
PROCEDURE (c: Connection) Servername*(): String;
BEGIN c.CheckInfo; RETURN CopyOrNil(TlsThin.ConnServername(c.handle))
END Servername;

(* --- Deadlines, for TlsTasks --- *)

(* Gives c a deadline ms milliseconds from now, on the monotonic clock,
   or none if ms = 0: TlsTasks' calls on c that would wait past it
   return FALSE with kind timedOut. The deadline stays until it is set
   again, across calls. Halts (98) for a negative ms. *)
PROCEDURE (c: Connection) SetDeadline*(ms: LONGINT);
BEGIN
  ASSERT(c.handle # 0, 91); ASSERT(ms >= 0, 98);
  IF ms = 0 THEN c.deadline := 0
  ELSE c.deadline := SYSTEM.VAL(LONGINT, CNow()) + ms
  END
END SetDeadline;

(* Milliseconds until c's deadline, 0 if it has passed, -1 if c has
   none. *)
PROCEDURE (c: Connection) TimeLeft*(): LONGINT;
  VAR left: LONGINT;
BEGIN
  IF c.deadline = 0 THEN RETURN -1 END;
  left := c.deadline - SYSTEM.VAL(LONGINT, CNow());
  IF left < 0 THEN left := 0 END;
  RETURN left
END TimeLeft;

(* For TlsTasks: a wait on c's descriptor for what (an operation's name)
   passed c's deadline; c.error becomes "<what> timed out", kind
   timedOut. *)
PROCEDURE (c: Connection) TimedOut*(what: ARRAY OF CHAR);
  VAR e: Error; i, j: LONGINT; suffix: ARRAY 12 OF CHAR;
BEGIN
  suffix := " timed out";
  i := 0; WHILE (i < LEN(what)) & (what[i] # 0X) DO INC(i) END;
  NEW(e); e.kind := timedOut; e.want := 0; NEW(e.text, i + LEN(suffix));
  FOR j := 0 TO i - 1 DO e.text[j] := what[j] END;
  j := 0; REPEAT e.text[i + j] := suffix[j]; INC(j) UNTIL suffix[j - 1] = 0X;
  c.error := e
END TimedOut;

PROCEDURE NewWouldBlock(want: INTEGER; text: ARRAY OF CHAR): Error;
  VAR e: Error;
BEGIN e := NewError(wouldBlock, 0, text); e.want := want; RETURN e
END NewWouldBlock;

BEGIN
  ASSERT(TlsThin.Init() = 0, 90);
  wouldRead := NewWouldBlock(wantRead, "would block: wait until readable");
  wouldWrite := NewWouldBlock(wantWrite, "would block: wait until writable")
END Tls.
