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
   (PLAN.md, "Errors"). Contexts and connections come in Phase 4. *)

IMPORT SYSTEM, GarbageCollectedHeap, TlsThin;

CONST
  (* Error kinds *)
  config* = 1;     (* a Config setter: a missing or malformed file, a bad string *)
  handshake* = 2;  (* Phase 4 *)
  io* = 3;         (* Phase 4 *)
  closed* = 4;     (* Phase 4 *)

TYPE
  String* = POINTER TO ARRAY OF CHAR;  (* always 0X-terminated *)

  Error* = POINTER TO ErrorDesc;
  ErrorDesc* = RECORD
    kind-: INTEGER;  (* one of the kinds above *)
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
  NEW(e); e.kind := kind;
  IF adr # 0 THEN e.text := CopyC(adr) ELSE e.text := NewString(fallback) END;
  RETURN e
END NewError;

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

BEGIN
  ASSERT(TlsThin.Init() = 0, 90)
END Tls.
