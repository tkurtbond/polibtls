MODULE TlsThin; (* libtls, one to one: the thin layer under Tls *)

(* Each libtls function is an unexported ["C"] procedure wrapped in an
   exported Oberon one, so the thick layer, Tls, never names a C symbol.
   No ownership or error policy here: that is Tls's.

   Types cross with explicit widths, so this module means the same under
   -OC or -O2: SYSTEM.INT32 for int (descriptors too) and uint32_t (the
   protocol bits, which fit in 31), SYSTEM.ADDRESS for pointers and
   size_t, except a buffer's length: ssize_t and time_t vary in width
   (ssize_t is 32 bits on i386), and a LONGINT length isn't assignable
   to a 32-bit ADDRESS, so tls_read and tls_write, and the two functions
   returning a time_t, go through the C part, TlsThin.c, which takes the
   length and returns the result as int64_t, SYSTEM.INT64 here (as
   posockets does, for the same reason).

   Strings: an ARRAY OF CHAR argument reaches libtls as a const char *,
   and must hold a 0X, which the caller ensures. libtls copies every
   string it is given here or reads it only during the call (LibreTLS
   3.8.1's source: file names are loaded at once, ciphers and the server
   name strdup'd), so a value parameter's copy in the wrapper's frame is
   enough. A string libtls returns comes back as its address, 0 for
   NULL; libtls owns it and may free it on the next call on the same
   object, so the caller copies it at once.

   Results: 0 for success and -1 for failure unless said otherwise;
   tls_error or tls_config_error then has the text, which is all there
   is: libtls sets errno to 0 on leaving tls_handshake, tls_read,
   tls_write and tls_close, so errno isn't bound. *)

IMPORT SYSTEM;

TYPE
  Config* = SYSTEM.ADDRESS;   (* struct tls_config * *)
  Context* = SYSTEM.ADDRESS;  (* struct tls *, a context or a connection *)

VAR
  (* tls.h's values, from the C part, set by the body. *)
  api-: SYSTEM.INT32;              (* TLS_API *)
  wantPollIn-: SYSTEM.INT32;       (* TLS_WANT_POLLIN *)
  wantPollOut-: SYSTEM.INT32;      (* TLS_WANT_POLLOUT *)
  protocolTLSv12-: SYSTEM.INT32;   (* TLS_PROTOCOL_TLSv1_2 *)
  protocolTLSv13-: SYSTEM.INT32;   (* TLS_PROTOCOL_TLSv1_3 *)
  protocolsAll-: SYSTEM.INT32;     (* TLS_PROTOCOLS_ALL *)
  protocolsDefault-: SYSTEM.INT32; (* TLS_PROTOCOLS_DEFAULT *)

PROCEDURE ["C", "TlsThin.-constant"] CConstant(which: SYSTEM.INT32): SYSTEM.INT32;

PROCEDURE ["C", "tls_init"] CInit(): SYSTEM.INT32;

PROCEDURE ["C", "tls_config_new"] CConfigNew(): Config;
PROCEDURE ["C", "tls_config_free"] CConfigFree(config: Config);
PROCEDURE ["C", "tls_config_error"] CConfigError(config: Config): SYSTEM.ADDRESS;
PROCEDURE ["C", "tls_config_set_keypair_file"] CConfigSetKeypairFile(config: Config; certFile, keyFile: ARRAY OF CHAR): SYSTEM.INT32;
PROCEDURE ["C", "tls_config_add_keypair_file"] CConfigAddKeypairFile(config: Config; certFile, keyFile: ARRAY OF CHAR): SYSTEM.INT32;
PROCEDURE ["C", "tls_config_set_ca_file"] CConfigSetCaFile(config: Config; caFile: ARRAY OF CHAR): SYSTEM.INT32;
PROCEDURE ["C", "tls_config_parse_protocols"] CConfigParseProtocols(VAR protocols: SYSTEM.INT32; protostr: ARRAY OF CHAR): SYSTEM.INT32;
PROCEDURE ["C", "tls_config_set_protocols"] CConfigSetProtocols(config: Config; protocols: SYSTEM.INT32): SYSTEM.INT32;
PROCEDURE ["C", "tls_config_set_ciphers"] CConfigSetCiphers(config: Config; ciphers: ARRAY OF CHAR): SYSTEM.INT32;
PROCEDURE ["C", "tls_config_verify_client_optional"] CConfigVerifyClientOptional(config: Config);
PROCEDURE ["C", "tls_config_insecure_noverifycert"] CConfigInsecureNoVerifyCert(config: Config);
PROCEDURE ["C", "tls_config_insecure_noverifyname"] CConfigInsecureNoVerifyName(config: Config);
PROCEDURE ["C", "tls_config_insecure_noverifytime"] CConfigInsecureNoVerifyTime(config: Config);
PROCEDURE ["C", "tls_config_clear_keys"] CConfigClearKeys(config: Config);

PROCEDURE ["C", "tls_server"] CServer(): Context;
PROCEDURE ["C", "tls_client"] CClient(): Context;
PROCEDURE ["C", "tls_configure"] CConfigure(ctx: Context; config: Config): SYSTEM.INT32;
PROCEDURE ["C", "tls_free"] CFree(ctx: Context);
PROCEDURE ["C", "tls_error"] CError(ctx: Context): SYSTEM.ADDRESS;

PROCEDURE ["C", "tls_accept_socket"] CAcceptSocket(ctx: Context; VAR cctx: Context; s: SYSTEM.INT32): SYSTEM.INT32;
PROCEDURE ["C", "tls_accept_fds"] CAcceptFds(ctx: Context; VAR cctx: Context; fdRead, fdWrite: SYSTEM.INT32): SYSTEM.INT32;
PROCEDURE ["C", "tls_connect_socket"] CConnectSocket(ctx: Context; s: SYSTEM.INT32; servername: SYSTEM.ADDRESS): SYSTEM.INT32;
PROCEDURE ["C", "tls_connect_fds"] CConnectFds(ctx: Context; fdRead, fdWrite: SYSTEM.INT32; servername: SYSTEM.ADDRESS): SYSTEM.INT32;
PROCEDURE ["C", "tls_handshake"] CHandshake(ctx: Context): SYSTEM.INT32;
PROCEDURE ["C", "TlsThin.-read"] CRead(ctx: Context; buf: SYSTEM.ADDRESS; buflen: SYSTEM.INT64): SYSTEM.INT64;
PROCEDURE ["C", "TlsThin.-write"] CWrite(ctx: Context; buf: SYSTEM.ADDRESS; buflen: SYSTEM.INT64): SYSTEM.INT64;
PROCEDURE ["C", "tls_close"] CClose(ctx: Context): SYSTEM.INT32;

PROCEDURE ["C", "tls_peer_cert_provided"] CPeerCertProvided(ctx: Context): SYSTEM.INT32;
PROCEDURE ["C", "tls_peer_cert_contains_name"] CPeerCertContainsName(ctx: Context; name: ARRAY OF CHAR): SYSTEM.INT32;
PROCEDURE ["C", "tls_peer_cert_hash"] CPeerCertHash(ctx: Context): SYSTEM.ADDRESS;
PROCEDURE ["C", "tls_peer_cert_subject"] CPeerCertSubject(ctx: Context): SYSTEM.ADDRESS;
PROCEDURE ["C", "tls_peer_cert_issuer"] CPeerCertIssuer(ctx: Context): SYSTEM.ADDRESS;
PROCEDURE ["C", "tls_peer_cert_chain_pem"] CPeerCertChainPem(ctx: Context; VAR size: SYSTEM.ADDRESS): SYSTEM.ADDRESS;
PROCEDURE ["C", "TlsThin.-notbefore"] CPeerCertNotBefore(ctx: Context): SYSTEM.INT64;
PROCEDURE ["C", "TlsThin.-notafter"] CPeerCertNotAfter(ctx: Context): SYSTEM.INT64;
PROCEDURE ["C", "tls_conn_version"] CConnVersion(ctx: Context): SYSTEM.ADDRESS;
PROCEDURE ["C", "tls_conn_cipher"] CConnCipher(ctx: Context): SYSTEM.ADDRESS;
PROCEDURE ["C", "tls_conn_servername"] CConnServername(ctx: Context): SYSTEM.ADDRESS;

PROCEDURE Init*(): SYSTEM.INT32;
BEGIN RETURN CInit()
END Init;

(* Configuration *)

(* A new config, or 0 when out of memory. *)
PROCEDURE ConfigNew*(): Config;
BEGIN RETURN CConfigNew()
END ConfigNew;

(* Drops a reference: libtls frees the config when no context holds
   one (PLAN.md, Phase 0). *)
PROCEDURE ConfigFree*(config: Config);
BEGIN CConfigFree(config)
END ConfigFree;

(* The address of the config's last error text, 0 for none. It stays
   until the next failing call on config; successes don't clear it. *)
PROCEDURE ConfigError*(config: Config): SYSTEM.ADDRESS;
BEGIN RETURN CConfigError(config)
END ConfigError;

PROCEDURE ConfigSetKeypairFile*(config: Config; certFile, keyFile: ARRAY OF CHAR): SYSTEM.INT32;
BEGIN RETURN CConfigSetKeypairFile(config, certFile, keyFile)
END ConfigSetKeypairFile;

(* Another key pair, chosen by SNI. *)
PROCEDURE ConfigAddKeypairFile*(config: Config; certFile, keyFile: ARRAY OF CHAR): SYSTEM.INT32;
BEGIN RETURN CConfigAddKeypairFile(config, certFile, keyFile)
END ConfigAddKeypairFile;

PROCEDURE ConfigSetCaFile*(config: Config; caFile: ARRAY OF CHAR): SYSTEM.INT32;
BEGIN RETURN CConfigSetCaFile(config, caFile)
END ConfigSetCaFile;

(* Parses a protocol list such as "tlsv1.3" or "secure" into protocol
   bits. On failure it sets no error text anywhere. *)
PROCEDURE ConfigParseProtocols*(VAR protocols: SYSTEM.INT32; protostr: ARRAY OF CHAR): SYSTEM.INT32;
BEGIN RETURN CConfigParseProtocols(protocols, protostr)
END ConfigParseProtocols;

PROCEDURE ConfigSetProtocols*(config: Config; protocols: SYSTEM.INT32): SYSTEM.INT32;
BEGIN RETURN CConfigSetProtocols(config, protocols)
END ConfigSetProtocols;

PROCEDURE ConfigSetCiphers*(config: Config; ciphers: ARRAY OF CHAR): SYSTEM.INT32;
BEGIN RETURN CConfigSetCiphers(config, ciphers)
END ConfigSetCiphers;

PROCEDURE ConfigVerifyClientOptional*(config: Config);
BEGIN CConfigVerifyClientOptional(config)
END ConfigVerifyClientOptional;

PROCEDURE ConfigInsecureNoVerifyCert*(config: Config);
BEGIN CConfigInsecureNoVerifyCert(config)
END ConfigInsecureNoVerifyCert;

PROCEDURE ConfigInsecureNoVerifyName*(config: Config);
BEGIN CConfigInsecureNoVerifyName(config)
END ConfigInsecureNoVerifyName;

PROCEDURE ConfigInsecureNoVerifyTime*(config: Config);
BEGIN CConfigInsecureNoVerifyTime(config)
END ConfigInsecureNoVerifyTime;

(* Erases the private keys config holds; safe after tls_configure. *)
PROCEDURE ConfigClearKeys*(config: Config);
BEGIN CConfigClearKeys(config)
END ConfigClearKeys;

(* Contexts *)

(* A new server or client context, or 0 when out of memory. *)
PROCEDURE Server*(): Context;
BEGIN RETURN CServer()
END Server;

PROCEDURE Client*(): Context;
BEGIN RETURN CClient()
END Client;

PROCEDURE Configure*(ctx: Context; config: Config): SYSTEM.INT32;
BEGIN RETURN CConfigure(ctx, config)
END Configure;

(* Frees a context or connection; never closes its descriptors. *)
PROCEDURE Free*(ctx: Context);
BEGIN CFree(ctx)
END Free;

(* The address of ctx's last error text, 0 for none. It stays until
   the next failing call on ctx, or the entry to Handshake, Read, Write
   or Close; other successes don't clear it. *)
PROCEDURE Error*(ctx: Context): SYSTEM.ADDRESS;
BEGIN RETURN CError(ctx)
END Error;

(* Connections *)

(* A connection on socket s from server context ctx, in cctx. *)
PROCEDURE AcceptSocket*(ctx: Context; VAR cctx: Context; s: SYSTEM.INT32): SYSTEM.INT32;
BEGIN RETURN CAcceptSocket(ctx, cctx, s)
END AcceptSocket;

PROCEDURE AcceptFds*(ctx: Context; VAR cctx: Context; fdRead, fdWrite: SYSTEM.INT32): SYSTEM.INT32;
BEGIN RETURN CAcceptFds(ctx, cctx, fdRead, fdWrite)
END AcceptFds;

(* Starts a client context ctx on socket s. servername is the name to
   verify and send by SNI; "" sends none and verifies no name (libtls's
   NULL). *)
PROCEDURE ConnectSocket*(ctx: Context; s: SYSTEM.INT32; servername: ARRAY OF CHAR): SYSTEM.INT32;
BEGIN
  IF servername[0] = 0X THEN RETURN CConnectSocket(ctx, s, 0)
  ELSE RETURN CConnectSocket(ctx, s, SYSTEM.ADR(servername))
  END
END ConnectSocket;

PROCEDURE ConnectFds*(ctx: Context; fdRead, fdWrite: SYSTEM.INT32; servername: ARRAY OF CHAR): SYSTEM.INT32;
BEGIN
  IF servername[0] = 0X THEN RETURN CConnectFds(ctx, fdRead, fdWrite, 0)
  ELSE RETURN CConnectFds(ctx, fdRead, fdWrite, SYSTEM.ADR(servername))
  END
END ConnectFds;

(* Handshake, Read, Write and Close may also return wantPollIn or
   wantPollOut, even on a blocking descriptor (PLAN.md, "I/O"): the
   same call must then be repeated with the same arguments. *)
PROCEDURE Handshake*(ctx: Context): SYSTEM.INT32;
BEGIN RETURN CHandshake(ctx)
END Handshake;

(* Up to buflen bytes into buf: the number read, 0 at end of data,
   -1, wantPollIn or wantPollOut. *)
PROCEDURE Read*(ctx: Context; buf: SYSTEM.ADDRESS; buflen: SYSTEM.INT64): SYSTEM.INT64;
BEGIN RETURN CRead(ctx, buf, buflen)
END Read;

(* Up to buflen bytes from buf: the number written, -1, wantPollIn or
   wantPollOut. *)
PROCEDURE Write*(ctx: Context; buf: SYSTEM.ADDRESS; buflen: SYSTEM.INT64): SYSTEM.INT64;
BEGIN RETURN CWrite(ctx, buf, buflen)
END Write;

(* Sends close_notify; leaves the descriptors open. *)
PROCEDURE Close*(ctx: Context): SYSTEM.INT32;
BEGIN RETURN CClose(ctx)
END Close;

(* The peer and the connection, after the handshake *)

(* 1 if the peer gave a certificate, else 0. *)
PROCEDURE PeerCertProvided*(ctx: Context): SYSTEM.INT32;
BEGIN RETURN CPeerCertProvided(ctx)
END PeerCertProvided;

(* 1 if the peer's certificate is valid for name, else 0. *)
PROCEDURE PeerCertContainsName*(ctx: Context; name: ARRAY OF CHAR): SYSTEM.INT32;
BEGIN RETURN CPeerCertContainsName(ctx, name)
END PeerCertContainsName;

(* "SHA256:" and the hash in lowercase hex. *)
PROCEDURE PeerCertHash*(ctx: Context): SYSTEM.ADDRESS;
BEGIN RETURN CPeerCertHash(ctx)
END PeerCertHash;

(* The peer's certificate chain in PEM, its own certificate first, size
   bytes and no 0X; 0 if it gave none. libtls's, freed with ctx. *)
PROCEDURE PeerCertChainPem*(ctx: Context; VAR size: SYSTEM.ADDRESS): SYSTEM.ADDRESS;
BEGIN RETURN CPeerCertChainPem(ctx, size)
END PeerCertChainPem;

PROCEDURE PeerCertSubject*(ctx: Context): SYSTEM.ADDRESS;
BEGIN RETURN CPeerCertSubject(ctx)
END PeerCertSubject;

PROCEDURE PeerCertIssuer*(ctx: Context): SYSTEM.ADDRESS;
BEGIN RETURN CPeerCertIssuer(ctx)
END PeerCertIssuer;

(* Seconds since the epoch, or -1. *)
PROCEDURE PeerCertNotBefore*(ctx: Context): SYSTEM.INT64;
BEGIN RETURN CPeerCertNotBefore(ctx)
END PeerCertNotBefore;

PROCEDURE PeerCertNotAfter*(ctx: Context): SYSTEM.INT64;
BEGIN RETURN CPeerCertNotAfter(ctx)
END PeerCertNotAfter;

PROCEDURE ConnVersion*(ctx: Context): SYSTEM.ADDRESS;
BEGIN RETURN CConnVersion(ctx)
END ConnVersion;

PROCEDURE ConnCipher*(ctx: Context): SYSTEM.ADDRESS;
BEGIN RETURN CConnCipher(ctx)
END ConnCipher;

(* The name the client sent by SNI, on a server's connection. *)
PROCEDURE ConnServername*(ctx: Context): SYSTEM.ADDRESS;
BEGIN RETURN CConnServername(ctx)
END ConnServername;

BEGIN
  api := CConstant(0);
  wantPollIn := CConstant(1);
  wantPollOut := CConstant(2);
  protocolTLSv12 := CConstant(3);
  protocolTLSv13 := CConstant(4);
  protocolsAll := CConstant(5);
  protocolsDefault := CConstant(6)
END TlsThin.
