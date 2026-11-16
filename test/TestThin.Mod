MODULE TestThin; (* Every TlsThin procedure, with good and bad arguments *)

(* Handshakes run over a non-blocking socket pair from TestPeers, the
   server and client sides in turn in one program: each call that would
   wait returns wantPollIn or wantPollOut, and the loop moves to the
   other side. No Tasks, so this test gets valgrind's memory check.
   Certificates are test/make-certs.sh's, from test/. *)

IMPORT SYSTEM, Check, TlsThin, TestPeers;

CONST
  certs = "../build/certs/";
  maxTurns = 100; (* far more than a handshake's few round trips *)

TYPE String = ARRAY 256 OF CHAR;

VAR crlf: ARRAY 3 OF CHAR;

VAR
  serverCfg, clientCfg, insecureCfg: TlsThin.Config;
  server, client: TlsThin.Context;
  protocols: SYSTEM.INT32;
  s, crt, key: String;

(* The 0X-terminated string at adr, cut to fit, into s; "" for 0. *)
PROCEDURE Get(adr: SYSTEM.ADDRESS; VAR s: ARRAY OF CHAR);
VAR i: LONGINT; c: CHAR;
BEGIN
  i := 0;
  IF adr # 0 THEN
    SYSTEM.GET(adr, c);
    WHILE (c # 0X) & (i < LEN(s) - 1) DO
      s[i] := c; INC(i); SYSTEM.GET(adr + i, c)
    END
  END;
  s[i] := 0X
END Get;

(* a and b, into r. *)
PROCEDURE Cat(a, b: ARRAY OF CHAR; VAR r: ARRAY OF CHAR);
VAR i, j: LONGINT;
BEGIN
  i := 0; WHILE a[i] # 0X DO r[i] := a[i]; INC(i) END;
  j := 0; WHILE b[j] # 0X DO r[i] := b[j]; INC(i); INC(j) END;
  r[i] := 0X
END Cat;

(* The paths of make-certs.sh's pair name, into crt and key. *)
PROCEDURE Pair(name: ARRAY OF CHAR; VAR crt, key: ARRAY OF CHAR);
VAR base: String;
BEGIN Cat(certs, name, base); Cat(base, ".crt", crt); Cat(base, ".key", key)
END Pair;

PROCEDURE Contains(s, part: ARRAY OF CHAR): BOOLEAN;
VAR i, j: LONGINT;
BEGIN
  i := 0;
  WHILE s[i] # 0X DO
    j := 0;
    WHILE (part[j] # 0X) & (s[i + j] = part[j]) DO INC(j) END;
    IF part[j] = 0X THEN RETURN TRUE END;
    INC(i)
  END;
  RETURN part[0] = 0X
END Contains;

PROCEDURE ConfigErrorHas(cfg: TlsThin.Config; part: ARRAY OF CHAR): BOOLEAN;
VAR s: String;
BEGIN Get(TlsThin.ConfigError(cfg), s); RETURN Contains(s, part)
END ConfigErrorHas;

PROCEDURE ErrorHas(ctx: TlsThin.Context; part: ARRAY OF CHAR): BOOLEAN;
VAR s: String;
BEGIN Get(TlsThin.Error(ctx), s); RETURN Contains(s, part)
END ErrorHas;

PROCEDURE Waiting(r: SYSTEM.INT64): BOOLEAN;
BEGIN RETURN (r = TlsThin.wantPollIn) OR (r = TlsThin.wantPollOut)
END Waiting;

(* Both handshakes, each side in turn until both are done. *)
PROCEDURE Handshake(conn, cli: TlsThin.Context): BOOLEAN;
VAR rs, rc: SYSTEM.INT32; n: INTEGER;
BEGIN
  rs := TlsThin.wantPollIn; rc := TlsThin.wantPollIn; n := 0;
  WHILE ((rs # 0) OR (rc # 0)) & (n < maxTurns) DO
    IF rc # 0 THEN rc := TlsThin.Handshake(cli) END;
    IF rs # 0 THEN rs := TlsThin.Handshake(conn) END;
    IF ~Waiting(rs) & (rs # 0) OR ~Waiting(rc) & (rc # 0) THEN n := maxTurns END;
    INC(n)
  END;
  RETURN (rs = 0) & (rc = 0)
END Handshake;

(* Writes text, without its 0X, on from, and reads it on to, into got. *)
PROCEDURE Send(from, to: TlsThin.Context; text: ARRAY OF CHAR; VAR got: ARRAY OF CHAR): BOOLEAN;
VAR w, r: SYSTEM.INT64; len, n: LONGINT;
BEGIN
  len := 0; WHILE text[len] # 0X DO INC(len) END;
  n := 0;
  REPEAT w := TlsThin.Write(from, SYSTEM.ADR(text[0]), len); INC(n)
  UNTIL ~Waiting(w) OR (n > maxTurns);
  IF w # len THEN RETURN FALSE END;
  n := 0;
  REPEAT r := TlsThin.Read(to, SYSTEM.ADR(got[0]), LEN(got) - 1); INC(n)
  UNTIL ~Waiting(r) OR (n > maxTurns);
  IF (r < 0) OR (r >= LEN(got)) THEN RETURN FALSE END;
  got[SYSTEM.VAL(LONGINT, r)] := 0X;
  RETURN TRUE
END Send;

(* Repeats Close on ctx while it waits: close_notify on a non-blocking
   socket may need the peer's to arrive (tls_close(3)). *)
PROCEDURE CloseOn(ctx: TlsThin.Context): SYSTEM.INT32;
VAR r: SYSTEM.INT32; n: INTEGER;
BEGIN
  n := 0;
  REPEAT r := TlsThin.Close(ctx); INC(n) UNTIL ~Waiting(r) OR (n > maxTurns);
  RETURN r
END CloseOn;

(* A connection from server to a client of cfg on a fresh socket pair,
   sending servername; checks the handshake, then each side's view of
   the other, then data both ways, then close_notify. *)
PROCEDURE Connection(cfg: TlsThin.Config; servername, label: ARRAY OF CHAR;
                     clientCert, fds: BOOLEAN);
VAR a, b: LONGINT; conn, cli: TlsThin.Context; got, request, response: String;
  r: SYSTEM.INT64; n: INTEGER; before, after: SYSTEM.INT64;
BEGIN
  Check.Check(TestPeers.Pair(a, b, TRUE), label);
  cli := TlsThin.Client();
  Check.Check(TlsThin.Configure(cli, cfg) = 0, "  client configured");
  conn := 0;
  IF fds THEN
    Check.Check(TlsThin.AcceptFds(server, conn, SYSTEM.VAL(SYSTEM.INT32, a), SYSTEM.VAL(SYSTEM.INT32, a)) = 0, "  AcceptFds");
    Check.Check(TlsThin.ConnectFds(cli, SYSTEM.VAL(SYSTEM.INT32, b), SYSTEM.VAL(SYSTEM.INT32, b), servername) = 0, "  ConnectFds")
  ELSE
    Check.Check(TlsThin.AcceptSocket(server, conn, SYSTEM.VAL(SYSTEM.INT32, a)) = 0, "  AcceptSocket");
    Check.Check(TlsThin.ConnectSocket(cli, SYSTEM.VAL(SYSTEM.INT32, b), servername) = 0, "  ConnectSocket")
  END;
  Check.Check(conn # 0, "  accepting gives a connection");
  Check.Check(Handshake(conn, cli), "  both handshakes finish");

  Get(TlsThin.ConnVersion(conn), s);
  Check.Check(s = "TLSv1.3", "  ConnVersion is TLSv1.3");
  Get(TlsThin.ConnCipher(cli), s);
  Check.Check(s # "", "  ConnCipher");
  IF servername = "" THEN
    Check.Check(TlsThin.ConnServername(conn) = 0, "  ConnServername: none sent")
  ELSE
    Get(TlsThin.ConnServername(conn), s);
    Check.Check(s = servername, "  ConnServername is the name sent")
  END;

  Check.Check(TlsThin.PeerCertProvided(cli) = 1, "  the client has the server's certificate");
  IF servername # "" THEN
    Check.Check(TlsThin.PeerCertContainsName(cli, servername) = 1, "  and it is for the name sent")
  END;
  Check.Check(TlsThin.PeerCertContainsName(cli, "nowhere.example") = 0, "  and not for another");
  IF clientCert THEN
    Check.Check(TlsThin.PeerCertProvided(conn) = 1, "  the server has the client's certificate");
    Get(TlsThin.PeerCertHash(conn), s);
    Check.Check(Contains(s, "SHA256:") & (s[71] = 0X) & (s[70] # 0X), "  PeerCertHash is SHA256: and 64 digits");
    Get(TlsThin.PeerCertSubject(conn), s);
    Check.Check(Contains(s, "polibtls test client1"), "  PeerCertSubject");
    Get(TlsThin.PeerCertIssuer(conn), s);
    Check.Check(Contains(s, "polibtls test client1"), "  PeerCertIssuer: self-signed");
    before := TlsThin.PeerCertNotBefore(conn); after := TlsThin.PeerCertNotAfter(conn);
    (* 2026-01-01 and 9 years on: make-certs.sh makes 10-year ones. *)
    Check.Check((before > 1767225600) & (after - before > 9 * 365 * 86400), "  PeerCertNotBefore and NotAfter")
  ELSE
    Check.Check(TlsThin.PeerCertProvided(conn) = 0, "  the server has no client certificate");
    Check.Check(TlsThin.PeerCertHash(conn) = 0, "  PeerCertHash: none");
    Check.Check(TlsThin.PeerCertNotBefore(conn) = -1, "  PeerCertNotBefore: -1")
  END;

  Cat("gemini://localhost/", crlf, request);
  Check.Check(Send(cli, conn, request, got) & (got = request), "  Write by the client, Read by the server");
  Cat("20 text/gemini", crlf, response);
  Check.Check(Send(conn, cli, response, got) & (got = response), "  Write by the server, Read by the client");

  Check.Check(CloseOn(conn) # -1, "  Close by the server");
  n := 0;
  REPEAT r := TlsThin.Read(cli, SYSTEM.ADR(got[0]), LEN(got)); INC(n) UNTIL ~Waiting(r) OR (n > maxTurns);
  Check.Check(r = 0, "  the client reads end of data");
  Check.Check(CloseOn(cli) = 0, "  Close by the client");

  TlsThin.Free(conn); TlsThin.Free(cli);
  Check.Check(TestPeers.Close(a) & TestPeers.Close(b), "  the descriptors were still open")
END Connection;

(* A write to a peer that has gone fails, with SIGPIPE ignored, and
   the error text says why. errno can't: libtls sets it to 0 on leaving
   tls_write (PLAN.md, "Errors"). *)
PROCEDURE GonePeer;
VAR a, b: LONGINT; conn, cli: TlsThin.Context; w: SYSTEM.INT64; n: INTEGER;
BEGIN
  Check.Check(TestPeers.Pair(a, b, TRUE), "a peer that goes");
  cli := TlsThin.Client();
  Check.Check(TlsThin.Configure(cli, insecureCfg) = 0, "  client configured");
  Check.Check(TlsThin.AcceptSocket(server, conn, SYSTEM.VAL(SYSTEM.INT32, a)) = 0, "  AcceptSocket");
  Check.Check(TlsThin.ConnectSocket(cli, SYSTEM.VAL(SYSTEM.INT32, b), "localhost") = 0, "  ConnectSocket");
  Check.Check(Handshake(conn, cli), "  both handshakes finish");
  TlsThin.Free(cli);
  Check.Check(TestPeers.Close(b), "  the client's descriptor closed");
  n := 0;
  REPEAT w := TlsThin.Write(conn, SYSTEM.ADR(crlf[0]), 2); INC(n)
  UNTIL ~Waiting(w) OR (n > maxTurns);
  Check.Check(w = -1, "  Write fails");
  Check.Check(ErrorHas(conn, "Broken pipe"), "  Error says so");
  TlsThin.Free(conn);
  Check.Check(TestPeers.Close(a), "  the server's descriptor was still open")
END GonePeer;

PROCEDURE Config(VAR cfg: TlsThin.Config);
BEGIN cfg := TlsThin.ConfigNew(); Check.Check(cfg # 0, "ConfigNew")
END Config;

BEGIN
  crlf[0] := 0DX; crlf[1] := 0AX; crlf[2] := 0X;
  TestPeers.IgnoreBrokenPipe;

  Check.Check(TlsThin.api = 20200120, "api is TLS_API");
  Check.Check((TlsThin.wantPollIn = -2) & (TlsThin.wantPollOut = -3), "wantPollIn and wantPollOut");
  Check.Check((TlsThin.protocolTLSv12 = 8) & (TlsThin.protocolTLSv13 = 16), "the protocol bits");
  Check.Check((TlsThin.protocolsAll = 24) & (TlsThin.protocolsDefault = 24), "protocolsAll and protocolsDefault");
  Check.Check(TlsThin.Init() = 0, "Init again does no harm");

  (* Protocols *)
  Check.Check((TlsThin.ConfigParseProtocols(protocols, "tlsv1.3") = 0) & (protocols = 16), "ConfigParseProtocols tlsv1.3");
  Check.Check((TlsThin.ConfigParseProtocols(protocols, "secure") = 0) & (protocols = 24), "ConfigParseProtocols secure");
  Check.Check(TlsThin.ConfigParseProtocols(protocols, "tlsv9") = -1, "ConfigParseProtocols rejects tlsv9");

  (* The server's config: bad arguments first, each leaving error text. *)
  Config(serverCfg);
  Check.Check(TlsThin.ConfigError(serverCfg) = 0, "a new config has no error");
  Pair("self-ec", crt, key);
  Check.Check(TlsThin.ConfigSetKeypairFile(serverCfg, "/nonexistent.crt", key) = -1, "ConfigSetKeypairFile with no certificate file");
  Check.Check(ConfigErrorHas(serverCfg, "/nonexistent.crt"), "  ConfigError names it");
  Check.Check(TlsThin.ConfigSetCaFile(serverCfg, "/nonexistent-ca.crt") = -1, "ConfigSetCaFile with no file");
  Check.Check(ConfigErrorHas(serverCfg, "/nonexistent-ca.crt"), "  ConfigError names it");
  Check.Check(TlsThin.ConfigSetCiphers(serverCfg, "no-such-cipher") = -1, "ConfigSetCiphers with no such cipher");
  Check.Check(ConfigErrorHas(serverCfg, "no-such-cipher"), "  ConfigError names it");
  Check.Check(TlsThin.ConfigSetProtocols(serverCfg, TlsThin.protocolsDefault) = 0, "ConfigSetProtocols");
  Check.Check(ConfigErrorHas(serverCfg, "no-such-cipher"), "  a success leaves the error text");
  Check.Check(TlsThin.ConfigSetCiphers(serverCfg, "secure") = 0, "ConfigSetCiphers secure");
  Check.Check(TlsThin.ConfigSetKeypairFile(serverCfg, crt, key) = 0, "ConfigSetKeypairFile");
  Pair("other-rsa", crt, key);
  Check.Check(TlsThin.ConfigAddKeypairFile(serverCfg, crt, key) = 0, "ConfigAddKeypairFile");
  TlsThin.ConfigVerifyClientOptional(serverCfg);
  TlsThin.ConfigInsecureNoVerifyCert(serverCfg);

  server := TlsThin.Server();
  Check.Check(server # 0, "Server");
  Check.Check(TlsThin.Error(server) = 0, "a new context has no error");
  Check.Check(TlsThin.Configure(server, serverCfg) = 0, "Configure the server");
  TlsThin.ConfigClearKeys(serverCfg);
  TlsThin.ConfigFree(serverCfg); (* the server keeps a reference *)

  (* A client that verifies the server against the CA and sends a
     certificate; its server here is self-signed, so that one is given
     as the CA file. *)
  Config(clientCfg);
  Pair("self-ec", crt, key);
  Check.Check(TlsThin.ConfigSetCaFile(clientCfg, crt) = 0, "ConfigSetCaFile");
  Pair("client1-ec", crt, key);
  Check.Check(TlsThin.ConfigSetKeypairFile(clientCfg, crt, key) = 0, "a client's ConfigSetKeypairFile");
  Check.Check((TlsThin.ConfigParseProtocols(protocols, "tlsv1.3") = 0)
    & (TlsThin.ConfigSetProtocols(clientCfg, protocols) = 0), "ConfigSetProtocols tlsv1.3");

  (* A client that verifies nothing, for the other names. *)
  Config(insecureCfg);
  TlsThin.ConfigInsecureNoVerifyCert(insecureCfg);
  TlsThin.ConfigInsecureNoVerifyName(insecureCfg);
  TlsThin.ConfigInsecureNoVerifyTime(insecureCfg);

  (* The wrong kind of context *)
  client := TlsThin.Client();
  Check.Check(TlsThin.Configure(client, clientCfg) = 0, "Configure a client");
  Check.Check(TlsThin.ConnectSocket(server, 0, "localhost") = -1, "ConnectSocket on a server context fails");
  Check.Check(ErrorHas(server, "not a client context"), "  Error says why");
  s := "";
  Check.Check(TlsThin.Read(server, SYSTEM.ADR(s[0]), LEN(s)) = -1, "Read on a server context fails");
  Check.Check(TlsThin.Error(server) # 0, "  Error says why");
  TlsThin.Free(client);

  Connection(clientCfg, "localhost", "a verified connection with a client certificate", TRUE, FALSE);
  Connection(insecureCfg, "other.example", "SNI: other.example", FALSE, FALSE);
  Connection(insecureCfg, "", "no server name, by AcceptFds and ConnectFds", FALSE, TRUE);
  GonePeer;

  TlsThin.ConfigFree(clientCfg); TlsThin.ConfigFree(insecureCfg);
  TlsThin.Free(server);
  Check.Summary
END TestThin.
