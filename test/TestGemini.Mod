MODULE TestGemini; (* The Gemini examples, against each other and other peers *)

(* Runs examples/GeminiHello, the server, on port 0 of every local
   address, and makes requests of it, each a child process: with
   examples/GeminiFetch, verifying the server by CA, by address on
   127.0.0.1 and ::1, with and without a client certificate, and pinning
   it, by the right fingerprint and a wrong one; with openssl s_client;
   and, each if there is one, with OpenBSD's nc, which uses libtls,
   gemget, a Gemini client in Go, whose TLS is Go's own, and gnutls-cli,
   GnuTLS's: TLS stacks other than OpenSSL. Then the server's log must
   name each request and client certificate.

   Then GeminiFetch against servers that end a response without TLS
   close_notify, openssl s_server and nc -N: it must print what came and
   fail, since an end without close_notify may be an attacker cutting the
   response short (PLAN.md, Phase 8).

   nc is the first of $LIBTLS_NC, netcat and nc that is linked with
   libtls (Fedora's netcat package installs OpenBSD's nc as netcat; nc
   may be nmap's ncat, which uses OpenSSL); gemget is $GEMGET or gemget,
   gnutls-cli $GNUTLS_CLI or gnutls-cli, on PATH. Without one, its checks
   are skipped, saying so. Every server is started under timeout(1), so a
   failure here never leaves the test waiting for ever. The examples and
   certificates are the build's, from test/. *)

IMPORT Out, Check, TestPeers;

CONST
  certs = "../build/certs/";
  hello = "exec timeout 60 ../build/GeminiHello";
  fetch = "exec ../build/GeminiFetch";
  LineWait = 10000;  (* ms for a server's next line of output *)
  CR = 0DX; LF = 0AX;

TYPE Text = ARRAY 512 OF CHAR;

VAR
  got, log: ARRAY 65536 OF CHAR;
  logLen, gotLen: LONGINT;  (* log's length; Fetch's output's *)
  nc: Text;             (* a libtls nc, or "" *)
  gemget, gnutlsCli: Text;  (* or "" *)
  port: LONGINT;        (* GeminiHello's *)
  serverHash, client1Hash, client1RsaHash, client2Hash, client2EcHash,
  selfEcHash, selfRsaHash: Text;
  cmd: Text; i: LONGINT;

PROCEDURE Append(VAR s: ARRAY OF CHAR; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0; WHILE part[j] # 0X DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

PROCEDURE AppendInt(VAR s: ARRAY OF CHAR; VAR i: LONGINT; n: LONGINT);
  VAR d: ARRAY 24 OF CHAR; k: LONGINT;
BEGIN
  k := 0; REPEAT d[k] := CHR(ORD("0") + n MOD 10); n := n DIV 10; INC(k) UNTIL n = 0;
  WHILE k > 0 DO DEC(k); s[i] := d[k]; INC(i) END;
  s[i] := 0X
END AppendInt;

PROCEDURE Length(s: ARRAY OF CHAR): LONGINT;
  VAR n: LONGINT;
BEGIN n := 0; WHILE s[n] # 0X DO INC(n) END; RETURN n
END Length;

(* got[0..n-1] contains s *)
PROCEDURE Has(VAR got: ARRAY OF CHAR; n: LONGINT; s: ARRAY OF CHAR): BOOLEAN;
  VAR i, j, m: LONGINT;
BEGIN
  m := Length(s); i := 0;
  WHILE i + m <= n DO
    j := 0; WHILE (j < m) & (got[i + j] = s[j]) DO INC(j) END;
    IF j = m THEN RETURN TRUE END;
    INC(i)
  END;
  RETURN FALSE
END Has;

(* s begins with prefix *)
PROCEDURE Begins(s, prefix: ARRAY OF CHAR): BOOLEAN;
  VAR i: LONGINT;
BEGIN
  i := 0; WHILE (prefix[i] # 0X) & (s[i] = prefix[i]) DO INC(i) END;
  RETURN prefix[i] = 0X
END Begins;

(* The number that ends line, before its newline: the port in "port N",
   "Listening on localhost N" and "ACCEPT 127.0.0.1:N"; -1 if none. *)
PROCEDURE LastNumber(line: ARRAY OF CHAR): LONGINT;
  VAR i, n, f: LONGINT;
BEGIN
  i := Length(line);
  WHILE (i > 0) & (line[i - 1] <= " ") DO DEC(i) END;
  n := 0; f := 1;
  WHILE (i > 0) & ("0" <= line[i - 1]) & (line[i - 1] <= "9") & (f <= 10000) DO
    DEC(i); INC(n, (ORD(line[i]) - ORD("0")) * f); f := f * 10
  END;
  IF f = 1 THEN RETURN -1 ELSE RETURN n END
END LastNumber;

(* Runs command, with input and then end of file, to its end: its exit
   status (-1 if it couldn't start or didn't exit) and its output,
   standard error included, in got[0..n-1]. *)
PROCEDURE Run(command, input: ARRAY OF CHAR; VAR n: LONGINT): INTEGER;
  VAR c: TestPeers.Child;
BEGIN
  n := 0;
  IF ~TestPeers.Spawn(command, input, Length(input), c) THEN RETURN -1 END;
  RETURN TestPeers.Wait(c, got, n)
END Run;

(* The fingerprint libtls gives of certificate name, by cert-info.sh. *)
PROCEDURE Hash(name: ARRAY OF CHAR; VAR h: Text);
  VAR cmd: Text; i, n: LONGINT;
BEGIN
  i := 0; Append(cmd, i, "sh cert-info.sh "); Append(cmd, i, certs); Append(cmd, i, name);
  Append(cmd, i, ".crt");
  h := "";
  IF Run(cmd, "", n) = 0 THEN
    i := 0; WHILE (i < n) & (i < LEN(h) - 1) & (got[i] # LF) DO h[i] := got[i]; INC(i) END;
    h[i] := 0X
  END;
  i := 0; Append(cmd, i, "cert-info.sh: the fingerprint of "); Append(cmd, i, name);
  Check.Check(Begins(h, "SHA256:"), cmd)
END Hash;

(* The program that script, a shell command, prints, or "" if it exits
   nonzero. *)
PROCEDURE Find(script: ARRAY OF CHAR; VAR path: Text);
  VAR n, i: LONGINT;
BEGIN
  path := "";
  IF Run(script, "", n) = 0 THEN
    i := 0; WHILE (i < n) & (i < LEN(path) - 1) & (got[i] # LF) DO path[i] := got[i]; INC(i) END;
    path[i] := 0X
  END
END Find;

(* Says which program will be used as name, or that its checks are
   skipped, and how to give one. *)
PROCEDURE Found(name, path, how: ARRAY OF CHAR);
BEGIN
  IF path = "" THEN
    Out.String("skip - "); Out.String(name); Out.String(": not found ("); Out.String(how);
    Out.String(")")
  ELSE
    Out.String("# "); Out.String(name); Out.String(": "); Out.String(path)
  END;
  Out.Ln
END Found;

(* Runs cmd, giving it input, a client of GeminiHello: it must exit 0
   with output containing has1 and has2. *)
PROCEDURE Client(label, cmd, input, has1, has2: ARRAY OF CHAR);
  VAR n: LONGINT; s: INTEGER; ok: BOOLEAN;
BEGIN
  s := Run(cmd, input, n);
  IF n > LEN(got) - 1 THEN n := LEN(got) - 1 END;
  ok := (s = 0) & Has(got, n, has1) & Has(got, n, has2);
  Check.Check(ok, label);
  IF ~ok THEN
    Out.String("  exit "); Out.Int(s, 0); Out.String(", output: "); got[n] := 0X; Out.String(got); Out.Ln
  END
END Client;

(* The request line url CR LF *)
PROCEDURE Request(url: ARRAY OF CHAR; VAR r: Text);
  VAR i: LONGINT;
BEGIN
  COPY(url, r); i := Length(r); r[i] := CR; r[i + 1] := LF; r[i + 2] := 0X
END Request;

(* "gemini://" + host + ":" + port + path *)
PROCEDURE Url(host: ARRAY OF CHAR; port: LONGINT; path: ARRAY OF CHAR; VAR u: Text);
  VAR i: LONGINT;
BEGIN
  i := 0; Append(u, i, "gemini://"); Append(u, i, host); Append(u, i, ":");
  AppendInt(u, i, port); Append(u, i, path)
END Url;

(* Reads a server's output until a line beginning with prefix, at most
   lines lines: the number at its end, or -1. *)
PROCEDURE ServerPort(VAR c: TestPeers.Child; prefix: ARRAY OF CHAR; lines: INTEGER): LONGINT;
  VAR line: Text;
BEGIN
  WHILE (lines > 0) & TestPeers.ReadLine(c, line, LineWait) DO
    IF Begins(line, prefix) THEN RETURN LastNumber(line) END;
    DEC(lines)
  END;
  RETURN -1
END ServerPort;

(* GeminiFetch with options, of url (host, path), with GeminiHello's
   port: its exit status must be status, and its output must contain
   each of has1 and has2 (when not ""); and GeminiHello's log must
   contain logged (when not ""), checked at the end. *)
PROCEDURE Fetch(label, options, host, path: ARRAY OF CHAR; status: INTEGER;
    has1, has2: ARRAY OF CHAR);
  VAR cmd, url: Text; i, n: LONGINT; s: INTEGER; ok: BOOLEAN;
BEGIN
  Url(host, port, path, url);
  i := 0; Append(cmd, i, fetch); Append(cmd, i, " "); Append(cmd, i, options);
  Append(cmd, i, " "); Append(cmd, i, url);
  s := Run(cmd, "", n);
  IF n > LEN(got) - 1 THEN n := LEN(got) - 1 END;
  gotLen := n;
  ok := (s = status) & ((has1 = "") OR Has(got, n, has1)) & ((has2 = "") OR Has(got, n, has2));
  Check.Check(ok, label);
  IF ~ok THEN
    Out.String("  exit "); Out.Int(s, 0); Out.String(", output: "); got[n] := 0X; Out.String(got); Out.Ln
  END
END Fetch;

(* The log line GeminiHello must have printed: from, status, url (host,
   path) and hash ("-" for none). *)
PROCEDURE Logged(label, from, status, host, path, hash: ARRAY OF CHAR);
  VAR line, url: Text; i: LONGINT;
BEGIN
  Url(host, port, path, url);
  i := 0; Append(line, i, from); Append(line, i, " "); Append(line, i, status);
  Append(line, i, " "); Append(line, i, url); Append(line, i, " "); Append(line, i, hash);
  Append(line, i, "x"); line[i - 1] := LF;
  Check.Check(Has(log, logLen, line), label)
END Logged;

(* GeminiHello with server-ec and other-rsa, and every client of it. *)
PROCEDURE ServeHello;
  VAR c: TestPeers.Child; cmd, url, r, expect, opt: Text; line: Text;
    i, n, k, count: LONGINT; s: INTEGER; all: BOOLEAN;
BEGIN
  count := 5; IF nc # "" THEN INC(count) END;
  IF gemget # "" THEN INC(count, 2) END;
  IF gnutlsCli # "" THEN INC(count) END;
  i := 0; Append(cmd, i, hello); Append(cmd, i, " -n "); AppendInt(cmd, i, count);
  Append(cmd, i, " 0 "); Append(cmd, i, certs); Append(cmd, i, "server-ec.crt ");
  Append(cmd, i, certs); Append(cmd, i, "server-ec.key ");
  Append(cmd, i, certs); Append(cmd, i, "other-rsa.crt ");
  Append(cmd, i, certs); Append(cmd, i, "other-rsa.key");
  IF ~TestPeers.Spawn(cmd, "", 0, c) THEN Check.Check(FALSE, "GeminiHello: started"); RETURN END;
  port := ServerPort(c, "port ", 1);
  Check.Check(port > 0, "GeminiHello: listening, on the port it printed");
  IF port > 0 THEN
    (* 1 *)
    Url("127.0.0.1", port, "/a", url);
    i := 0; Append(expect, i, "You asked for "); Append(expect, i, url); Append(expect, i, ".");
    Fetch("GeminiFetch -ca, 127.0.0.1: the page", "-ca ../build/certs/ca-ec.crt",
      "127.0.0.1", "/a", 0, "20 text/gemini", expect);
    (* 2 *)
    i := 0; Append(expect, i, "Your client certificate is "); Append(expect, i, client1Hash);
    Fetch("GeminiFetch -ca -cert, ::1: the page names the client certificate",
      "-ca ../build/certs/ca-ec.crt -cert ../build/certs/client1-ec.crt -key ../build/certs/client1-ec.key",
      "[::1]", "/b", 0, "20 text/gemini", expect);
    (* 3 *)
    i := 0; Append(opt, i, "-pin "); Append(opt, i, serverHash);
    Fetch("GeminiFetch -pin, the server's fingerprint: the page", opt,
      "localhost", "/c", 0, "20 text/gemini", "You sent no client certificate.");
    (* 4 *)
    Fetch("GeminiFetch -pin, another fingerprint: refused before the request",
      "-pin SHA256:0000", "127.0.0.1", "/d", 1, "not the pinned SHA256:0000", "");
    Check.Check(~Has(got, gotLen, "20 text"), "GeminiFetch -pin, another fingerprint: no response");
    (* 5 *)
    i := 0; Append(cmd, i, "exec openssl s_client -quiet -verify_return_error -CAfile ");
    Append(cmd, i, certs); Append(cmd, i, "ca-ec.crt -verify_ip ::1 -connect [::1]:");
    AppendInt(cmd, i, port);
    Request("http://x/", r);
    s := Run(cmd, r, n);
    Check.Check((s = 0) & Has(got, n, "59 bad request"), "openssl s_client, ::1: a non-Gemini URL, 59");
    (* 6 *)
    IF nc # "" THEN
      i := 0; Append(cmd, i, "exec "); Append(cmd, i, nc); Append(cmd, i, " -c -R ");
      Append(cmd, i, certs); Append(cmd, i, "ca-ec.crt -e localhost -C ");
      Append(cmd, i, certs); Append(cmd, i, "client2-rsa.crt -K ");
      Append(cmd, i, certs); Append(cmd, i, "client2-rsa.key 127.0.0.1 ");
      AppendInt(cmd, i, port);
      Url("localhost", port, "/nc", url); Request(url, r);
      i := 0; Append(expect, i, "Your client certificate is "); Append(expect, i, client2Hash);
      Client("nc -c -C (libtls), 127.0.0.1: the page names the client certificate",
        cmd, r, "20 text/gemini", expect)
    END;
    (* 7, 8: Go's crypto/tls. gemget checks no server certificate. *)
    IF gemget # "" THEN
      i := 0; Append(cmd, i, "exec "); Append(cmd, i, gemget); Append(cmd, i, " -o - --header ");
      Url("127.0.0.1", port, "/gemget", url); Append(cmd, i, url);
      Client("gemget (Go), 127.0.0.1: the page", cmd, "", "Header: 20 text/gemini",
        "You sent no client certificate.");
      i := 0; Append(cmd, i, "exec "); Append(cmd, i, gemget); Append(cmd, i, " -o - --cert ");
      Append(cmd, i, certs); Append(cmd, i, "client2-ec.crt --key ");
      Append(cmd, i, certs); Append(cmd, i, "client2-ec.key ");
      Url("[::1]", port, "/gemget", url); Append(cmd, i, url);
      i := 0; Append(expect, i, "Your client certificate is "); Append(expect, i, client2EcHash);
      Client("gemget (Go) --cert, ::1: the page names the client certificate", cmd, "",
        "# Hello from polibtls", expect)
    END;
    (* 9: GnuTLS. At the end of its input it sends its own close_notify,
       which the server must read before it closes (GeminiHello's Drain). *)
    IF gnutlsCli # "" THEN
      i := 0; Append(cmd, i, "exec "); Append(cmd, i, gnutlsCli);
      Append(cmd, i, " --logfile=/dev/null --x509cafile "); Append(cmd, i, certs);
      Append(cmd, i, "ca-ec.crt --x509certfile "); Append(cmd, i, certs);
      Append(cmd, i, "client1-rsa.crt --x509keyfile "); Append(cmd, i, certs);
      Append(cmd, i, "client1-rsa.key -p "); AppendInt(cmd, i, port); Append(cmd, i, " 127.0.0.1");
      Url("localhost", port, "/gnutls", url); Request(url, r);
      i := 0; Append(expect, i, "Your client certificate is "); Append(expect, i, client1RsaHash);
      Client("gnutls-cli (GnuTLS), 127.0.0.1: verified the server; the page names the client certificate",
        cmd, r, "20 text/gemini", expect)
    END
  END;
  (* A line per connection, then GeminiHello exits; if one is missing,
     end it, so Wait can't wait for ever. *)
  logLen := 0; k := 0; all := port > 0;
  WHILE all & (k < count) DO
    all := TestPeers.ReadLine(c, line, LineWait);
    IF all THEN
      i := logLen; Append(log, i, line); logLen := i; INC(k);
      Out.String("# GeminiHello: "); Out.String(line)
    END
  END;
  Check.Check(all, "GeminiHello: a line for each connection");
  IF ~all THEN TestPeers.Kill(c) END;
  s := TestPeers.Wait(c, got, n);
  Check.Check(all & (s = 0) & (n = 0), "GeminiHello -n: exited 0 after its connections");
  IF port > 0 THEN
    Logged("GeminiHello log: 127.0.0.1, no client certificate", "127.0.0.1", "20", "127.0.0.1", "/a", "-");
    Logged("GeminiHello log: ::1, the client certificate", "::1", "20", "[::1]", "/b", client1Hash);
    Check.Check(Has(log, logLen, "127.0.0.1 failed: "), "GeminiHello log: the pin refused, the request never came");
    Check.Check(Has(log, logLen, "::1 59 http://x/ -"), "GeminiHello log: the 59");
    IF nc # "" THEN
      Logged("GeminiHello log: nc's client certificate", "127.0.0.1", "20", "localhost", "/nc", client2Hash)
    END;
    IF gemget # "" THEN
      Logged("GeminiHello log: gemget's client certificate", "::1", "20", "[::1]", "/gemget", client2EcHash)
    END;
    IF gnutlsCli # "" THEN
      Logged("GeminiHello log: gnutls-cli's client certificate", "127.0.0.1", "20", "localhost", "/gnutls",
        client1RsaHash)
    END
  END;
END ServeHello;

(* GeminiFetch, pinning hash, against a server that sends a response and
   ends without close_notify: server is a shell command reading the
   response on its standard input, printing its port in a line beginning
   with prefix. The response is sent a second after the server starts,
   by when the request has come: sent before, it would be left unread,
   and closing would reset the connection. *)
PROCEDURE Truncated(label, server, prefix: ARRAY OF CHAR; hash: ARRAY OF CHAR);
  VAR c: TestPeers.Child; cmd, opt: Text; i, n, p: LONGINT; s: INTEGER;
BEGIN
  i := 0; Append(cmd, i, "(sleep 1; printf '20 text/gemini\r\ncut short\n'; sleep 1) | timeout 20 ");
  Append(cmd, i, server);
  IF ~TestPeers.Spawn(cmd, "", 0, c) THEN Check.Check(FALSE, label); RETURN END;
  p := ServerPort(c, prefix, 10);
  IF p > 0 THEN
    port := p;
    i := 0; Append(opt, i, "-pin "); Append(opt, i, hash);
    Fetch(label, opt, "127.0.0.1", "/", 1, "cut short", "reading the response: ")
  ELSE Check.Check(FALSE, label)
  END;
  s := TestPeers.Wait(c, got, n)
END Truncated;

BEGIN
  Hash("server-ec", serverHash); Hash("client1-ec", client1Hash); Hash("client2-rsa", client2Hash);
  Hash("self-ec", selfEcHash); Hash("self-rsa", selfRsaHash);
  Hash("client1-rsa", client1RsaHash); Hash("client2-ec", client2EcHash);
  Find('for n in "$LIBTLS_NC" netcat nc; do p=$(command -v "$n") && ldd "$p" | grep -q libtls && { echo "$p"; exit 0; }; done; exit 1', nc);
  Found("nc", nc, "one linked with libtls: install netcat, or set LIBTLS_NC");
  Find('for n in "$GEMGET" gemget; do command -v "$n" && exit 0; done; exit 1', gemget);
  Found("gemget", gemget, "on PATH, or set GEMGET");
  Find('for n in "$GNUTLS_CLI" gnutls-cli; do command -v "$n" && exit 0; done; exit 1', gnutlsCli);
  Found("gnutls-cli", gnutlsCli, "install gnutls-utils, or set GNUTLS_CLI");
  ServeHello;
  Truncated("GeminiFetch, openssl s_server (no close_notify): the response, then refused as cut short",
    "openssl s_server -naccept 1 -accept 127.0.0.1:0 -cert ../build/certs/self-ec.crt -key ../build/certs/self-ec.key",
    "ACCEPT", selfEcHash);
  IF nc # "" THEN
    i := 0; Append(cmd, i, nc);
    Append(cmd, i, " -v -N -c -l -C ../build/certs/self-rsa.crt -K ../build/certs/self-rsa.key 127.0.0.1 0");
    Truncated("GeminiFetch, nc -N (no close_notify): the response, then refused as cut short",
      cmd, "Listening on", selfRsaHash)
  END;
  Check.Summary
END TestGemini.
