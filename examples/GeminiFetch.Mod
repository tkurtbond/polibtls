MODULE GeminiFetch; (* A Gemini client: fetches a URL, prints the response *)

(* Usage: GeminiFetch [-pin hash | -ca file] [-cert file -key file] url

   Connects to the host and port (default 1965) of url, a gemini:// URL,
   sends the URL, and prints the response, its header line included, on
   standard output. A response counts only if the server ended it with
   TLS close_notify: an end without one may be an attacker cutting it
   short, so it is an error.

   How it trusts the server:
   - with -pin, the server's certificate must have that fingerprint
     ("SHA256:" and lowercase hex, as libtls gives it): the pin is the
     server's identity, as in a Gemini client's trust on first use, so
     no CA, name or validity period is checked. The fingerprint is
     compared before the request is sent, so a request never reaches a
     server it isn't meant for.
   - with -ca, the certificate must be valid, for the URL's host, and
     signed by a CA in file.
   - with neither, nothing is checked: the fingerprint is printed on
     standard error, for -pin next time.
   With -cert and -key it presents that client certificate.

   Exits 0 for a response whose status is 2x (success), 1 for any other
   response or a failure, 2 for bad usage.

   It shows a client connection (Tls.ConnectSocket) on a socket from
   posockets, with blocking I/O, pinning by Connection.PeerCertHash. *)

IMPORT SYSTEM, Platform, Err, Args, Sockets, Tls;

CONST
  DefaultPort = 1965;
  MaxUrl = 1024;
  CR = 0DX; LF = 0AX;

VAR
  url, host, pin, ca, cert, key: ARRAY MaxUrl + 1 OF CHAR;
  port: LONGINT;
  s: Sockets.Socket;  (* the connection's, once made, closed on every exit *)

(* Ends the program with status, closing the socket first: the program
   leaves nothing open behind it, which valgrind's --track-fds checks. *)
PROCEDURE Exit(status: INTEGER);
BEGIN
  IF s # NIL THEN Sockets.Close(s) END;
  Platform.Exit(status)
END Exit;

PROCEDURE Fail(what, why: ARRAY OF CHAR);
BEGIN
  Err.String("GeminiFetch: "); Err.String(what);
  IF why # "" THEN Err.String(": "); Err.String(why) END;
  Err.Ln; Exit(1)
END Fail;

PROCEDURE Usage;
BEGIN
  Err.String("usage: GeminiFetch [-pin hash | -ca file] [-cert file -key file] url"); Err.Ln;
  Platform.Exit(2)
END Usage;

(* The host and port of url, gemini://host[:port][/...], in host and
   port; an IPv6 address is in brackets there and not in host. FALSE
   if url isn't one. *)
PROCEDURE Parse(url: ARRAY OF CHAR): BOOLEAN;
  CONST scheme = "gemini://";
  VAR i, j: LONGINT; s: ARRAY 10 OF CHAR; close: CHAR;
BEGIN
  s := scheme; i := 0;
  WHILE (s[i] # 0X) & (url[i] = s[i]) DO INC(i) END;
  IF s[i] # 0X THEN RETURN FALSE END;
  IF url[i] = "[" THEN close := "]"; INC(i) ELSE close := 0X END;
  j := 0;
  WHILE (url[i] # 0X) & (url[i] # close) & ((close = "]")
      OR (url[i] # ":") & (url[i] # "/") & (url[i] # "?") & (url[i] # "#")) DO
    host[j] := url[i]; INC(i); INC(j)
  END;
  host[j] := 0X;
  IF j = 0 THEN RETURN FALSE END;
  IF close # 0X THEN
    IF url[i] # close THEN RETURN FALSE END;
    INC(i)
  END;
  port := DefaultPort;
  IF url[i] = ":" THEN
    INC(i); port := 0;
    WHILE ("0" <= url[i]) & (url[i] <= "9") & (port <= 65535) DO
      port := port * 10 + ORD(url[i]) - ORD("0"); INC(i)
    END;
    IF (port = 0) OR (port > 65535) THEN RETURN FALSE END
  END;
  RETURN (url[i] = 0X) OR (url[i] = "/") OR (url[i] = "?") OR (url[i] = "#")
END Parse;

PROCEDURE Length(s: ARRAY OF CHAR): LONGINT;
  VAR n: LONGINT;
BEGIN n := 0; WHILE s[n] # 0X DO INC(n) END; RETURN n
END Length;

PROCEDURE GetArgs;
  VAR arg: ARRAY 16 OF CHAR; i: INTEGER;
BEGIN
  pin := ""; ca := ""; cert := ""; key := ""; i := 1;
  LOOP
    Args.Get(i, arg);
    IF i + 1 >= Args.argc THEN EXIT
    ELSIF arg = "-pin" THEN Args.Get(i + 1, pin)
    ELSIF arg = "-ca" THEN Args.Get(i + 1, ca)
    ELSIF arg = "-cert" THEN Args.Get(i + 1, cert)
    ELSIF arg = "-key" THEN Args.Get(i + 1, key)
    ELSE EXIT
    END;
    INC(i, 2)
  END;
  IF (i # Args.argc - 1) OR (pin # "") & (ca # "") OR ((cert = "") # (key = "")) THEN Usage END;
  Args.Get(i, url);
  IF (Length(url) >= MaxUrl) OR ~Parse(url) THEN
    Err.String("GeminiFetch: not a gemini:// URL: "); Err.String(url); Err.Ln; Platform.Exit(2)
  END
END GetArgs;

(* The client's options, by GetArgs. *)
PROCEDURE NewConfig(): Tls.Config;
  VAR c: Tls.Config;
BEGIN
  c := Tls.NewConfig();
  IF (cert # "") & ~c.SetKeypairFile(cert, key) THEN Fail("client certificate", c.error.text^) END;
  IF ca # "" THEN
    IF ~c.SetCaFile(ca) THEN Fail("CA file", c.error.text^) END
  ELSE
    c.InsecureNoVerifyCert; c.InsecureNoVerifyName; c.InsecureNoVerifyTime
  END;
  RETURN c
END NewConfig;

PROCEDURE Main;
  VAR c: Tls.Config; err: Sockets.Error; conn: Tls.Connection;
    hash: Tls.String; buf: ARRAY 4096 OF CHAR; n, m: LONGINT; status: CHAR;
BEGIN
  s := NIL;
  GetArgs;
  c := NewConfig();
  Sockets.IgnoreBrokenPipe;
  IF ~Sockets.Connect(host, SHORT(port), s, err) THEN Fail(err.text, "") END;
  (* SNI and the name verified: the URL's host *)
  IF ~Tls.ConnectSocket(c, s.fd, host, conn) THEN Fail("TLS", conn.error.text^) END;
  c.Close;
  IF ~conn.Handshake() THEN Fail("handshake", conn.error.text^) END;
  hash := conn.PeerCertHash();
  IF pin # "" THEN
    IF hash^ # pin THEN
      conn.Discard;
      Err.String("GeminiFetch: the server's certificate is "); Err.String(hash^);
      Err.String(", not the pinned "); Err.String(pin); Err.Ln; Exit(1)
    END
  ELSIF ca = "" THEN
    Err.String("GeminiFetch: unverified server certificate "); Err.String(hash^); Err.Ln
  END;
  COPY(url, buf); n := Length(buf); buf[n] := CR; buf[n + 1] := LF;
  IF ~conn.WriteAll(buf, 0, n + 2, m) THEN Fail("sending the request", conn.error.text^) END;
  status := 0X;
  WHILE conn.Read(buf, 0, LEN(buf), n) DO
    IF status = 0X THEN status := buf[0] END;
    IF Platform.Write(Platform.StdOut, SYSTEM.ADR(buf), n) # 0 THEN
      Fail("writing standard output", "")
    END
  END;
  IF conn.error.kind # Tls.closed THEN Fail("reading the response", conn.error.text^) END;
  IF ~conn.Close() THEN Fail("closing", conn.error.text^) END;
  IF status # "2" THEN Exit(1) END;
  Sockets.Close(s)
END Main;

BEGIN
  Main
END GeminiFetch.
