MODULE TestConfig; (* Tls.Config: every setter, with good and bad files and strings *)

(* A key pair whose key is malformed or doesn't match its certificate
   passes the setter and fails only when a context is configured, so
   TestBlocking (Phase 4) checks it. Certificates are
   test/make-certs.sh's, from test/. *)

IMPORT Check, Tls;

CONST certs = "../build/certs/";

TYPE Name = ARRAY 128 OF CHAR;

VAR c, dropped: Tls.Config; crt, key: Name;

PROCEDURE Append(VAR s: Name; VAR i: LONGINT; part: ARRAY OF CHAR);
  VAR j: LONGINT;
BEGIN
  j := 0; WHILE part[j] # 0X DO s[i] := part[j]; INC(i); INC(j) END;
  s[i] := 0X
END Append;

(* s := certs + name + ext; no string + in poc. *)
PROCEDURE Path(name, ext: ARRAY OF CHAR; VAR s: Name);
  VAR i: LONGINT;
BEGIN i := 0; Append(s, i, certs); Append(s, i, name); Append(s, i, ext)
END Path;

PROCEDURE Pair(name: ARRAY OF CHAR; VAR crt, key: Name);
BEGIN Path(name, ".crt", crt); Path(name, ".key", key)
END Pair;

(* c failed with an error of kind config whose text has part. *)
PROCEDURE Failed(ok: BOOLEAN; part, label: ARRAY OF CHAR);
BEGIN
  Check.Check(~ok & (c.error # NIL) & (c.error.kind = Tls.config)
    & Check.Contains(c.error.text^, part), label)
END Failed;

PROCEDURE Succeeded(ok: BOOLEAN; label: ARRAY OF CHAR);
BEGIN Check.Check(ok & (c.error = NIL), label)
END Succeeded;

BEGIN
  c := Tls.NewConfig();
  Check.Check(c.error = NIL, "NewConfig: no error");

  (* key pairs *)
  Pair("self-ec", crt, key); Succeeded(c.SetKeypairFile(crt, key), "SetKeypairFile: EC");
  Pair("self-rsa", crt, key); Succeeded(c.SetKeypairFile(crt, key), "SetKeypairFile: RSA");
  Pair("other-ec", crt, key); Succeeded(c.AddKeypairFile(crt, key), "AddKeypairFile");
  Pair("missing", crt, key);
  Failed(c.SetKeypairFile(crt, key), "failed to open certificate file", "SetKeypairFile: a missing certificate");
  Pair("self-ec", crt, key);
  Failed(c.SetKeypairFile(crt, "../build/certs/missing.key"), "failed to open key file",
    "SetKeypairFile: a missing key");
  Failed(c.SetKeypairFile("make-certs.sh", key), "failed to load certificate",
    "SetKeypairFile: a certificate that isn't PEM");
  Failed(c.SetKeypairFile(key, key), "failed to load certificate",
    "SetKeypairFile: a key given as the certificate");
  Failed(c.AddKeypairFile("", ""), "failed to open certificate file", "AddKeypairFile: no file name");
  Succeeded(c.SetKeypairFile(crt, key), "a success clears the error");

  (* CA file *)
  Succeeded(c.SetCaFile("../build/certs/ca-ec.crt"), "SetCaFile");
  Failed(c.SetCaFile("../build/certs/missing.crt"), "missing.crt", "SetCaFile: a missing file");
  Succeeded(c.SetCaFile("make-certs.sh"), "SetCaFile: a file that isn't PEM is accepted here");

  (* protocols *)
  Succeeded(c.SetProtocols("tlsv1.3"), "SetProtocols: tlsv1.3");
  Succeeded(c.SetProtocols("tlsv1.2,tlsv1.3"), "SetProtocols: a list");
  Succeeded(c.SetProtocols("all:!tlsv1.2"), "SetProtocols: a removal");
  Succeeded(c.SetProtocols("secure"), "SetProtocols: secure");
  Failed(c.SetProtocols("tlsv9"), "invalid protocols", "SetProtocols: an unknown name");
  Failed(c.SetProtocols(""), "invalid protocols", "SetProtocols: nothing");

  (* ciphers *)
  Succeeded(c.SetCiphers("compat"), "SetCiphers: compat");
  Succeeded(c.SetCiphers("ECDHE-ECDSA-AES256-GCM-SHA384"), "SetCiphers: an OpenSSL list");
  Failed(c.SetCiphers("no-such-cipher"), "no ciphers for 'no-such-cipher'", "SetCiphers: an unknown cipher");
  Failed(c.SetCiphers(""), "no ciphers for ''", "SetCiphers: nothing");

  (* options with no result *)
  c.VerifyClientOptional; c.InsecureNoVerifyCert; c.InsecureNoVerifyName; c.InsecureNoVerifyTime;
  Check.Check(c.error # NIL, "options leave the last error alone");

  c.Close; c.Close;
  Check.Check(TRUE, "Close twice");

  (* Left for the finalizer at exit: valgrind's still-reachable check
     shows it freed. *)
  dropped := Tls.NewConfig();
  Pair("self-ec", crt, key); Check.Check(dropped.SetKeypairFile(crt, key), "a config left unclosed");
  dropped := NIL;

  Check.Summary
END TestConfig.
