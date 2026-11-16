MODULE HaltConfigClosed; (* A closed Config used: halts with 91 *)

IMPORT Tls;

VAR c: Tls.Config;

BEGIN
  c := Tls.NewConfig(); c.Close;
  IF c.SetCaFile("../build/certs/ca-ec.crt") THEN END
END HaltConfigClosed.
