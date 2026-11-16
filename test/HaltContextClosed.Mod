MODULE HaltContextClosed; (* A closed Context used: halts with 91 *)

IMPORT Tls;

VAR c: Tls.Config; x: Tls.Context; conn: Tls.Connection;

BEGIN
  c := Tls.NewConfig();
  IF ~c.SetKeypairFile("../build/certs/self-ec.crt", "../build/certs/self-ec.key") THEN HALT(1) END;
  x := Tls.NewServer();
  IF ~x.Configure(c) THEN HALT(1) END;
  x.Close;
  IF x.AcceptSocket(0, conn) THEN END
END HaltContextClosed.
