MODULE HaltNegativeFd; (* A negative descriptor given to AcceptSocket: halts with 95 *)

IMPORT Tls;

VAR c: Tls.Config; x: Tls.Context; conn: Tls.Connection;

BEGIN
  c := Tls.NewConfig();
  IF ~c.SetKeypairFile("../build/certs/self-ec.crt", "../build/certs/self-ec.key") THEN HALT(1) END;
  x := Tls.NewServer();
  IF ~x.Configure(c) THEN HALT(1) END;
  IF x.AcceptSocket(-1, conn) THEN END
END HaltNegativeFd.
