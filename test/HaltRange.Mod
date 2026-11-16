MODULE HaltRange; (* A Read past the end of its buffer: halts with 93 *)

IMPORT Tls;

VAR c: Tls.Config; x: Tls.Context; conn: Tls.Connection; buf: ARRAY 16 OF CHAR; n: LONGINT;

BEGIN
  c := Tls.NewConfig();
  IF ~c.SetKeypairFile("../build/certs/self-ec.crt", "../build/certs/self-ec.key") THEN HALT(1) END;
  x := Tls.NewServer();
  IF ~x.Configure(c) THEN HALT(1) END;
  IF ~x.AcceptSocket(0, conn) THEN HALT(1) END;
  IF conn.Read(buf, 8, 9, n) THEN END
END HaltRange.
