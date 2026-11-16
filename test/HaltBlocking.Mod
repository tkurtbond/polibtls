MODULE HaltBlocking; (* A blocking descriptor given to TlsTasks: halts with 97 *)

(* Standard input, /dev/null under make test, is blocking. *)

IMPORT Tls, TlsTasks;

VAR c: Tls.Config; x: Tls.Context; conn: Tls.Connection;

BEGIN
  c := Tls.NewConfig();
  IF ~c.SetKeypairFile("../build/certs/self-ec.crt", "../build/certs/self-ec.key") THEN HALT(1) END;
  x := Tls.NewServer();
  IF ~x.Configure(c) THEN HALT(1) END;
  IF ~x.AcceptSocket(0, conn) THEN HALT(1) END;
  IF TlsTasks.Handshake(conn) THEN END
END HaltBlocking.
