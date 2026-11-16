MODULE HaltInfoEarly; (* Connection info asked before the handshake: halts with 92 *)

IMPORT Tls, TestPeers;

VAR c: Tls.Config; x: Tls.Context; conn: Tls.Connection; a, b: LONGINT;

BEGIN
  c := Tls.NewConfig();
  IF ~c.SetKeypairFile("../build/certs/self-ec.crt", "../build/certs/self-ec.key") THEN HALT(1) END;
  x := Tls.NewServer();
  IF ~x.Configure(c) THEN HALT(1) END;
  IF ~TestPeers.Pair(a, b, TRUE) OR ~x.AcceptSocket(a, conn) THEN HALT(1) END;
  IF conn.PeerCertProvided() THEN END
END HaltInfoEarly.
