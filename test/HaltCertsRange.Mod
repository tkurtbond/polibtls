MODULE HaltCertsRange; (* A length past the array given to TlsCerts: halts with 93 *)

IMPORT TlsCerts;

VAR s: ARRAY 8 OF CHAR; d: TlsCerts.Digest;

BEGIN
  s := "x";
  TlsCerts.Sha256(s, 4, 5, d)
END HaltCertsRange.
