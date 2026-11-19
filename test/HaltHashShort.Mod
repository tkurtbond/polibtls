MODULE HaltHashShort; (* A hash array shorter than HashLength: halts with 99 *)

IMPORT TlsCerts;

VAR s: ARRAY 8 OF CHAR; h: ARRAY TlsCerts.HashLength - 1 OF CHAR;

BEGIN
  s := "x";
  IF TlsCerts.KeyHash(s, 1, h) THEN END
END HaltHashShort.
