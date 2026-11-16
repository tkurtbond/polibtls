MODULE TestInit; (* The library builds, links libtls and initialises it *)

IMPORT Check, Tls, TlsThin;

BEGIN
  (* Importing Tls ran tls_init, or this would have halted with 90. *)
  Check.Check(TRUE, "Tls initialised libtls");
  Check.Check(TlsThin.api = 20200120, "tls.h is LibreTLS's TLS_API 20200120");
  Check.Summary
END TestInit.
