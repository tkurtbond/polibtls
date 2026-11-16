MODULE Tls; (* The thick layer of polibtls (PLAN.md, "Modules") *)

(* Config, Context, Connection and Error come in Phases 3 and 4. For
   now the module initialises libtls, once, as every later call needs. *)

IMPORT TlsThin;

BEGIN
  ASSERT(TlsThin.Init() = 0, 90)
END Tls.
