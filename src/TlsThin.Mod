MODULE TlsThin; (* libtls, one to one (PLAN.md, "Modules") *)

(* Each libtls function is an unexported ["C"] procedure wrapped in an
   exported Oberon one, so the thick layer, Tls, never names a C symbol.
   No ownership or error policy here: that is Tls's. Integers cross with
   explicit widths, so this module means the same under -OC or -O2.

   Phase 1 binds only what the skeleton needs; Phase 2 adds the rest. *)

IMPORT SYSTEM;

PROCEDURE ["C", "tls_init"] CInit(): SYSTEM.INT32;
PROCEDURE ["C", "TlsThin.-api"] CApi(): SYSTEM.INT32;

(* tls_init: 0 on success, -1 on failure. *)
PROCEDURE Init*(): SYSTEM.INT32;
BEGIN RETURN CInit()
END Init;

(* TLS_API from tls.h. *)
PROCEDURE Api*(): SYSTEM.INT32;
BEGIN RETURN CApi()
END Api;

END TlsThin.
