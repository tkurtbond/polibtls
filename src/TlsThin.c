/* TlsThin.c -- the C part of module TlsThin (polibtls).

   What Oberon can't take from libtls directly is here: tls.h's #define
   values, and later anything with an out parameter or a type whose
   width poc can't name portably (AGENTS.md, "Layout"). Every function
   takes and returns only int32_t, int64_t and intptr_t.

   The functions are labelled TlsThin.-<name>, so they can't collide
   with C names. */

#include <stdint.h>
#include <tls.h>

#define NAME(n) __asm__("TlsThin.-" n)

int32_t tlsthin_api(void) NAME("api");

/* TLS_API, the version of the libtls interface tls.h describes. */
int32_t tlsthin_api(void) { return TLS_API; }
