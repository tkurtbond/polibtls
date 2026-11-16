/* TlsThin.c -- the C part of module TlsThin (polibtls).

   What Oberon can't take from libtls directly is here: tls.h's #define
   values. (Not errno: libtls clears it; PLAN.md, "Errors".) Every function takes and
   returns only int32_t, int64_t and intptr_t.

   The functions are labelled TlsThin.-<name>, so they can't collide
   with C names. */

#include <stdint.h>
#include <tls.h>

#define NAME(n) __asm__("TlsThin.-" n)

int32_t tlsthin_constant(int32_t which) NAME("constant");

/* tls.h's values, by number, as TlsThin's body asks for them; -1 for a
   number this file doesn't know, which the body treats as a bug. */
int32_t tlsthin_constant(int32_t which)
{
	switch (which) {
	case 0: return TLS_API;
	case 1: return TLS_WANT_POLLIN;
	case 2: return TLS_WANT_POLLOUT;
	case 3: return TLS_PROTOCOL_TLSv1_2;
	case 4: return TLS_PROTOCOL_TLSv1_3;
	case 5: return TLS_PROTOCOLS_ALL;
	case 6: return TLS_PROTOCOLS_DEFAULT;
	default: return -1;
	}
}
