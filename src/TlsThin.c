/* TlsThin.c -- the C part of module TlsThin (polibtls).

   What Oberon can't take from libtls directly is here: tls.h's #define
   values, and the functions returning ssize_t or time_t, whose width
   varies (ssize_t is 32 bits on i386, where time_t is 64 on the BSDs
   but was 32 on older systems), widened to int64_t. (Not errno: libtls
   clears it; PLAN.md, "Errors".) Every function takes and
   returns only int32_t, int64_t and intptr_t.

   The functions are labelled TlsThin.-<name>, so they can't collide
   with C names. */

#include <stdint.h>
#include <tls.h>

#define NAME(n) __asm__("TlsThin.-" n)

int32_t tlsthin_constant(int32_t which) NAME("constant");
int64_t tlsthin_read(intptr_t ctx, intptr_t buf, int64_t buflen) NAME("read");
int64_t tlsthin_write(intptr_t ctx, intptr_t buf, int64_t buflen) NAME("write");
int64_t tlsthin_notbefore(intptr_t ctx) NAME("notbefore");
int64_t tlsthin_notafter(intptr_t ctx) NAME("notafter");

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

int64_t tlsthin_read(intptr_t ctx, intptr_t buf, int64_t buflen)
{
	return tls_read((struct tls *)ctx, (void *)buf, (size_t)buflen);
}

int64_t tlsthin_write(intptr_t ctx, intptr_t buf, int64_t buflen)
{
	return tls_write((struct tls *)ctx, (const void *)buf, (size_t)buflen);
}

int64_t tlsthin_notbefore(intptr_t ctx)
{
	return tls_peer_cert_notbefore((struct tls *)ctx);
}

int64_t tlsthin_notafter(intptr_t ctx)
{
	return tls_peer_cert_notafter((struct tls *)ctx);
}
