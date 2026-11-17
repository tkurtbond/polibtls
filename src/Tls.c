/* Tls.c -- the C part of module Tls (polibtls).

   What Tls needs from the system rather than from libtls: whether a
   descriptor is in non-blocking mode. Connections' deadlines (PLAN.md,
   Phase 6) take poDateTime's monotonic clock. Every function takes and
   returns only int32_t and int64_t.

   The functions are labelled Tls.-<name>, so they can't collide with C
   names; their C names avoid libtls's tls_ prefix. */

#include <stdint.h>
#include <fcntl.h>

#define NAME(n) __asm__("Tls.-" n)

int32_t tlsmod_nonblocking(int64_t fd) NAME("nonblocking");

/* 1 if fd is in non-blocking mode, 0 if it is blocking or isn't open
   (fcntl fails). */
int32_t tlsmod_nonblocking(int64_t fd)
{
	int flags = fcntl((int)fd, F_GETFL);

	return flags != -1 && (flags & O_NONBLOCK) != 0;
}
