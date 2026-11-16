/* Tls.c -- the C part of module Tls (polibtls).

   What Tls needs from the system rather than from libtls: whether a
   descriptor is in non-blocking mode, and a monotonic clock for
   connections' deadlines (PLAN.md, Phase 6). Every function takes and
   returns only int32_t and int64_t.

   The functions are labelled Tls.-<name>, so they can't collide with C
   names; their C names avoid libtls's tls_ prefix. */

#include <stdint.h>
#include <fcntl.h>
#include <time.h>

#define NAME(n) __asm__("Tls.-" n)

int32_t tlsmod_nonblocking(int64_t fd) NAME("nonblocking");
int64_t tlsmod_now(void) NAME("now");

/* 1 if fd is in non-blocking mode, 0 if it is blocking or isn't open
   (fcntl fails). */
int32_t tlsmod_nonblocking(int64_t fd)
{
	int flags = fcntl((int)fd, F_GETFL);

	return flags != -1 && (flags & O_NONBLOCK) != 0;
}

/* Milliseconds on the monotonic clock, from an arbitrary start. */
int64_t tlsmod_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}
