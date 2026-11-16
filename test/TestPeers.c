/* TestPeers.c -- the C part of module TestPeers, the tests' own access
   to the system: a socket pair to run TLS over, without the network or
   posockets (PLAN.md, "Testing"). Labelled TestPeers.-<name>. */

#include <signal.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

#define NAME(n) __asm__("TestPeers.-" n)

int32_t testpeers_pair(int64_t *fds, int32_t nonblocking) NAME("pair");
int32_t testpeers_close(int64_t fd) NAME("close");
void testpeers_ignore_sigpipe(void) NAME("ignore-sigpipe");

/* A connected pair of Unix-domain stream sockets in fds[0] and fds[1],
   close-on-exec, and non-blocking if asked: 0, or -1. */
int32_t testpeers_pair(int64_t *fds, int32_t nonblocking)
{
	int sv[2];
	int type = SOCK_STREAM | SOCK_CLOEXEC | (nonblocking ? SOCK_NONBLOCK : 0);

	if (socketpair(AF_UNIX, type, 0, sv) != 0)
		return -1;
	fds[0] = sv[0];
	fds[1] = sv[1];
	return 0;
}

int32_t testpeers_close(int64_t fd) { return close((int)fd); }

/* Writing to a gone peer then fails with EPIPE instead of killing the
   test (PLAN.md, "I/O"). */
void testpeers_ignore_sigpipe(void) { signal(SIGPIPE, SIG_IGN); }
