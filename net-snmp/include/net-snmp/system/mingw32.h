#include "generic.h"

#undef bsdlike
#undef MBSTAT_SYMBOL
#undef TOTAL_MEMORY_SYMBOL
#undef HAVE_GETOPT_H
#undef HAVE_SOCKET
#undef HAVE_SIGNAL

/*
 * I'm sure there is a cleaner way to do this.
 * Probably should be in net_snmp_config.h and
 * set during config.
 */
#ifndef LOG_DAEMON
#define	LOG_DAEMON	(3<<3)	/* System daemons */
#endif

/* This was taken from the win32 config file. */
#define EADDRINUSE		WSAEADDRINUSE

/*
 * Not sure if the checking is required but cygwin
 * does it this way.
 */
#ifndef HAVE_SSIZE_T
#if defined(__INT_MAX__) && __INT_MAX__ == 2147483647
typedef int ssize_t;
#else
typedef long ssize_t;
#endif
#endif

/*
 * File io stuff. Odd that this is not defined by MinGW.
 * Maybe there is an M$ish way to do it.
 */
#define	F_SETFL		4
#define	O_NONBLOCK	0x4000  /* non blocking I/O (POSIX style) */

/*
 * I dunno why. It's just not there. Define struct timezone.
 * If other systems need this it could be moved to system.h
 * and the proper checking done at config time. Right now I have
 * just put it here to keep the MinGW out of the main tree as much
 * as possible.
 */
struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};
