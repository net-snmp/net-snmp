/*
 * The Win32 API is maintained by the MinGW developers.
 * The licensing for the Win32 API is defined in the
 * MinGW file README.w32api, which states:

   "Unless otherwise stated in individual source files,

    THIS SOFTWARE IS NOT COPYRIGHTED

    This source code is offered for use in the public domain.  You may use,
    modify or distribute it freely.

    This source code is distributed in the hope that it will be useful but
    WITHOUT ANY WARRANTY.  ALL WARRANTIES, EXPRESS OR IMPLIED ARE HEREBY
    DISCLAIMED.  This includes but is not limited to warranties of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
 
 */

/*
 * Make sure that the Winsock header files get included before any <sys/...>
 * header files to avoid that the build fails as follows:
 *   In file included from /usr/include/w32api/winsock2.h:56:0,
 *                    from ../include/net-snmp/types.h:24,
 *                    from snmp_client.c:87:
 *   /usr/include/w32api/psdk_inc/_fd_types.h:100:2: warning:  *warning "fd_set and associated macros have been defined in sys/types.      This can cause runtime problems with W32 sockets" [-Wcpp]
 *   #warning "fd_set and associated macros have been defined in sys/types.
 */
#include <winsock2.h>
#include <ws2tcpip.h>

#include <net-snmp/system/generic.h>

#ifdef HAVE_STDINT_H
#include <stdint.h>	/* uint32_t */
#endif

#undef bsdlike
#undef MBSTAT_SYMBOL
#undef TOTAL_MEMORY_SYMBOL
#undef HAVE_GETOPT_H
#undef HAVE_SOCKET
#undef HAVE_SIGNAL

/* Define if you have the gettimeofday function.  */
#define HAVE_GETTIMEOFDAY 1

/* Define if you have the gethostbyname function.  */
#define HAVE_GETHOSTBYNAME 1

/* Define if you have the gethostname function.  */
#define HAVE_GETHOSTNAME 1

/* Define if you have raise() instead of alarm() */
#define HAVE_RAISE 1

/* Define if you have the socket function.  */
#define HAVE_SOCKET 1

/* Define to 1 if you have the `execv' function. */
#undef HAVE_EXECV

/* Define to 1 if you have the `fork' function. */
#undef HAVE_FORK

/*
 * I'm sure there is a cleaner way to do this.
 * Probably should be in net_snmp_config.h and
 * set during config.
 */
#ifndef LOG_DAEMON
#define	LOG_DAEMON	(3<<3)	/* System daemons */
#endif

/* got socklen_t? */
#define HAVE_SOCKLEN_T 1

/* This was taken from the win32 config file - see licensing information above */
#define EADDRINUSE		WSAEADDRINUSE

/*
 * File io stuff. Odd that this is not defined by MinGW.
 * Maybe there is an M$ish way to do it.
 */
#define	F_SETFL		4
#define	O_NONBLOCK	0x4000  /* non blocking I/O (POSIX style) */

#ifndef HAVE_STRUCT_TIMEZONE_TZ_DSTTIME
/*
 * Older MinGW versions do not have struct timezone, so define it here.
 */
struct timezone {
	int tz_minuteswest;
	int tz_dsttime;
};
#endif

