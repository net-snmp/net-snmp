/*
 * snmplib/all_includes.h
 *
 * Only the following are out of alphabetical order to meet other dependencies:
 *		HAVE_WINSOCK_H              
 *		HAVE_ARPA_INET_H
 *		HAVE_NET_ROUTE_H
 */

#ifndef _ALL_INCLUDES_H
#define _ALL_INCLUDES_H


/* #include <config.h>	/* */
#include "../config.h"
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>




/* ------------------------------------ -o- 
 * System specific includes.
 */
#if HAVE_DIRENT_H
#	include <dirent.h>
#	define NAMLEN(dirent)	strlen((dirent)->d_name)
#else
#	define dirent		direct
#	define NAMLEN(dirent)	(dirent)->d_namlen
#	if HAVE_SYS_NDIR_H
#		include <sys/ndir.h>
#	endif
#	if HAVE_SYS_DIR_H
#		include <sys/dir.h>
#	endif
#	if HAVE_NDIR_H
#		include <ndir.h>
#	endif
#endif

#if HAVE_FCNTL_H
#	include <fcntl.h>
#endif

#if HAVE_INET_MIB2_H
#	include <inet/mib2.h>
#endif

#ifdef HAVE_IO_H
#	include <io.h>
#endif

#ifdef HAVE_LIBKMT 
#	include <kmt.h>
#	include <kmt_algs.h>
#endif

#if HAVE_KSTAT_H
#	include <kstat.h>
#endif

#if HAVE_WINSOCK_H
#	include <winsock.h>
#else
#	include <sys/socket.h>
#	include <net/if.h>
#	include <netdb.h>
#endif

#if HAVE_NETINET_IN_H /* */
#	include <netinet/in.h>
#else
#	include <netinet/in_systm.h>
#	include <netinet/ip.h>
#	include <sys/socket.h>
#endif

#if HAVE_ARPA_INET_H /* */
#	include <arpa/inet.h>
#endif

#if HAVE_NET_ROUTE_H /* */
#	include <net/route.h>
#endif

#if HAVE_NETINET_IN_PCB_H /* */
#	include <netinet/in_systm.h>
#	include <netinet/ip.h>
		/* XXX  Put previous two under "have netinet/in.h"?
		 */
#	include <netinet/in_pcb.h>
#endif

#if HAVE_STDLIB_H
#	include <stdlib.h>
#endif

#if HAVE_STRING_H
#	include <string.h>
#else
#	include <strings.h>
#endif

#if HAVE_SYS_FILE_H
#	include <sys/file.h>
#endif

#if HAVE_SYS_IOCTL_H
#	include <sys/ioctl.h>
#endif

#if HAVE_SYS_PARAM_H
#	include <sys/param.h>
#endif

#if HAVE_SYS_SELECT_H
#	include <sys/select.h>
#endif

#if HAVE_SYS_SOCKIO_H
#	include <sys/sockio.h>
#endif

#if HAVE_SYS_SYSCTL_H
#	include <sys/sysctl.h>
#endif

#if HAVE_UNISTD_H
# 	include <unistd.h>
#endif

#ifdef KINETICS
#	include "gw.h"
#	include "ab.h"
#	include "inet.h"
#	include "fp4/cmdmacro.h"
#	include "fp4/pbuf.h"
#	include "glob.h"
#endif

#ifdef STDC_HEADERS
#	include <stdarg.h>
#	include <stdlib.h>
#	include <string.h>
#else
#	include <varargs.h>
#endif

#if TIME_WITH_SYS_TIME
#	ifdef WIN32
#		include <sys/timeb.h>
#	else
#		include <sys/time.h>
#	endif
#	include <time.h>
#else
#	if HAVE_SYS_TIME_H
#		include <sys/time.h>
#	else
#		include <time.h>
#	endif
#endif

#ifdef vms
#	include <in.h>
#endif

#ifndef WIN32
#	ifdef HAVE_NLIST_H
#		include <nlist.h>
#	endif
#endif




/* ------------------------------------ -o- 
 * Constants.
 */
#define TRUE	1
#define FALSE	0

#ifndef NULL
#define NULL	0
#endif


#endif /* _ALL_INCLUDES_H */

