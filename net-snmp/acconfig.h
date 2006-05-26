/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

#ifndef NET_SNMP_CONFIG_H
#define NET_SNMP_CONFIG_H

/* config.h:  a general config file */

/* Default (SNMP) version number for the tools to use */
#define DEFAULT_SNMP_VERSION 3

/* don't change these values! */
#define SNMPV1      0xAAAA       /* readable by anyone */
#define SNMPV2ANY   0xA000       /* V2 Any type (includes NoAuth) */
#define SNMPV2AUTH  0x8000       /* V2 Authenticated requests only */

/* default list of mibs to load */

#define DEFAULT_MIBS "IP-MIB:IF-MIB:TCP-MIB:UDP-MIB:SNMPv2-MIB:RFC1213-MIB"

/* default location to look for mibs to load using the above tokens
   and/or those in the MIBS envrionment variable*/
#undef DEFAULT_MIBDIRS

/* default mib files to load, specified by path. */
#undef DEFAULT_MIBFILES

/* should we compile to use special opaque types: float, double,
   counter64, i64, ui64, union? */
#undef OPAQUE_SPECIAL_TYPES

/* comment the next line if you are compiling with libsnmp.h 
   and are not using the UC-Davis SNMP library. */
#define UCD_SNMP_LIBRARY 1

/* define if you want to compile support for both authentication and
   privacy support. */
#undef SCAPI_AUTHPRIV

/* define if you are using the MD5 code ...*/
#undef USE_INTERNAL_MD5

/* define if you are using the codeS11 library ...*/
#undef USE_PKCS

/* add in recent CMU library extensions (not complete) */
#undef CMU_COMPATIBLE

/* add in recent resource lock functions (not complete) */
#undef _REENTRANT

/* debugging stuff */
/* if defined, we optimize the code to exclude all debugging calls. */
#undef SNMP_NO_DEBUGGING
/* ignore the -D flag and always print debugging information */
#define SNMP_ALWAYS_DEBUG 0

/* reverse encoding BER packets is both faster and more efficient in space. */
#define USE_REVERSE_ASNENCODING       1
#define DEFAULT_ASNENCODING_DIRECTION 1 /* 1 = reverse, 0 = forwards */

/* PERSISTENT_DIRECTORY: If defined, the library is capabile of saving
   persisant information to this directory in the form of configuration
   lines: PERSISTENT_DIRECTORY/NAME.persistent.conf */
#define PERSISTENT_DIRECTORY "/var/snmp"

/* PERSISTENT_MASK: the umask permissions to set up persistent files with */
#define PERSISTENT_MASK 077

/* AGENT_DIRECTORY_MODE: the mode the agents should use to create
   directories with. Since the data stored here is probably sensitive, it
   probably should be read-only by root/administrator. */
#define AGENT_DIRECTORY_MODE 0700

/* MAX_PERSISTENT_BACKUPS:
 *   The maximum number of persistent backups the library will try to
 *   read from the persistent cache directory.  If an application fails to
 *   close down successfully more than this number of times, data will be lost.
 */
#define MAX_PERSISTENT_BACKUPS 10

@TOP@

/* define if you are embedding perl in the main agent */
#undef NETSNMP_EMBEDDED_PERL

/* define the system type include file here */
#define SYSTEM_INCLUDE_FILE <net-snmp/system/generic.h>

/* define the machine (cpu) type include file here */
#define MACHINE_INCLUDE_FILE <net-snmp/machine/generic.h>

/* define the UDP buffer defaults undefined means use the OS buffers
 * by default */
#undef DEFAULT_SERVER_SEND_BUF
#undef DEFAULT_SERVER_RECV_BUF
#undef DEFAULT_CLIENT_SEND_BUF
#undef DEFAULT_CLIENT_RECV_BUF

/* SNMPLIBDIR contains important files */
#undef SNMPLIBPATH
#undef SNMPSHAREPATH
#undef SNMPCONFPATH
#undef SNMPDLMODPATH

/* LOGFILE:  If defined it closes stdout/err/in and opens this in out/err's
   place.  (stdin is closed so that sh scripts won't wait for it) */
#undef LOGFILE

/* default system contact */
#undef SYS_CONTACT

/* system location */
#undef SYS_LOC

/* Use libwrap to handle allow/deny hosts? */
#undef USE_LIBWRAP

/* Use dmalloc to do malloc debugging? */
#undef HAVE_DMALLOC_H

/* location of UNIX kernel */
#define KERNEL_LOC "/vmunix"

/* location of mount table list */
#define ETC_MNTTAB "/etc/mnttab"

/* location of swap device (ok if not found) */
#undef DMEM_LOC

/* Command to generate ps output, the final column must be the process
   name withOUT arguments */
#define PSCMD "/bin/ps"

/* Where is the uname command */
#define UNAMEPROG "/bin/uname"

/* pattern for temporary file names */
#define NETSNMP_TEMP_FILE_PATTERN "/tmp/snmpdXXXXXX"

/* testing code sections. */
#undef SNMP_TESTING_CODE 

/* If you don't have root access don't exit upon kmem errors */
#undef NO_ROOT_ACCESS

/* If we don't want to use kmem. */
#undef NO_KMEM_USAGE

/* If you don't want the agent to report on variables it doesn't have data for */
#undef NO_DUMMY_VALUES

/* Define if statfs takes 2 args and the second argument has
   type struct fs_data. [Ultrix] */
#undef STAT_STATFS_FS_DATA

/* Define if the TCP timer constants in <netinet/tcp_timer.h>
   depend on the integer variable `hz'.  [FreeBSD 4.x] */
#undef TCPTV_NEEDS_HZ

@BOTTOM@

/* define if you have type int32_t */
#undef HAVE_INT32_T

/* define if you have type uint32_t */
#undef HAVE_UINT32_T

/* define if you have type u_int32_t */
#undef HAVE_U_INT32_T

/* define if you have type int64_t */
#undef HAVE_INT64_T

/* define if you have type uint64_t */
#undef HAVE_UINT64_T

/* define if you have type u_int64_t */
#undef HAVE_U_INT64_T

/* define if you have type intptr_t */
#undef HAVE_INTPTR_T

/* define if you have type uintptr_t */
#undef HAVE_UINTPTR_T

/* define if you have getdevs() */
#undef HAVE_GETDEVS

/* define if you have devstat_getdevs() */
#undef HAVE_DEVSTAT_GETDEVS

/* define if you have <netinet/in_pcb.h> */
#undef HAVE_NETINET_IN_PCB_H

/* define if you have <sys/disklabel.h> */
#undef HAVE_SYS_DISKLABEL_H

/* define if you are using linux and /proc/net/dev has the compressed
   field, which exists in linux kernels 2.2 and greater. */
#undef PROC_NET_DEV_HAS_COMPRESSED

/* define rtentry to ortentry on SYSV machines (alphas) */
#undef RTENTRY

/* Use BSD 4.4 routing table entries? */
#undef RTENTRY_4_4

/* Does struct sigaction have a sa_sigaction field? */
#undef STRUCT_SIGACTION_HAS_SA_SIGACTION

/* Does struct tm have a tm_gmtoff field? */
#undef STRUCT_TM_HAS_TM_GMTOFFF

/* Does struct sockaddr have a sa_len field? */
#undef STRUCT_SOCKADDR_HAS_SA_LEN

/* Does struct sockaddr have a sa_family2 field? */
#undef STRUCT_SOCKADDR_HAS_SA_UNION_SA_GENERIC_SA_FAMILY2

/* Does struct in6_addr have a s6_un.sa6_ladd field? */
#undef STRUCT_IN6_ADDR_HAS_S6_UN_SA6_LADDR

/* rtentry structure tests */
#undef RTENTRY_RT_NEXT
#undef STRUCT_RTENTRY_HAS_RT_DST
#undef STRUCT_RTENTRY_HAS_RT_UNIT
#undef STRUCT_RTENTRY_HAS_RT_USE
#undef STRUCT_RTENTRY_HAS_RT_REFCNT
#undef STRUCT_RTENTRY_HAS_RT_HASH

/* ifnet structure tests */
#undef STRUCT_IFNET_HAS_IF_BAUDRATE
#undef STRUCT_IFNET_HAS_IF_BAUDRATE_IFS_VALUE
#undef STRUCT_IFNET_HAS_IF_SPEED
#undef STRUCT_IFNET_HAS_IF_TYPE
#undef STRUCT_IFNET_HAS_IF_IMCASTS
#undef STRUCT_IFNET_HAS_IF_IQDROPS
#undef STRUCT_IFNET_HAS_IF_LASTCHANGE_TV_SEC
#undef STRUCT_IFNET_HAS_IF_NOPROTO
#undef STRUCT_IFNET_HAS_IF_OMCASTS
#undef STRUCT_IFNET_HAS_IF_XNAME
#undef STRUCT_IFNET_HAS_IF_OBYTES
#undef STRUCT_IFNET_HAS_IF_IBYTES
#undef STRUCT_IFNET_HAS_IF_ADDRLIST

/* tcpstat.tcps_rcvmemdrop */
#undef STRUCT_TCPSTAT_HAS_TCPS_RCVMEMDROP

/* udpstat.udps_discard */
#undef STRUCT_UDPSTAT_HAS_UDPS_DISCARD

/* udpstat.udps_discard */
#undef STRUCT_UDPSTAT_HAS_UDPS_NOPORT

/* udpstat.udps_discard */
#undef STRUCT_UDPSTAT_HAS_UDPS_NOPORTBCAST

/* udpstat.udps_discard */
#undef STRUCT_UDPSTAT_HAS_UDPS_FULLSOCK

/* arphd.at_next */
#undef STRUCT_ARPHD_HAS_AT_NEXT

/* ifaddr.ifa_next */
#undef STRUCT_IFADDR_HAS_IFA_NEXT

/* ifnet.if_mtu */
#undef STRUCT_IFNET_HAS_IF_MTU

/* swdevt.sw_nblksenabled */
#undef STRUCT_SWDEVT_HAS_SW_NBLKSENABLED

/* nlist.n_value */
#undef STRUCT_NLIST_HAS_N_VALUE

/* ipstat structure tests */
#undef STRUCT_IPSTAT_HAS_IPS_CANTFORWARD
#undef STRUCT_IPSTAT_HAS_IPS_CANTFRAG
#undef STRUCT_IPSTAT_HAS_IPS_DELIVERED
#undef STRUCT_IPSTAT_HAS_IPS_FRAGDROPPED
#undef STRUCT_IPSTAT_HAS_IPS_FRAGTIMEOUT
#undef STRUCT_IPSTAT_HAS_IPS_LOCALOUT
#undef STRUCT_IPSTAT_HAS_IPS_NOPROTO
#undef STRUCT_IPSTAT_HAS_IPS_NOROUTE
#undef STRUCT_IPSTAT_HAS_IPS_ODROPPED
#undef STRUCT_IPSTAT_HAS_IPS_OFRAGMENTS
#undef STRUCT_IPSTAT_HAS_IPS_REASSEMBLED

/* vfsstat.f_frsize */
#undef STRUCT_STATVFS_HAS_F_FRSIZE

/* vfsstat.f_files */
#undef STRUCT_STATVFS_HAS_F_FILES

/* statfs inode structure tests*/
#undef STRUCT_STATFS_HAS_F_FILES
#undef STRUCT_STATFS_HAS_F_FFREE
#undef STRUCT_STATFS_HAS_F_FAVAIL

/* des_ks_struct.weak_key */
#undef STRUCT_DES_KS_STRUCT_HAS_WEAK_KEY

/* ifnet needs to have _KERNEL defined */
#undef IFNET_NEEDS_KERNEL

/* sysctl works to get boottime, etc... */
#undef CAN_USE_SYSCTL

/* type check for in_addr_t */
#undef in_addr_t

/* define if SIOCGIFADDR exists in sys/ioctl.h */
#undef SYS_IOCTL_H_HAS_SIOCGIFADDR

/* define if your compiler (processor) defines __FUNCTION__ for you */
#undef HAVE_CPP_UNDERBAR_FUNCTION_DEFINED

/* Mib-2 tree Info */
/* These are the system information variables. */

#define VERS_DESC   "unknown"             /* overridden at run time */
#define SYS_NAME    "unknown"             /* overridden at run time */

/* comment out the second define to turn off functionality for any of
   these: (See README for details) */

/*   proc PROCESSNAME [MAX] [MIN] */
#define PROCMIBNUM 2

/*   exec/shell NAME COMMAND      */
#define SHELLMIBNUM 8

/*   swap MIN                     */
#define MEMMIBNUM 4

/*   disk DISK MINSIZE            */
#define DISKMIBNUM 9

/*   load 1 5 15                  */
#define LOADAVEMIBNUM 10

/* which version are you using? This mibloc will tell you */
#define VERSIONMIBNUM 100

/* Reports errors the agent runs into */
/* (typically its "can't fork, no mem" problems) */
#define ERRORMIBNUM 101

/* The sub id of EXTENSIBLEMIB returned to queries of
   .iso.org.dod.internet.mgmt.mib-2.system.sysObjectID.0 */
#define AGENTID 250

/* This ID is returned after the AGENTID above.  IE, the resulting
   value returned by a query to sysObjectID is
   EXTENSIBLEMIB.AGENTID.???, where ??? is defined below by OSTYPE */

#define HPUX9ID 1
#define SUNOS4ID 2 
#define SOLARISID 3
#define OSFID 4
#define ULTRIXID 5
#define HPUX10ID 6
#define NETBSD1ID 7
#define FREEBSDID 8
#define IRIXID 9
#define LINUXID 10
#define BSDIID 11
#define OPENBSDID 12
#define WIN32ID 13
#define HPUX11ID 14
#define AIXID 15
#define MACOSXID 16
#define UNKNOWNID 255

#ifdef hpux9
#define OSTYPE HPUX9ID
#endif
#ifdef hpux10
#define OSTYPE HPUX10ID
#endif
#ifdef hpux11
#define OSTYPE HPUX11ID
#endif
#ifdef sunos4
#define OSTYPE SUNOS4ID
#endif
#ifdef solaris2
#define OSTYPE SOLARISID
#endif
#if defined(osf3) || defined(osf4) || defined(osf5)
#define OSTYPE OSFID
#endif
#ifdef ultrix4
#define OSTYPE ULTRIXID
#endif
#if defined(netbsd1) || defined(netbsd2)
#define OSTYPE NETBSD1ID
#endif
#if defined(__FreeBSD__)
#define OSTYPE FREEBSDID
#endif
#if defined(irix6) || defined(irix5)
#define OSTYPE IRIXID
#endif
#ifdef linux
#define OSTYPE LINUXID
#endif
#if defined(bsdi2) || defined(bsdi3) || defined(bsdi4)
#define OSTYPE BSDIID
#endif
#if defined(openbsd2) || defined(openbsd3)
#define OSTYPE OPENBSDID
#endif
#ifdef WIN32
#define OSTYPE WIN32ID
#endif
#if defined(aix3) || defined(aix4) || defined(aix5)
#define OSTYPE AIXID
#endif
#ifdef darwin8
#define OSTYPE MACOSXID
#endif
/* unknown */
#ifndef OSTYPE
#define OSTYPE UNKNOWNID
#endif

/* The enterprise number has been assigned by the IANA group.   */
/* Optionally, this may point to the location in the tree your  */
/* company/organization has been allocated.                     */
/* The assigned enterprise number for the NET_SNMP MIB modules. */
#define ENTERPRISE_OID			8072
#define ENTERPRISE_MIB			1,3,6,1,4,1,8072
#define ENTERPRISE_DOT_MIB		1.3.6.1.4.1.8072
#define ENTERPRISE_DOT_MIB_LENGTH	7

/* The assigned enterprise number for sysObjectID. */
#define SYSTEM_MIB		1,3,6,1,4,1,8072,3,2,OSTYPE
#define SYSTEM_DOT_MIB		1.3.6.1.4.1.8072.3.2.OSTYPE
#define SYSTEM_DOT_MIB_LENGTH	10

/* The assigned enterprise number for notifications. */
#define NOTIFICATION_MIB		1,3,6,1,4,1,8072,4
#define NOTIFICATION_DOT_MIB		1.3.6.1.4.1.8072.4
#define NOTIFICATION_DOT_MIB_LENGTH	8

/* this is the location of the ucdavis mib tree.  It shouldn't be
   changed, as the places it is used are expected to be constant
   values or are directly tied to the UCD-SNMP-MIB. */
#define UCDAVIS_OID		2021
#define UCDAVIS_MIB		1,3,6,1,4,1,2021
#define UCDAVIS_DOT_MIB		1.3.6.1.4.1.2021
#define UCDAVIS_DOT_MIB_LENGTH	7

/* this is the location of the net-snmp mib tree.  It shouldn't be
   changed, as the places it is used are expected to be constant
   values or are directly tied to the UCD-SNMP-MIB. */
#define NETSNMP_OID		8072
#define NETSNMP_MIB		1,3,6,1,4,1,8072
#define NETSNMP_DOT_MIB		1.3.6.1.4.1.8072
#define NETSNMP_DOT_MIB_LENGTH	7

/* how long to wait (seconds) for error querys before reseting the error trap.*/
#define ERRORTIMELENGTH 600 

/* Exec command to fix PROC problems */
/* %s will be replaced by the process name in error */

/* #define PROCFIXCMD "/usr/bin/perl /local/scripts/fixproc %s" */

/* Exec command to fix EXEC problems */
/* %s will be replaced by the exec/script name in error */

/* #define EXECFIXCMD "/usr/bin/perl /local/scripts/fixproc %s" */

/* Should exec output Cashing be used (speeds up things greatly), and
   if so, After how many seconds should the cache re-newed?  Note:
   Don't define CASHETIME to disable cashing completely */

#define EXCACHETIME 30
#define CACHEFILE ".snmp-exec-cache"
#define MAXCACHESIZE (200*80)   /* roughly 200 lines max */

/* misc defaults */

/* default of 100 meg minimum if the minimum size is not specified in
   the config file */
#define DEFDISKMINIMUMSPACE 100000

#define DEFMAXLOADAVE 12.0      /* default maximum load average before error */

/* Because of sleep(1)s, this will also be time to wait (in seconds) for exec
   to finish */
#define MAXREADCOUNT 100   /* max times to loop reading output from execs. */

/* The original CMU code had this hardcoded as = 1 */
#define SNMPBLOCK 1       /* Set if snmpgets should block and never timeout */

/* How long to wait before restarting the agent after a snmpset to
   EXTENSIBLEMIB.VERSIONMIBNUM.VERRESTARTAGENT.  This is
   necessary to finish the snmpset reply before restarting. */
#define RESTARTSLEEP 5

/* Number of community strings to store */
#define NUM_COMMUNITIES	5

/* UNdefine to allow specifying zero-length community string */
/* #define NO_ZEROLENGTH_COMMUNITY 1 */

/* #define EXIT_ON_BAD_KLREAD  */
/* define to exit the agent on a bad kernel read */

#define LASTFIELD -1      /* internal define */

/* configure options specified */
#define CONFIGURE_OPTIONS ""

/* got socklen_t? */
#undef HAVE_SOCKLEN_T

/* got in_addr_t? */
#undef HAVE_IN_ADDR_T

/* got ssize_t? */
#undef HAVE_SSIZE_T

#ifndef HAVE_STRCHR
#ifdef HAVE_INDEX
# define strchr index
# define strrchr rindex
#endif
#endif

#ifndef HAVE_INDEX
#ifdef HAVE_STRCHR
#ifdef mingw32
# define index(a,b) strchr(a,b)
# define rindex(a,b) strrchr(a,b)
#else
# define index strchr
# define rindex strrchr
#endif
#endif
#endif

#ifndef HAVE_MEMCPY
#ifdef HAVE_BCOPY
# define memcpy(d, s, n) bcopy ((s), (d), (n))
# define memmove(d, s, n) bcopy ((s), (d), (n))
# define memcmp bcmp
#endif
#endif

#ifndef HAVE_MEMMOVE
#ifdef HAVE_MEMCPY
# define memmove memcpy
#endif
#endif

#ifndef HAVE_BCOPY
#ifdef HAVE_MEMCPY
# define bcopy(s, d, n) memcpy ((d), (s), (n))
# define bzero(p,n) memset((p),(0),(n))
# define bcmp memcmp
#endif
#endif

/* If you have openssl 0.9.7 or above, you likely have AES support. */
#undef USE_OPENSSL
#if defined(USE_OPENSSL) && defined(HAVE_OPENSSL_AES_H) && defined(HAVE_AES_CFB128_ENCRYPT)
#define HAVE_AES 1
#endif

/* define random functions */

#ifndef HAVE_RANDOM
#ifdef HAVE_LRAND48
#define random lrand48
#define srandom(s) srand48(s)
#else
#ifdef HAVE_RAND
#define random rand
#define srandom(s) srand(s)
#endif
#endif
#endif

/* define signal if DNE */

#ifndef HAVE_SIGNAL
#ifdef HAVE_SIGSET
#define signal(a,b) sigset(a,b)
#endif
#endif

/* define if you have librpm and libdb */
#undef HAVE_LIBDB
#undef HAVE_LIBRPM

/* define if you have pkginfo */
#undef HAVE_PKGINFO

/* define if you have gethostbyname */
#undef HAVE_GETHOSTBYNAME

/* define if you have getservbyname */
#undef HAVE_GETSERVBYNAME

/* printing system */
#undef HAVE_LPSTAT
#undef LPSTAT_PATH
#undef HAVE_PRINTCAP

/*  Pluggable transports.  */

/*  This is defined if support for the UDP/IP transport domain is
    available.   */
#undef SNMP_TRANSPORT_UDP_DOMAIN

/*  This is defined if support for the "callback" transport domain is
    available.   */
#undef SNMP_TRANSPORT_CALLBACK_DOMAIN

/*  This is defined if support for the TCP/IP transport domain is
    available.  */
#undef SNMP_TRANSPORT_TCP_DOMAIN

/*  This is defined if support for the Unix transport domain
    (a.k.a. "local IPC") is available.  */
#undef SNMP_TRANSPORT_UNIX_DOMAIN

/*  This is defined if support for the AAL5 PVC transport domain is
    available.  */
#undef SNMP_TRANSPORT_AAL5PVC_DOMAIN

/*  This is defined if support for the IPX transport domain is
    available.  */
#undef SNMP_TRANSPORT_IPX_DOMAIN

/*  This is defined if support for the UDP/IPv6 transport domain is
    available.  */
#undef SNMP_TRANSPORT_UDPIPV6_DOMAIN

/*  This is defined if support for the TCP/IPv6 transport domain is
    available.  */
#undef SNMP_TRANSPORT_TCPIPV6_DOMAIN

/*  This is defined if support for the UDP/IP transport domain is
    available.   */
#undef SNMP_TRANSPORT_TLS_DOMAIN

/*  This is defined if support for stdin/out transport domain is available.   */
#undef SNMP_TRANSPORT_STD_DOMAIN

/* define this if the USM security module is available */
#undef SNMP_SECMOD_USM

/* define this if the KSM (kerberos based snmp) security module is available */
#undef SNMP_SECMOD_KSM

/* define this if the local security module is available */
#undef SNMP_SECMOD_LOCALSM

/* define this if we're using the new MIT crypto API */
#undef MIT_NEW_CRYPTO

/* define if you want to build with reentrant/threaded code (incomplete)*/
#undef NS_REENTRANT

/* define if you want to build MFD module rewrites*/
#undef NETSNMP_ENABLE_MFD_REWRITES

/* on aix, if you have perfstat */
#undef HAVE_PERFSTAT

/* Not-to-be-compiled macros for use by configure only */
#define config_require(x)
#define config_exclude(x)
#define config_arch_require(x,y)
#define config_parse_dot_conf(w,x,y,z)
#define config_add_mib(x)
#define config_belongs_in(x)
  
#if defined (WIN32) || defined (mingw32) || defined (cygwin)
#define ENV_SEPARATOR ";"
#define ENV_SEPARATOR_CHAR ';'
#else
#define ENV_SEPARATOR ":"
#define ENV_SEPARATOR_CHAR ':'
#endif

/*
 * this must be before the system/machine includes, to allow them to
 * override and turn off inlining. To do so, they should do the
 * following:
 *
 *    #undef NETSNMP_ENABLE_INLINE
 *    #define NETSNMP_ENABLE_INLINE 0
 *
 * A user having problems with their compiler can also turn off
 * the use of inline by defining NETSNMP_NO_INLINE via their cflags:
 *
 *    -DNETSNMP_NO_INLINE
 *
 * Header and source files should only test against NETSNMP_USE_INLINE:
 *
 *   #ifdef NETSNMP_USE_INLINE
 *   NETSNMP_INLINE function(int parm) { return parm -1; }
 *   #endif
 *
 * Functions which should be static, regardless of whether or not inline
 * is available or enabled should use the NETSNMP_STATIC_INLINE macro,
 * like so:
 *
 *    NETSNMP_STATIC_INLINE function(int parm) { return parm -1; }
 *
 * NOT like this:
 *
 *    static NETSNMP_INLINE function(int parm) { return parm -1; }
 *
 */
#undef NETSNMP_BROKEN_INLINE
#ifdef NETSNMP_BROKEN_INLINE
#   define NETSNMP_ENABLE_INLINE 0
#else
#   define NETSNMP_ENABLE_INLINE 1
#endif

#include SYSTEM_INCLUDE_FILE
#include MACHINE_INCLUDE_FILE

#if NETSNMP_ENABLE_INLINE && !defined(NETSNMP_NO_INLINE)
#   define NETSNMP_USE_INLINE 1
#   ifndef NETSNMP_INLINE
#      define NETSNMP_INLINE inline
#   endif
#   ifndef NETSNMP_STATIC_INLINE
#      define NETSNMP_STATIC_INLINE static inline
#   endif
#else
#   define NETSNMP_INLINE 
#   define NETSNMP_STATIC_INLINE static
#endif

#ifndef NETSNMP_IMPORT
#  define NETSNMP_IMPORT extern
#endif

#if defined(HAVE_NLIST) && defined(STRUCT_NLIST_HAS_N_VALUE) && !defined(DONT_USE_NLIST) && !defined(NO_KMEM_USAGE)
#define CAN_USE_NLIST
#endif

#if HAVE_DMALLOC_H
#define DMALLOC_FUNC_CHECK
#endif

#undef INET6
#undef LOCAL_SMUX

/* define if agentx transport is to use domain sockets only */
#undef AGENTX_DOM_SOCK_ONLY

/* define if you do not want snmptrapd to register as an AgentX subagent */
#undef SNMPTRAPD_DISABLE_AGENTX

#undef HEIMDAL

#endif /* NET_SNMP_CONFIG_H */
