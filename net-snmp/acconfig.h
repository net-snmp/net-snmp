/* config.h:  a general config file */

/* Define IN_UCD_SNMP_SOURCE if compiling inside the ucd-snmp source tree */
#define IN_UCD_SNMP_SOURCE 1

/* Our assigned enterprise number */
#define ENTERPRISE_NUMBER 2021

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

/* ... or define this if you're using openssl support */
#undef USE_OPENSSL

/* add in recent CMU library extensions (not complete) */
#undef CMU_COMPATIBLE

/* add in recent resource lock functions (not complete) */
#undef _REENTRANT

/* debugging stuff */
#undef SNMP_NO_DEBUGGING           /* if defined, we optimize the code
                                      to exclude all debugging calls. */
#define SNMP_ALWAYS_DEBUG 0        /* Always print debugging information and
                                      ignore the -D flag passed to the cmds */

/* reverse encoding BER packets is both faster and more efficient in space. */
#define USE_REVERSE_ASNENCODING       1
#define DEFAULT_ASNENCODING_DIRECTION 1 /* 1 = reverse, 0 = forwards */

/* PERSISTENT_DIRECTORY: If defined, the library is capabile of saving
   persisant information to this directory in the form of configuration
   lines: PERSISTENT_DIRECTORY/NAME.persistent.conf */
#define PERSISTENT_DIRECTORY "/var/snmp"

/* PERSISTENT_MASK: the umask permissions to set up the persistent files with */
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

/* define the system type include file here */
#define SYSTEM_INCLUDE_FILE "s/generic.h"

/* define the machine (cpu) type include file here */
#define MACHINE_INCLUDE_FILE "m/generic.h"

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

/* testing code sections. */
#undef SNMP_TESTING_CODE 

/* If you don't have root access don't exit upon kmem errors */
#undef NO_ROOT_ACCESS

/* If you don't want the agent to report on variables it doesn't have data for */
#undef NO_DUMMY_VALUES

/* Define if statfs takes 2 args and the second argument has
   type struct fs_data. [Ultrix] */
#undef STAT_STATFS_FS_DATA

/* Define if the TCP timer constants in <netinet/tcp_timer.h>
   depend on the integer variable `hz'.  [FreeBSD 4.x] */
#undef TCPTV_NEEDS_HZ

@BOTTOM@

/* define if you have <netinet/in_pcb.h> */
#undef HAVE_NETINET_IN_PCB_H

/* define if you are using linux and /proc/net/dev has the compressed
   field, which exists in linux kernels 2.2 and greater. */
#undef PROC_NET_DEV_HAS_COMPRESSED

/* define rtentry to ortentry on SYSV machines (alphas) */
#undef RTENTRY

/* Use BSD 4.4 routing table entries? */
#undef RTENTRY_4_4

/* Does struct sigaction have a sa_sigaction field? */
#undef STRUCT_SIGACTION_HAS_SA_SIGACTION

/* Does struct sockaddr have a sa_len field? */
#undef STRUCT_SOCKADDR_HAS_SA_LEN

/* Does struct sockaddr have a sa_family2 field? */
#undef STRUCT_SOCKADDR_HAS_SA_UNION_SA_GENERIC_SA_FAMILY2

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

/* vfsstat.f_frsize */
#undef STRUCT_STATVFS_HAS_F_FRSIZE

/* vfsstat.f_files */
#undef STRUCT_STATVFS_HAS_F_FILES

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

/* mib pointer to the top of the extensible tree.  This has been
 assigned to UCDavis by the iana group.  Optionally, point this to the
 location in the tree your company/organization has been allocated. */

/* location of the extensible mib tree */
#define EXTENSIBLEMIB 1,3,6,1,4,1,2021
/* location of the extensible mib tree */
#define EXTENSIBLEDOTMIB 1.3.6.1.4.1.2021
/* count the above numbers */
#define EXTENSIBLENUM 7

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

/* The sub id of EXENSIBLEMIB returned to queries of
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
#define UNKNOWNID 255

#ifdef hpux9
#define OSTYPE HPUX9ID
#endif
#ifdef hpux10
#define OSTYPE HPUX10ID
#endif
#ifdef sunos4
#define OSTYPE SUNOS4ID
#endif
#ifdef solaris2
#define OSTYPE SOLARISID
#endif
#if defined(osf3) || defined(osf4)
#define OSTYPE OSFID
#endif
#ifdef ultrix4
#define OSTYPE ULTRIXID
#endif
#ifdef netbsd1
#define OSTYPE NETBSD1ID
#endif
#ifdef freebsd2
#define OSTYPE FREEBSDID
#endif
#if defined(irix6) || defined(irix5)
#define OSTYPE IRIXID
#endif
#ifdef linux
#define OSTYPE LINUXID
#endif
#if defined(bsdi2) || defined(bsdi3)
#define OSTYPE BSDIID
#endif
#ifdef openbsd2
#define OSTYPE OPENBSDID
#endif
/* unknown */
#ifndef OSTYPE
#define OSTYPE UNKNOWNID
#endif

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

#define MAXDISKS 50                      /* can't scan more than this number */

/* misc defaults */

/* default of 100 meg minimum if the minimum size is not specified in
   the config file */
#define DEFDISKMINIMUMSPACE 100000

#define DEFMAXLOADAVE 12.0      /* default maximum load average before error */

#define MAXREADCOUNT 100   /* max times to loop reading output from
                              execs.  Because of sleep(1)s, this will also
                              be time to wait (in seconds) for exec to finish */

#define SNMPBLOCK 1       /* Set to 1 if you want snmpgets to block and never
                             timeout.  Original CMU code had this
                             hardcoded into the code as = 1 */

#define RESTARTSLEEP 5    /* How long to wait after a snmpset to
                             EXTENSIBLEMIB.VERSIONMIBNUM.VERRESTARTAGENT
                             before restarting the agent.  This is
                             necessary to finish the snmpset reply
                             before restarting. */

/* Number of community strings to store */
#define NUM_COMMUNITIES	5

/* UNdefine to allow specifying zero-length community string */
/* #define NO_ZEROLENGTH_COMMUNITY 1 */

/* #define EXIT_ON_BAD_KLREAD  */
/* define to exit the agent on a bad kernel read */

#define LASTFIELD -1      /* internal define */

/* configure options specified */
#define CONFIGURE_OPTIONS ""

#ifndef HAVE_STRCHR
#ifdef HAVE_INDEX
# define strchr index
# define strrchr rindex
#endif
#endif

#ifndef HAVE_INDEX
#ifdef HAVE_STRCHR
# define index strchr
# define rindex strrchr
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

/* define if you want to build with reentrant/threaded code */
#undef NS_REENTRANT

/* Not-to-be-compiled macros for use by configure only */
#define config_require(x)
#define config_arch_require(x,y)
#define config_parse_dot_conf(w,x,y,z)
#define config_add_mib(x)
  
#ifdef WIN32
#define ENV_SEPARATOR ";"
#define ENV_SEPARATOR_CHAR ';'
#else
#define ENV_SEPARATOR ":"
#define ENV_SEPARATOR_CHAR ':'
#endif

#include SYSTEM_INCLUDE_FILE
#include MACHINE_INCLUDE_FILE

#if defined(HAVE_NLIST) && defined(STRUCT_NLIST_HAS_N_VALUE) && !defined(DONT_USE_NLIST)
#define CAN_USE_NLIST
#endif

#if HAVE_DMALLOC_H
#define DMALLOC_FUNC_CHECK
#endif

#undef INET6

