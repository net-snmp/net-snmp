/* config.h.in.  Generated automatically from configure.in by autoheader.  */
/* config.h:  a general config file */

/* don't change these values! */
#define SNMPV1      0xAAAA       /* readable by anyone */
#define SNMPV2ANY   0xA000       /* V2 Any type (includes NoAuth) */
#define SNMPV2AUTH  0x8000       /* V2 Authenticated requests only */

/* default list of mibs to load */
#define DEFAULT_MIBS "IP-MIB:IF-MIB:TCP-MIB:UDP-MIB:SNMPv2-MIB:RFC1213-MIB:UCD-SNMP-MIB"

/* default location to look for mibs to load */
#define DEFAULT_MIBDIRS "\\USR\\MIBS"

/* default location to look for mibs to load */
#undef DEFAULT_MIBFILES

/* typedef for abreviated types */
/* typedef unsigned char u_char; */
/* typedef unsigned long u_long; */

/* Define if using alloca.c.  */
#undef C_ALLOCA

/* Define if the closedir function returns void instead of int.  */
#undef CLOSEDIR_VOID

/* Define to one of _getb67, GETB67, getb67 for Cray-2 and Cray-YMP systems.
   This function is required for alloca.c support on those systems.  */
#undef CRAY_STACKSEG_END

/* Define if you have alloca, as a function or macro.  */
#undef HAVE_ALLOCA

/* Define if you have <alloca.h> and it should be used (not on Ultrix).  */
#undef HAVE_ALLOCA_H

/* Define if you have the getmntent function.  */
#undef HAVE_GETMNTENT

/* Define if you have <sys/wait.h> that is POSIX.1 compatible.  */
#undef HAVE_SYS_WAIT_H

/* Define to `long' if <sys/types.h> doesn't define.  */
#undef off_t

/* Define to `int' if <sys/types.h> doesn't define.  */
#undef pid_t

/* Define as the return type of signal handlers (int or void).  */
#undef RETSIGTYPE

/* If using the C implementation of alloca, define if you know the
   direction of stack growth for your system; otherwise it will be
   automatically deduced at run-time.
 STACK_DIRECTION > 0 => grows toward higher addresses
 STACK_DIRECTION < 0 => grows toward lower addresses
 STACK_DIRECTION = 0 => direction of growth unknown
 */
#undef STACK_DIRECTION

/* Define if you have the ANSI C header files.  */
#define STDC_HEADERS 1

/* Define if you can safely include both <sys/time.h> and <time.h>.  */
#define TIME_WITH_SYS_TIME 1
#define SYS_TIME_NAME <sys/timeb.h>   /* change depending on name */

/* Define if you have the gettimeofday function.  */
#undef HAVE_GETTIMEOFDAY

/* Define if you have the <sys/time.h> header file.  */
#undef HAVE_SYS_TIME_H

/* Define if the closedir function returns void instead of int.  */
#undef VOID_CLOSEDIR

/* Define if your processor stores words with the most significant
   byte first (like Motorola and SPARC, unlike Intel and VAX).  */
#undef WORDS_BIGENDIAN

#define SNMPLIBPATH "\\USR"

/* SNMPPATH contains (more) important files */

#undef SNMPPATH

/* LOGFILE:  If defined it closes stdout/err/in and opens this in out/err's
   place.  (stdin is closed so that sh scripts won't wait for it) */

#undef LOGFILE

/* to hack in forced V2 security, I had to reserve the left byte of
   the ACL Mib word for V2.  Do NOT define more than 5 V1 communities
   else they will roll into these definitions (see snmp_vars.c:340) 
   If GLOBALSECURITY is defined, it sets the default SNMP access type
   for the extensible mibs to the setting type described. */

#define GLOBALSECURITY SNMPV2AUTH    /* only authenticated snmpv2 requests
                                        permited */

/* default system contact */
#undef SYS_CONTACT

/* system location */
#undef SYS_LOC

/* location of UNIX kernel */
#define KERNEL_LOC "/vmunix"

/* location of mount table list */
#define ETC_MNTTAB "/etc/mnttab"

/* location of swap device (ok if not found) */
#undef DMEM_LOC

/* define rtentry to ortentry on SYSV machines (alphas) */
#define RTENTRY rtentry;

/* Use BSD 4.4 routing table entries? */
#undef RTENTRY_4_4

/* Does the rtentry structure have a rt_next node */
#undef RTENTRY_RT_NEXT

#define PSCMD "/bin/ps"

/* Where is the uname command */
#define UNAMEPROG "/bin/uname"

/* debugging stuff */
#undef DODEBUG

/* If you don't have root access don't exit upon kmem errors */
#undef NO_ROOT_ACCESS

/* Define if you have the bcopy function.  */
#undef HAVE_BCOPY

/* Define if you have the gethostname function.  */
#undef HAVE_GETHOSTNAME

/* Define if you have the getloadavg function.  */
#undef HAVE_GETLOADAVG

/* Define if you have the index function.  */
#undef HAVE_INDEX

/* Define if you have the kvm_openfiles function.  */
#undef HAVE_KVM_OPENFILES

/* Define if you have the lrand48 function.  */
#undef HAVE_LRAND48

/* Define if you have the memcpy function.  */
#define HAVE_MEMCPY 1

/* Define if you have the memmove function.  */
#define HAVE_MEMMOVE 1

/* Define if you have the rand function.  */
#define HAVE_RAND 1

/* Define if you have the random function.  */
#undef HAVE_RANDOM

/* Define if you have the select function.  */
#undef HAVE_SELECT

/* Define if you have the setmntent function.  */
#undef HAVE_SETMNTENT

/* Define if you have the sigblock function.  */
#undef HAVE_SIGBLOCK

/* Define if you have the sighold function.  */
#undef HAVE_SIGHOLD

/* Define if you have the signal function.  */
#undef HAVE_SIGNAL

/* Define if you have the sigset function.  */
#undef HAVE_SIGSET

/* Define if you have the socket function.  */
#define HAVE_SOCKET 1

/* Define if you have <winsock.h> header file. */
#define HAVE_WINSOCK_H 1

/* Define if you have the closesocket function.  */
#define HAVE_CLOSESOCKET 1

/* Define if you have the statfs function.  */
#undef HAVE_STATFS

/* Define if you have the statvfs function.  */
#undef HAVE_STATVFS

/* Define if you have the strchr function.  */
#define HAVE_STRCHR 1

/* Define if you do not have strcasecmp */
#define strcasecmp _stricmp

/* use win32 strdup */
#define strdup _strdup

/* Define if you have the strtol function.  */
#define HAVE_STRTOL 1

/* Define if you have the uname function.  */
#undef HAVE_UNAME

/* Define if you have <io.h> header file. */
#define HAVE_IO_H 1

/* Define if you have the <arpa/inet.h> header file.  */
#undef HAVE_ARPA_INET_H

/* Define if you have the <dirent.h> header file.  */
#undef HAVE_DIRENT_H

/* Define if you have the <err.h> header file.  */
#undef HAVE_ERR_H

/* Define if you have the <fcntl.h> header file.  */
#define HAVE_FCNTL_H 1

/* Define if you have the <fstab.h> header file.  */
#undef HAVE_FSTAB_H

/* Define if you have the <inet/mib2.h> header file.  */
#undef HAVE_INET_MIB2_H

/* Define if you have the <kstat.h> header file.  */
#undef HAVE_KSTAT_H

/* Define if you have the <kvm.h> header file.  */
#undef HAVE_KVM_H

/* Define if you have the <limits.h> header file.  */
#define HAVE_LIMITS_H 1

/* Define if you have the <machine/param.h> header file.  */
#undef HAVE_MACHINE_PARAM_H

/* Define if you have the <machine/pte.h> header file.  */
#undef HAVE_MACHINE_PTE_H

/* Define if you have the <malloc.h> header file.  */
#undef HAVE_MALLOC_H

/* Define if you have the <mntent.h> header file.  */
#undef HAVE_MNTENT_H

/* Define if you have the <mtab.h> header file.  */
#undef HAVE_MTAB_H

/* Define if you have the <ndir.h> header file.  */
#undef HAVE_NDIR_H

/* Define if you have the <net/if_dl.h> header file.  */
#undef HAVE_NET_IF_DL_H

/* Define if you have the <net/if_types.h> header file.  */
#undef HAVE_NET_IF_TYPES_H

/* Define if you have the <netinet/icmp_var.h> header file.  */
#undef HAVE_NETINET_ICMP_VAR_H

/* Define if you have the <netinet/if_ether.h> header file.  */
#undef HAVE_NETINET_IF_ETHER_H

/* Define if you have the <netinet/in.h> header file.  */
#undef HAVE_NETINET_IN_H

/* Define if you have the <netinet/in_pcb.h> header file.  */
#undef HAVE_NETINET_IN_PCB_H

/* Define if you have the <netinet/in_var.h> header file.  */
#undef HAVE_NETINET_IN_VAR_H

/* Define if you have the <netinet/ip_var.h> header file.  */
#undef HAVE_NETINET_IP_VAR_H

/* Define if you have the <netinet/tcp_fsm.h> header file.  */
#undef HAVE_NETINET_TCP_FSM_H

/* Define if you have the <netinet/tcp_timer.h> header file.  */
#undef HAVE_NETINET_TCP_TIMER_H

/* Define if you have the <netinet/tcp_var.h> header file.  */
#undef HAVE_NETINET_TCP_VAR_H

/* Define if you have the <netinet/tcpip.h> header file.  */
#undef HAVE_NETINET_TCPIP_H

/* Define if you have the <netinet/udp_var.h> header file.  */
#undef HAVE_NETINET_UDP_VAR_H

/* Define if you have the <sgtty.h> header file.  */
#undef HAVE_SGTTY_H

/* Define if you have the <stdlib.h> header file.  */
#define HAVE_STDLIB_H 1

/* Define if you have the <strings.h> header file.  */
#undef HAVE_STRINGS_H

/* Define if you have the <sys/conf.h> header file.  */
#undef HAVE_SYS_CONF_H

/* Define if you have the <sys/dir.h> header file.  */
#undef HAVE_SYS_DIR_H

/* Define if you have the <sys/dmap.h> header file.  */
#undef HAVE_SYS_DMAP_H

/* Define if you have the <sys/file.h> header file.  */
#undef HAVE_SYS_FILE_H

/* Define if you have the <sys/filio.h> header file.  */
#undef HAVE_SYS_FILIO_H

/* Define if you have the <sys/fixpoint.h> header file.  */
#undef HAVE_SYS_FIXPOINT_H

/* Define if you have the <sys/fs.h> header file.  */
#undef HAVE_SYS_FS_H

/* Define if you have the <sys/hashing.h> header file.  */
#undef HAVE_SYS_HASHING_H

/* Define if you have the <sys/ioctl.h> header file.  */
#undef HAVE_SYS_IOCTL_H

/* Define if you have the <sys/mbuf.h> header file.  */
#undef HAVE_SYS_MBUF_H

/* Define if you have the <sys/mnttab.h> header file.  */
#undef HAVE_SYS_MNTTAB_H

/* Define if you have the <sys/mount.h> header file.  */
#undef HAVE_SYS_MOUNT_H

/* Define if you have the <sys/ndir.h> header file.  */
#undef HAVE_SYS_NDIR_H

/* Define if you have the <sys/param.h> header file.  */
#undef HAVE_SYS_PARAM_H

/* Define if you have the <sys/proc.h> header file.  */
#undef HAVE_SYS_PROC_H

/* Define if you have the <sys/protosw.h> header file.  */
#undef HAVE_SYS_PROTOSW_H

/* Define if you have the <sys/select.h> header file.  */
#undef HAVE_SYS_SELECT_H

/* Define if you have the <sys/sockio.h> header file.  */
#undef HAVE_SYS_SOCKIO_H

/* Define if you have the <sys/statvfs.h> header file.  */
#undef HAVE_SYS_STATVFS_H

/* Define if you have the <sys/swap.h> header file.  */
#undef HAVE_SYS_SWAP_H

/* Define if you have the <sys/sysctl.h> header file.  */
#undef HAVE_SYS_SYSCTL_H

/* Define if you have the <sys/tcpipstats.h> header file.  */
#undef HAVE_SYS_TCPIPSTATS_H

/* Define if you have the <sys/user.h> header file.  */
#undef HAVE_SYS_USER_H

/* Define if you have the <sys/utsname.h> header file.  */
#undef HAVE_SYS_UTSNAME_H

/* Define if you have the <sys/vfs.h> header file.  */
#undef HAVE_SYS_VFS_H

/* Define if you have the <sys/vm.h> header file.  */
#undef HAVE_SYS_VM_H

/* Define if you have the <sys/vmmac.h> header file.  */
#undef HAVE_SYS_VMMAC_H

/* Define if you have the <sys/vmmeter.h> header file.  */
#undef HAVE_SYS_VMMETER_H

/* Define if you have the <sys/vmparam.h> header file.  */
#undef HAVE_SYS_VMPARAM_H

/* Define if you have the <sys/vmsystm.h> header file.  */
#undef HAVE_SYS_VMSYSTM_H

/* Define if you have the <syslog.h> header file.  */
#undef HAVE_SYSLOG_H

/* Define if you have the <ufs/ffs/fs.h> header file.  */
#undef HAVE_UFS_FFS_FS_H

/* Define if you have the <ufs/fs.h> header file.  */
#undef HAVE_UFS_FS_H

/* Define if you have the <ufs/ufs/dinode.h> header file.  */
#undef HAVE_UFS_UFS_DINODE_H

/* Define if you have the <unistd.h> header file.  */
#undef HAVE_UNISTD_H

/* Define if you have the <utsname.h> header file.  */
#undef HAVE_UTSNAME_H

/* Define if you have the <vm/swap_pager.h> header file.  */
#undef HAVE_VM_SWAP_PAGER_H

/* Define if you have the <vm/vm.h> header file.  */
#undef HAVE_VM_VM_H

/* Define if you have the <xti.h> header file.  */
#undef HAVE_XTI_H

/* Define if you have the elf library (-lelf).  */
#undef HAVE_LIBELF

/* Define if you have the kstat library (-lkstat).  */
#undef HAVE_LIBKSTAT

/* Define if you have the kvm library (-lkvm).  */
#undef HAVE_LIBKVM

/* Define if you have the m library (-lm).  */
#undef HAVE_LIBM

/* Define if you have the mld library (-lmld).  */
#undef HAVE_LIBMLD

/* Define if you have the nsl library (-lnsl).  */
#undef HAVE_LIBNSL

/* Define if you have the socket library (-lsocket).  */
#undef HAVE_LIBSOCKET

/* ifnet structure tests */
#undef STRUCT_IFNET_HAS_IF_BAUDRATE
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

/* arphd.at_next */
#undef STRUCT_ARPHD_HAS_AT_NEXT

/* ifaddr.ifa_next */
#undef STRUCT_IFADDR_HAS_IFA_NEXT

/* ifnet.if_mtu */
#undef STRUCT_IFNET_HAS_IF_MTU

/* ifnet needs to have _KERNEL defined */
#undef IFNET_NEEDS_KERNEL

/* sysctl works to get boottime, etc... */
#undef CAN_USE_SYSCTL

/* type check for in_addr_t */
#define in_addr_t u_long

/* mib pointer to the top of the extensible tree.  This has been
 assigned to UCDavis by the iana group.  Optionally, point this to the
 location in the tree your company/organization has been allocated. */

/* location of the extensible mib tree */
#define EXTENSIBLEMIB 1,3,6,1,4,1,2021
/* location of the extensible mib tree */
#define EXTENSIBLEDOTMIB 1.3.6.1.4.1.2021
/* count the above numbers */
#define EXTENSIBLENUM 7

/* the ErrorFlag is V1 accessable because HP Openview does not support
   V2.  You can make this list of pairs as long as you want, just make
   sure to end it in -1.*/

#define SECURITYEXCEPTIONS {100,SNMPV1,-1} /* the ErrorFlag is V1 */

/* Mib-2 tree Info */
/* These are the system information variables. */

#define VERS_DESC   "unknown"             /* overridden at run time */
#define SYS_NAME    "unknown"             /* overridden at run time */

/* comment out the second define to turn off functionality for any of
   these: (See README for details) */

/*   proc PROCESSNAME [MAX] [MIN] */
#define PROCMIBNUM 1
#define USEPROCMIB

/*   exec/shell NAME COMMAND      */
#define SHELLMIBNUM 3
#define USESHELLMIB

/*   swap MIN                     */
#define MEMMIBNUM 4
#if defined(hpux9) || defined(bsdi2)
#define USEMEMMIB
#endif

/*   disk DISK MINSIZE            */
#define DISKMIBNUM 6
#if (HAVE_FSTAB_H || HAVE_SYS_STATVFS_H)
#define USEDISKMIB
#endif

/*   load 1 5 15                  */
#define LOADAVEMIBNUM 7
#define USELOADAVEMIB

/*   pass MIBOID command */
#define USEPASSMIB

/* which version are you using? This mibloc will tell you */
#define VERSIONMIBNUM 100
#define USEVERSIONMIB    

/* Reports errors the agent runs into */
/* (typically its "can't fork, no mem" problems) */
#define ERRORMIBNUM 101
#define USEERRORMIB    

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
#define FREEBSD2ID 8
#define IRIXID 9
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
#define OSTYPE FREEBSD2ID
#endif
#if defined(irix6) || defined(irix5)
#define OSTYPE IRIXID
#endif
/* unknown */
#ifndef OSTYPE
#define OSTYPE UNKNOWNID
#endif

/* how long to wait (seconds) for error querys before reseting the error trap.*/
#define ERRORTIMELENGTH 600 

/* Exec command to fix PROC problems */
/* %s will be replaced by the process name in error */

#define PROCFIXCMD "/usr/local/bin/perl /local/scripts/fixproc %s"

/* Exec command to fix EXEC problems */
/* %s will be replaced by the exec/script name in error */

#define EXECFIXCMD "/usr/local/bin/perl /local/scripts/fixproc %s"

/* Should exec output Cashing be used (speeds up things greatly), and
   if so, After how many seconds should the cache re-newed?  Note:
   Don't define CASHETIME to disable cashing completely */

#define EXCACHETIME 30
#define CACHEFILE "/tmp/.snmp-exec-cache"
#define MAXCACHESIZE (200*80)   /* roughly 200 lines max */

#define MAXDISKS 10                      /* can't scan more than this number */

/* misc defaults */

/* default of 100 meg minimum if the minimum size is not specified in
   the config file */
#define DEFDISKMINIMUMSPACE 100000

#define DEFMAXLOADAVE 12.0      /* default maximum load average before error */

#define MAXREADCOUNT 20   /* max times to loop reading output from
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

/* #define EXIT_ON_BAD_KLREAD  */
/* define to exit the agent on a bad kernel read */

#define LASTFIELD -1      /* internal define */

/* debugging macros */

#ifdef DODEBUG
#define DEBUGP(x) fprintf(stderr,x);
#define DEBUGP1(x,y) fprintf(stderr,x,y);
#else
#define DEBUGP(x)
#define DEBUGP1(x,y)
#endif

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

/* Watch out for compilers that don't handle void properly. */
#undef void

/* Not-to-be-compiled macros for use by configure only */
#define config_require(x)
#define config_load_mib(x,y,z)
  
/*#include <mib_module_config.h> */

#ifndef DONT_INC_STRUCTS
/*#include "agent/mibgroup/struct.h" */
#endif

#ifndef linux
#ifndef solaris2
#define bsdlike
#endif
#endif

#if !(defined( __P) || defined(netbsd1))
#ifdef __STDC__
#define __P(params) params
#else
#define __P(params) ()
#endif /* __STDC__ */
#endif /* __P */
