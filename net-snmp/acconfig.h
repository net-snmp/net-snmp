/* config.h:  a general config file */

/* don't change these values! */
#define SNMPV1      0xAAAA       /* readable by anyone */
#define SNMPV2ANY   0xA000       /* V2 Any type (includes NoAuth) */
#define SNMPV2AUTH  0x8000       /* V2 Authenticated requests only */

@TOP@

/* SNMPLIBDIR contains important files */

#undef SNMPLIBPATH

/* mib pointer to the top of the extensible tree point this to the
 location in the tree your company/organization has been allocated.
 If you don't have an official one (like me), just make one up that
 doesn't overlap with other mibs you are using on the system */

/* location of the extensible mib tree */
#define EXTENSIBLEMIB 1,3,6,1,4,10
/* location of the extensible mib tree */
#define EXTENSIBLEDOTMIB 1.3.6.1.4.10
/* count the above numbers */
#define EXTENSIBLENUM 6

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

/* configuration files.  I rdist the first one and leave machine
   specific stuff in the second one */

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

/* Command to generate ps output, the final column must be the process
   name withOUT arguments */

#define PSCMD "/bin/ps"

/* debugging stuff */
#undef DODEBUG

@BOTTOM@

/* If defined, the snmplib library will store contents of the
   DESCRIPTION field in the mib.txt file.  Since none of the
   distributed applications use this information, it is turned off by
   default.  Uncomment to turn storage back on. */
/* #define USE_DESCRIPTION */

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
#define OSF3ID 4
#define ULTRIXID 5
#define HPUX10ID 6
#define NETBSD1ID 7
#define FREEBSD2ID 8
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
#ifdef osf3
#define OSTYPE OSF3ID
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

#define SNMPBLOCK 0       /* Set to 1 if you want snmpgets to block and never
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


#ifndef DONT_INC_STRUCTS
#include "agent/extensible/struct.h"
#endif

