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

#define EXTENSIBLEMIB 1,3,6,1,4,10 /* location of the extensible mib tree */
#define EXTENSIBLEDOTMIB 1.3.6.1.4.10 /* location of the extensible mib tree */
#define EXTENSIBLENUM 6            /* count the above numbers */

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

/* location of swap device (ok if not found) */
#undef DMEM_LOC

/* define rtentry to ortentry on SYSV machines (alphas) */
#define RTENTRY rtentry;

/* Command to generate ps output, the final column must be the process
   name withOUT arguments */

#define PSCMD "/bin/ps"

@BOTTOM@


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

#define PROCMIBNUM 1              /*   proc PROCESSNAME [MAX] [MIN] */
#define USEPROCMIB

#define SHELLMIBNUM 3             /*   exec/shell NAME COMMAND      */
#define USESHELLMIB

#define MEMMIBNUM 4               /*   swap MIN                     */
#ifdef hpux
#define USEMEMMIB
#endif

#define DISKMIBNUM 6              /*   disk DISK MINSIZE            */
#define USEDISKMIB

#define LOADAVEMIBNUM 7           /*   load 1 5 15                  */
#define USELOADAVEMIB

#define VERSIONMIBNUM 100  /* which version are you using? */
#define USEVERSIONMIB      /* This mibloc will tell you */

#define ERRORMIBNUM 101     /* Reports errors the agent runs into */
#define USEERRORMIB         /* (typically its "can't fork, no mem" problems) */

#define AGENTID 250  /* The sub id of EXENSIBLEMIB returned to queries of
                        .iso.org.dod.internet.mgmt.mib-2.system.sysObjectID.0 */

/* This ID is returned after the AGENTID above.  IE, the resulting
   value returned by a query to sysObjectID is
   EXTENSIBLEMIB.AGENTID.???, where ??? is defined below by OSTYPE */

#define HPUXID    1
#define SUNOS4ID  2 
#define SOLARISID 3
#define OSF3ID    4
#define ULTRIXID  5
#define UNKNOWNID 255

#ifdef hpux9
#define OSTYPE HPUXID
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
/* %s will be replaced by the process name in error */

#define EXECFIXCMD "/usr/local/bin/perl /local/scripts/fixproc %s"

/* Should exec output Cashing be used (speeds up things greatly), and
   if so, After how many seconds should the cache re-newed?  Note:
   Don't define CASHETIME to disable cashing completely */

#define EXCACHETIME 30
#define CACHEFILE "/tmp/.snmp-exec-cache"
#define MAXCACHESIZE (200*80)   /* roughly 200 lines max */

#define MAXDISKS 10                      /* can't scan more than this number */

/* misc defaults */

#define DEFDISKMINIMUMSPACE 100000       /* default of 100 meg minimum
                                            if the minimum size is not
                                            specified in the config file */

#define DEFMAXLOADAVE 12.0      /* default maximum load average before error */

#define MAXREADCOUNT 20   /* max times to loop reading output from
                             execs.  Because of sleep(1)s, this will also
                             be time to wait (in seconds) for exec to finish */

#define SNMPBLOCK 0       /* Set to 1 if you want snmpgets to block and never
                             timeout.  Original CMU code had this
                             hardcoded into the code as = 1 */

/* #define EXIT_ON_BAD_KLREAD  */
/* define to exit the agent on a bad kernel read */

#define LASTFIELD -1      /* internal define */

#ifndef DONT_INC_STRUCTS
#include "agent/extensible/struct.h"
#endif

