/* config.h:  a general config file */

/* Mib-2 tree Info */

#if defined(hpux)
#define VERS_DESC   "HP-UX 9.0.5"
#elif defined(ultrix)
#define VERS_DESC   "Ultrix 4.2"
#else
#define VERS_DESC   "SunOS 4.1.4"
#endif

#define SYS_CONTACT "support@ece.ucdavis.edu"
#define SYS_NAME    "unknown"
#define SYS_LOC     "UCDavis Electrical Engineering Departement"

/* Logfile.  If defined it closes stdout/err and opens this in their place */

#define LOGFILE "/usr/adm/ece-snmpd.log"

/* mib pointer to my tree */

#define EXTENSIBLEMIB 1,3,6,1,4,10 /* location of the extensible mib tree */
#define EXTENSIBLENUM 6            /* count the above */

/* Command to generate ps output, the final column must be the process
   name withOUT arguments */

/* comment out to turn off functionality for any of these: */

#define PROCMIBNUM 1              /*   proc PROCESSNAME [MAX] [MIN] */
#define SHELLMIBNUM 3             /*   exec/shell NAME COMMAND      */
#define MEMMIBNUM 4               /*   swap MIN                     */
#define DISKMIBNUM 6              /*   disk DISK MINSIZE            */
#define LOADAVEMIBNUM 7           /*   load 1 5 15                  */

#define VERSIONMIBNUM 100  /* which version are you using?
                              This mibloc will tell you */
#define ERRORMIBNUM 101
#define ERRORTIMELENGTH 600 /* how long to wait for error querys */

#if defined(hpux) || defined(SYSV)
#define PSCMD "/bin/ps -e"
#else
#define PSCMD "/bin/ps -axc"
#endif

/* Exec command to fix PROC problems */
/* %s will be replaced by the process name in error */

#define PROCFIXCMD "/usr/local/bin/perl /local/scripts/fixproc %s"

/* Exec command to fix EXEC problems */
/* %s will be replaced by the process name in error */

#define EXECFIXCMD "/usr/local/bin/perl /local/scripts/fixproc %s"

/* Should exec output Cashing be used, and if so,
   After how many seconds should the cache re-newed?
   Note:  Don't define CASHETIME to disable cashing completely */

#define EXCACHETIME 30
#define CACHEFILE "/tmp/.snmp-exec-cache"
#define MAXCACHESIZE (200*80)   /* roughly 200 lines max */

#define CONFIGFILE "/etc/ece-snmpd.conf"  /* default config file */
#define CONFIGFILETWO "/etc/ece-snmpd.local.conf" /* optional second file */

#define MAXDISKS 10                      /* can't scan more than this number */
#define DEFDISKMINIMUMSPACE 100000       /* 100 meg minimum disk space */

#define DEFMAXLOADAVE 12.0      /* default maximum load average before error */

#define LASTFIELD -1

#define MAXREADCOUNT 20   /* max times to loop reading output from
                             execs because of sleep(1)s this will also
                             be time in seconds */

#include "agent/extensible/struct.h"
