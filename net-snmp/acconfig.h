/* config.h:  a general config file */

/* mib pointer to my tree */

#define EXTENSIBLEMIB 1,3,6,1,4,10 /* process watch section */

/* Command to generate ps output, the final column must be the process
   name withOUT arguments */

#ifdef hpux
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

/* Should process output Cashing be used, and if so,
   After how many seconds should the cache re-newed?
   Note:  Don't define CASHETIME to disable cashing completely */

#define EXCACHETIME 30
#define CACHEFILE "/tmp/.snmp-exec-cache"
#define MAXCACHESIZE (200*80)   /* roughly 200 lines max */

#define CONFIGFILE "/etc/ece-snmpd.conf"  /* default config file */
#define CONFIGFILETWO "/etc/ece-snmpd.local.conf" /* optional second file */

#define MAXDISKS 10                      /* can't scan more than this number */
#define DEFDISKMINIMUMSPACE 100000       /* 100 meg minimum disk space */

#define DEFMAXLOADAVE 12.0              /* maximum load average before error */

#define LASTFIELD -1

#define MAXREADCOUNT 20   /* max times to loop reading output from
                             execs because of sleep(1)s this will also
                             be time in seconds */

#include "agent/extensible/struct.h"
