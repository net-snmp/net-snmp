/* wes.h:  a general config file */

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

#ifdef hpux
#define EXCACHETIME 30
#define CACHEFILE "/tmp/.snmp-exec-cache"
#define MAXCACHESIZE (200*80)   /* roughly 200 lines max */
#endif

unsigned char *var_wes_proc();
unsigned char *var_wes_mem();

#define CONFIGFILE "/etc/ece-snmpd.conf"  /* default config file */
#define CONFIGFILETWO "/etc/ece-snmpd.local.conf" /* optional second file */

#define MAXDISKS 10                      /* can't scan more than this number */
#define DEFDISKMINIMUMSPACE 100000       /* 100 meg minimum disk space */

#define LASTFIELD -1

#include "struct.h"
