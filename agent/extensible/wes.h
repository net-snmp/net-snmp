/* wes.h:  a general config file */

/* Command to generate ps output, the final column must be the process
   name withOUT arguments */

#ifdef hpux
#define PSCMD "/bin/ps -e"
#else
#define PSCMD "/bin/ps -axc"
#endif

/* Should process output Cashing be used, and if so,
   After how many seconds should the cache re-newed?
   Note:  Don't define CASHETIME to disable cashing completely */

#define CACHETIME 30
#define CACHEFILE "/tmp/.snmp-exec-cache"
#define MAXCACHESIZE (200*80)   /* roughly 200 lines max */

/* mib pointer to my tree */

#define WESMIB 1,3,6,1,4,10 /* process watch section */

/* 2 global mib defs:
   ERRORFLAG:  A binary flag to signal an error condition.
               Also used as exit code.
   ERRORMSG:  A text message describing what caused the above condition,
              Also used as the single line return message from programs */

#define MIBINDEX 1
#define ERRORNAME 2
#define ERRORFLAG 100
#define ERRORMSG 101

/* process mib names def numbers */

#define PROCINDEX 1
#define PROCNAMES 2
#define PROCMIN   3
#define PROCMAX   4
#define PROCCOUNT 5
#define PROCERROR 6
#define PROCERRORMSG 7

#define SHELLINDEX 1
#define SHELLNAMES 2
#define SHELLCOMMAND 3
#define SHELLRESULT 6
#define SHELLOUTPUT 7

#define LOCKDINDEX 1
#define LOCKDERROR 6
#define LOCKDERRORMSG 7
#define LOCKDNFSFILE "/.nfslockdtest/nfs/subdir/test"
#define LOCKDREALFILE "/.nfslockdtest/real/subdir/test"

#define MEMSWAPINDEX 1
#define MEMERRNAME 2 /* always returns "swap", for other mib
                        compatibility purposes */
#define MEMTOTALSWAP 3
#define MEMUSEDSWAP 4
#define MEMTOTALREAL 5
#define MEMUSEDREAL 6
#define MEMTOTALSWAPTXT 7
#define MEMUSEDSWAPTXT 8
#define MEMTOTALREALTXT 9
#define MEMUSEDREALTXT 10
#define MEMTOTALFREE 11
#define MEMSWAPMINIMUM 12
#define MEMSWAPERROR 13
#define DEFAULTMINIMUMSWAP 16000  /* kilobytes */

/* disk watching mib.  Returns are in kbytes */

#define DISKINDEX 1
#define DISKPATH 2
#define DISKDEVICE 3
#define DISKMINIMUM 4
#define DISKTOTAL 5
#define DISKAVAIL 6
#define DISKUSED 7
#define DISKPERCENT 8

#define HPCONF 1
#define HPRECONFIG 2
#define HPFLAG 3
#define HPLOGMASK 4
#define HPSTATUS 6
#define HPTRAP 101

unsigned char *var_wes_proc();
unsigned char *var_wes_mem();

#define CONFIGFILE "/etc/ece-snmpd.conf"  /* default config file */
#define CONFIGFILETWO "/etc/ece-snmpd.local.conf" /* optional second file */

#define MAXDISKS 10                      /* can't scan more than this number */
#define DEFDISKMINIMUMSPACE 100000       /* 100 meg minimum disk space */

#include "struct.h"
