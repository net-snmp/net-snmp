/* 2 global mib defs:
   ERRORFLAG:  A binary flag to signal an error condition.
               Also used as exit code.
   ERRORMSG:  A text message describing what caused the above condition,
              Also used as the single line return message from programs */

#define MIBINDEX 1
#define ERRORNAME 2
#define ERRORFLAG 100
#define ERRORMSG 101
#define ERRORFIX 102

/* process mib names def numbers */

#define PROCINDEX 1
#define PROCNAMES 2
#define PROCMIN 3
#define PROCMAX 4
#define PROCCOUNT 5
#define PROCERROR 6
#define PROCERRORMSG 7

#define SHELLINDEX 1
#define SHELLNAMES 2
#define SHELLCOMMAND 3
#define SHELLRESULT 6
#define SHELLOUTPUT 7

#define LOCKDMIBNUM 5
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

/* load average mib */
#define LOADAVE 3
#define LOADMAXVAL 4

/* Version info mib */
#define VERTAG 2
#define VERDATE 3
#define VERCDATE 4
#define VERIDENT 5
#define VERCLEARCACHE 10
#define VERUPDATECONFIG 11
#define VERRESTARTAGENT 12

#ifdef hpux
#define HPCONF 1
#define HPRECONFIG 2
#define HPFLAG 3
#define HPLOGMASK 4
#define HPSTATUS 6
#define HPTRAP 101
#endif
