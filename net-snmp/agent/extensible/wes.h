/* mib pointer to my tree */

#define WESMIB 1,3,6,1,4,10 /* process watch section */

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

#define MEMTOTALSWAP 1
#define MEMUSEDSWAP 2
#define MEMTOTALREAL 3
#define MEMUSEDREAL 4
#define MEMTOTALSWAPTXT 5
#define MEMUSEDSWAPTXT 6
#define MEMTOTALREALTXT 7
#define MEMUSEDREALTXT 8
#define MEMTOTALFREE 9

#define HPCONF 1
#define HPRECONFIG 2
#define HPFLAG 3
#define HPLOGMASK 4
#define HPSTATUS 6
#define HPTRAP 101

unsigned char *var_wes_proc();
unsigned char *var_wes_mem();

#define DEFPROCFILE "/etc/ece-snmpd.conf"

#include "struct.h"
