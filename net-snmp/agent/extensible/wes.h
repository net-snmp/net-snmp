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
#define SHELLRESULT 4
#define SHELLOUTPUT 5

#define MEMTOTALSWAP 1
#define MEMUSEDSWAP 2

unsigned char *var_wes_proc();
unsigned char *var_wes_mem();

#define DEFPROCFILE "/etc/snmp-ece.conf"

#include "struct.h"
