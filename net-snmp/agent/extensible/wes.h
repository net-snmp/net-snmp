/* mib pointer to my tree */

#define WESMIB 1,3,6,1,4,10 /* process watch section */

/* process mib names def numbers */

#define WESINDEX 1
#define WESNAMES 2
#define WESMIN   3
#define WESMAX   4
#define WESCOUNT 5
#define WESERROR 6
#define WESERRORMSG 7

unsigned char *var_wes_proc();

#define DEFPROCFILE "/etc/snmpProcWatch.conf"

#include "struct.h"
