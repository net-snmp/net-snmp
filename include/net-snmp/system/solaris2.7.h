#include "solaris.h"
#define _SLASH_PROC_METHOD_ 1
#define DONT_USE_NLIST 1
/*  NO_KMEM_USAGE #defined by jbpn since net-snmp-config.h.in no
    longer pays attention to the DONT_USE_NLIST token above.  */
#define NO_KMEM_USAGE 1
