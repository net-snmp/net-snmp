#include "freebsd.h"

#define freebsd2 1                  /* freebsd3 is a superset of freebsd2 */

#undef IFADDR_SYMBOL
#define IFADDR_SYMBOL "in_ifaddrhead"

#undef PROC_SYMBOL
#define PROC_SYMBOL "allproc"

#undef NPROC_SYMBOL
#define NPROC_SYMBOL "nprocs"

