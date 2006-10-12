#include <net-snmp/system/generic.h>
#include <sys/select.h>
#undef TOTAL_MEMORY_SYMBOL
#undef NPROC_SYMBOL
#undef RTHASHSIZE_SYMBOL
#undef RTHOST_SYMBOL
#undef RTNET_SYMBOL
#define RTTABLES_SYMBOL rt_tables

#ifndef __GNUC__
#  undef NETSNMP_ENABLE_INLINE
#  define NETSNMP_ENABLE_INLINE 0
#endif

/* define the extra mib modules that are supported */
#define NETSNMP_INCLUDE_HOST_RESOURCES
