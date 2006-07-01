#include "sysv.h"

#undef bsdlike
#undef IP_FORWARDING_SYMBOL
#undef ARPTAB_SYMBOL
#define ARPTAB_SYMBOL "arptab_nb"
#undef ARPTAB_SIZE_SYMBOL
#define ARPTAB_SIZE_SYMBOL "arphd"
#undef ICMPSTAT_SYMBOL
#undef TCPSTAT_SYMBOL
#undef TCP_SYMBOL
#undef UDPSTAT_SYMBOL
#undef UDB_SYMBOL
#undef RTTABLES_SYMBOL
#undef RTHASHSIZE_SYMBOL
#undef RTHOST_SYMBOL
#undef RTNET_SYMBOL
#undef IPSTAT_SYMBOL
#undef TCP_TTL_SYMBOL
#undef PROC_SYMBOL
#undef TOTAL_MEMORY_SYMBOL
#undef MBSTAT_SYMBOL

#define UDP_ADDRESSES_IN_HOST_ORDER 1
#define UDP_PORTS_IN_HOST_ORDER 1

/* get some required prototypes (strtok_r) from include files */
#define __EXTENSIONS__

