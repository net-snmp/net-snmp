/*
 irix.h

 Date Created: Mon Feb 16 22:19:39 1998
 Author:       Simon Leinen  <simon@switch.ch>
 */

#include "generic.h"

#undef TCP_TTL_SYMBOL
#define TCP_TTL_SYMBOL "tcp_ttl"

#undef IPSTAT_SYMBOL
#undef ICMPSTAT_SYMBOL
#undef TCPSTAT_SYMBOL
#undef UDPSTAT_SYMBOL

#define _KMEMUSER 1

/* don't define _KERNEL before including sys/unistd.h */
#define IFNET_NEEDS_KERNEL_LATE  1
