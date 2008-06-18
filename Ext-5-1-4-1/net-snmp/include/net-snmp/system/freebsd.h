#include "bsd.h"

#define CHECK_RT_FLAGS 1

/*
 * udp_inpcb list symbol 
 */
#undef INP_NEXT_SYMBOL
#define INP_NEXT_SYMBOL inp_next

#undef TCP_TTL_SYMBOL
#define TCP_TTL_SYMBOL "ip_defttl"

#ifdef _PATH_UTMP
#define UTMP_FILE _PATH_UTMP
#else
#define UTMP_FILE "/var/run/utmp"
#endif
