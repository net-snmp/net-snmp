#include "bsd.h"

#define CHECK_RT_FLAGS

/* udp_inpcb list symbol */
#undef INP_NEXT_SYMBOL
#define INP_NEXT_SYMBOL inp_list.le_next
#undef INP_PREV_SYMBOL
#define INP_PREV_SYMBOL inp_list.le_prev
#undef TCP_TTL_SYMBOL
#define TCP_TTL_SYMBOL "ip_defttl"

#define UTMP_FILE _PATH_UTMP
