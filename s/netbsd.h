#include "bsd.h"

#undef TCP_SYMBOL
#define TCP_SYMBOL "tcp_table"

/* inp_next symbol */
#undef INP_NEXT_SYMBOL
#define INP_NEXT_SYMBOL inp_queue.cqe_next
#undef INP_PREV_SYMBOL
#define INP_PREV_SYMBOL inp_queue.cqe_prev
