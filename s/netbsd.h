#include "bsd.h"

#undef TCP_SYMBOL
#define TCP_SYMBOL "tcbtable"
#undef TCP_TTL_SYMBOL
#define TCP_TTL_SYMBOL "ip_defttl"
#undef UDB_SYMBOL
#define UDB_SYMBOL "udbtable"
#undef NPROC_SYMBOL

/* inp_next symbol */
#undef INP_NEXT_SYMBOL
#define INP_NEXT_SYMBOL inp_queue.cqe_next
#undef INP_PREV_SYMBOL
#define INP_PREV_SYMBOL inp_queue.cqe_prev

#define HAVE_GETFSSTAT 1
#define HAVE_KVM_GETPROCS 1
#define HAVE_SYS_DISKLABEL_H 1

#define UTMP_FILE _PATH_UTMP
