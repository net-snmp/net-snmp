#include "freebsd.h"

/* this is not good enough before freebsd3! */
#undef HAVE_NET_IF_MIB_H
#define UTMP_FILE "/var/run/utmp"
#define HAVE_GETFSSTAT 1
#define HAVE_KVM_GETPROCS 1
#define HAVE_SYS_DISKLABEL_H 1
#undef PROC_SYMBOL
#undef NPROC_SYMBOL
#undef LOADAVE_SYMBOL
#undef TOTAL_MEMORY_SYMBOL
