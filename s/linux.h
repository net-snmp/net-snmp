#include "sysv.h"

#define DONT_USE_NLIST

#undef bsdlike

/* red hat >= 5.0 doesn't have this */
#ifndef MNTTYPE_PROC
#define MNTTYPE_PROC "proc"
#endif

#ifdef PROC_NET_DEV_HAS_COMPRESSED
/* linux 2.2 and above */
#define LINUX_INTERFACE_SCAN_LINE "%[^:]: %*d %d %d %*d %*d %*d %*d %*d %*d %d %d %*d %*d %d"
#else
#define LINUX_INTERFACE_SCAN_LINE "%[^:]: %d %d %*d %*d %*d %d %d %*d %*d %d"
#endif
