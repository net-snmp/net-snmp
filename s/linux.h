#include "sysv.h"

#define DONT_USE_NLIST

#undef bsdlike

/* red hat >= 5.0 doesn't have this */
#ifndef MNTTYPE_PROC
#define MNTTYPE_PROC "proc"
#endif

/* for 2.0 kernels */
#define LINUX_INTERFACE_SCAN_LINE "%[^:]: %d %d %*d %*d %*d %d %d %*d %*d %d"

/* for 2.1 kernels */
/* #define LINUX_INTERFACE_SCAN_LINE "%[^:]: %*d %d %d %*d %*d %*d %*d %*d %*d %d %d %*d %*d %*d %*d %d" */

/* for 2.2 kernels? */
/* #define LINUX_INTERFACE_SCAN_LINE "%[^:]: %*d %d %d %*d %*d %*d %*d %*d %*d %d %d %*d %*d %d"
