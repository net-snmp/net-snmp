#include "sysv.h"

#define DONT_USE_NLIST 1

#undef bsdlike

/* red hat >= 5.0 doesn't have this */
#ifndef MNTTYPE_PROC
#define MNTTYPE_PROC "proc"
#endif
