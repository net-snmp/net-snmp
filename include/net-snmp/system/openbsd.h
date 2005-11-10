#include "netbsd.h"

#define netbsd1 1               /* we're really close to this */
#define UVM

#undef MBPOOL_SYMBOL
#undef MCLPOOL_SYMBOL
#undef TOTAL_MEMORY_SYMBOL

/* at least OpenBSD/SPARC 3.7 doesn't define this */
#ifndef UINT32_MAX
#define UINT32_MAX	(4294967295U)
#endif
