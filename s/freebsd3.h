#include "freebsd.h"

#define freebsd2      /* freebsd3 is a superset of freebsd2 */

#if HAVE_GETFSSTAT
#if defined(MFSNAMELEN)
#define MOUNT_NFS              /* needed for HR mib */
#endif
#endif

#undef IFADDR_SYMBOL
#define IFADDR_SYMBOL "in_ifaddrhead"
