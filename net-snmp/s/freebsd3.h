#include "freebsd.h"

#define freebsd2                  /* freebsd3 is a superset of freebsd2 */

#undef IFADDR_SYMBOL
#define IFADDR_SYMBOL "in_ifaddrhead"
