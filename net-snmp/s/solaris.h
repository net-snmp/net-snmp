#include "generic.h"

#undef bsdlike
#undef IP_FORWARDING_SYMBOL
#define IP_FORWARDING_SYMBOL "ip_forwarding"
#undef ARPTAB_SYMBOL
#define ARPTAB_SYMBOL "arptab_nb"
#undef ARPTAB_SIZE_SYMBOL
#define ARPTAB_SIZE_SYMBOL "arphd"
