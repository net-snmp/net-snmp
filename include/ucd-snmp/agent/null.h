#ifdef UCD_COMPATIBLE

#include <net-snmp/agent/null.h>

#else

#error "Please update your headers or configure using --enable-ucd-compatibility"

#endif
