#ifdef UCD_COMPATIBLE

#include <net-snmp/snmpv3.h>

#else

#error "Please update your headers or configure using --enable-ucd-compatibility"

#endif
