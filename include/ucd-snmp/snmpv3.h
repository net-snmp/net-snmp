#ifdef UCD_COMPATIBLE

#include <net-snmp/snmplib/snmpv3.h>

#else

#error "Please update your headers or configure using --enable-ucd-compatibility"

#endif
