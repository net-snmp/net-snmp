#ifdef UCD_COMPATIBLE

#include <net-snmp/snmplib/default_store.h>

#else

#error "Please update your headers or configure using --enable-ucd-compatibility"

#endif
