#ifdef UCD_COMPATIBLE

#include <net-snmp/snmplib/snmp_alarm.h>

#else

#error "Please update your headers or configure using --enable-ucd-compatibility"

#endif
