#include <net-snmp/version.h>

const char     *NetSnmpVersionInfo = "5.1.rc1";

const char     *
netsnmp_get_version()
{
    return NetSnmpVersionInfo;
}
