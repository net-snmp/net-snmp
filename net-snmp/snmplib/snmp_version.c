#include <net-snmp/version.h>

const char     *NetSnmpVersionInfo = "5.0.11.2";

const char     *
netsnmp_get_version()
{
    return NetSnmpVersionInfo;
}
