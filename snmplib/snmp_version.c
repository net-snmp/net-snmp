#include <net-snmp/version.h>

const char     *NetSnmpVersionInfo = "5.1.pre2";

const char     *
netsnmp_get_version()
{
    return NetSnmpVersionInfo;
}
