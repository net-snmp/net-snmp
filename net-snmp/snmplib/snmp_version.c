#include <net-snmp/library/version.h>

const char *NetSnmpVersionInfo="5.0.pre1";

const char *
netsnmp_get_version() 
{
    return NetSnmpVersionInfo;
}
