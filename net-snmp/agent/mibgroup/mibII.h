/*
 * module to include the modules relavent to the mib-II mib(s) 
 */

config_require(mibII/system_mib)
config_require(mibII/sysORTable)
#if defined(NETSNMP_ENABLE_MFD_REWRITES)
config_require(ip-mib)
config_require(if-mib)
config_require(ip-forward-mib)
#else
config_require(mibII/at)
config_require(mibII/interfaces)
config_require(mibII/ip)
#endif
config_require(mibII/snmp_mib)
config_require(mibII/tcp)
config_require(mibII/icmp)
config_require(mibII/udp)
config_require(mibII/vacm_vars)
config_require(mibII/setSerialNo)
