#ifndef SNMPV3MIBS_H
#define SNMPV3MIBS_H

/*
 * snmpv3mibs.h: mib module to include the modules relavent to the
 * snmpv3 mib(s) 
 */

config_require(snmpv3/snmpEngine)
config_require(snmpv3/snmpMPDStats)
config_old_require(snmpv3/usmStats, snmpv3/usmStats_5_5)
config_require(snmpv3/usmConf)
config_require(snmpv3/usmUser)
#endif                          /* NSMPV3MIBS_H */
