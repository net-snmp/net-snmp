#ifndef SNMP_TARGET_H
#define SNMP_TARGET_H

/* utility functions */

struct snmp_session *get_target_sessions(char *taglist);

config_require(target/snmpTargetAddrEntry target/snmpTargetParamsEntry)

    
#endif /* SNMP_TARGET_H */
