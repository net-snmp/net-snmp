#ifndef _AGENTX_MASTER_H
#define _AGENTX_MASTER_H

config_require(agentx/master_admin)
config_require(agentx/master_request)
config_require(mibII/sysORTable)

int get_agentx_transID( int, snmp_ipaddr *);
void init_agentx_master(void);

#endif /* _AGENTX_MASTER_H */

