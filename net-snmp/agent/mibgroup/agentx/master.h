#ifndef _AGENTX_MASTER_H
#define _AGENTX_MASTER_H

config_require(agentx/protocol)
config_require(agentx/client)
config_require(agentx/master_admin)
config_require(agentx/master_request)
config_require(mibII/sysORTable)

void init_master(void);
void real_init_master(void);

#endif /* _AGENTX_MASTER_H */

