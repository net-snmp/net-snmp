#ifndef _AGENTX_SUBAGENT_H
#define _AGENTX_SUBAGENT_H

config_require(agentx/protocol)
config_require(agentx/client)

void init_subagent(void);
int handle_agentx_packet(int, struct snmp_session *, int, struct snmp_pdu *, void *);

extern struct snmp_session *agentx_session;

#endif /* _AGENTX_SUBAGENT_H */

