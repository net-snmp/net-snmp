#ifndef _AGENTX_MASTER_REQUEST_H
#define _AGENTX_MASTER_REQUEST_H

int agentx_add_inclusive(struct agent_snmp_session *asp,
			 struct variable_list *vbp);
int agentx_add_exclusive(struct agent_snmp_session *asp,
			 struct variable_list *vbp);

#endif /* _AGENTX_MASTER_REQUEST_H */
