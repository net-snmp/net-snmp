#ifndef _AGENTX_MASTER_ADMIN_H
#define _AGENTX_MASTER_ADMIN_H

int handle_master_agentx_packet(int, struct snmp_session *,
			        int, struct snmp_pdu *, void *);
#endif /* _AGENTX_MASTER_ADMIN_H */
