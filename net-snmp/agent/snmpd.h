/*
 * snmpd.h
 */

#define MASTER_AGENT 0
#define SUB_AGENT    1
extern int agent_role;

extern int snmp_dump_packet;
extern int verbose;
extern int (*sd_handlers[])(int);
extern int smux_listen_sd;

extern int snmp_read_packet (int);
extern u_char *getStatPtr (oid *, size_t *, u_char *, size_t *,
	u_short *, int, WriteMethod **write_method, struct snmp_pdu *, int *);

/* config file parsing routines */
void agentBoots_conf (char *, char *);
