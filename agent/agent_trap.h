#ifndef AGENT_TRAP_H
#define AGENT_TRAP_H

void send_easy_trap (int, int);
void send_trap_pdu(struct snmp_pdu *);
void send_v2trap ( struct variable_list *);
void send_trap_vars (int, int, struct variable_list *);

void snmpd_parse_config_authtrap (char *, char *);
void snmpd_parse_config_trapsink (char *, char *);
void snmpd_parse_config_trap2sink (char *, char *);
void snmpd_parse_config_informsink (char *, char *);
void snmpd_free_trapsinks (void);
void snmpd_parse_config_trapcommunity (char *, char *);
void snmpd_free_trapcommunity (void);

int create_trap_session (char *, char *, int, int);
int add_trap_session( struct snmp_session *, int, int);

#endif /* AGENT_TRAP_H */
