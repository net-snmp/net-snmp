#ifndef AGENT_TRAP_H
#define AGENT_TRAP_H

void send_easy_trap (int, int);
void send_trap_pdu(struct snmp_pdu *);
void send_v2trap ( struct variable_list *);
void send_trap_vars (int, int, struct variable_list *);

void snmpd_parse_config_authtrap (const char *, char *);
void snmpd_parse_config_trapsink (const char *, char *);
void snmpd_parse_config_trap2sink (const char *, char *);
void snmpd_parse_config_informsink (const char *, char *);
void snmpd_free_trapsinks (void);
void snmpd_parse_config_trapcommunity (const char *, char *);
void snmpd_free_trapcommunity (void);

int create_trap_session (char *, u_short, char *, int, int);
int add_trap_session( struct snmp_session *, int, int);

#endif /* AGENT_TRAP_H */
