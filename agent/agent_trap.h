#ifndef AGENT_TRAP_H
#define AGENT_TRAP_H

void send_easy_trap (int trap, int specific);
void send_trap_pdu(struct snmp_pdu *pdu);

void snmpd_parse_config_authtrap (char *, char *);
void snmpd_parse_config_trapsink (char *, char *);
void snmpd_parse_config_trap2sink (char *, char *);
void snmpd_free_trapsinks (void);
void snmpd_parse_config_trapcommunity (char *, char *);
void snmpd_free_trapcommunity (void);

#endif /* AGENT_TRAP_H */
