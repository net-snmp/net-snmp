#ifndef AGENT_TRAP_H
#define AGENT_TRAP_H

struct agent_add_trap_args {
   struct snmp_session *ss;
   int confirm;
};

void send_easy_trap (int, int);
void send_trap_pdu(struct snmp_pdu *);
void send_v2trap ( struct variable_list *);
void send_trap_vars (int, int, struct variable_list *);
void send_enterprise_trap_vars (int trap, int specific,
                       oid *enterprise, int enterprise_length,
                       struct variable_list *vars);
void snmpd_parse_config_authtrap (const char *, char *);
void snmpd_parse_config_trapsink (const char *, char *);
void snmpd_parse_config_trap2sink (const char *, char *);
void snmpd_parse_config_informsink (const char *, char *);
void snmpd_parse_config_trapsess(const char *, char *);
void snmpd_free_trapsinks (void);
void snmpd_parse_config_trapcommunity (const char *, char *);
void snmpd_free_trapcommunity (void);
void send_trap_to_sess(struct snmp_session *sess,
                       struct snmp_pdu *template_pdu);

int create_trap_session (char *, u_short, char *, int, int);
int add_trap_session( struct snmp_session *, int, int, int);
int remove_trap_session( struct snmp_session * );

#endif /* AGENT_TRAP_H */
