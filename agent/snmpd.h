
extern int snmp_dump_packet;
extern int verbose;

extern int snmp_agent_parse __P((u_char *, int, u_char *, int *, u_long));
extern void init_snmp __P((void));
extern void send_easy_trap __P((int));
extern u_char *getStatPtr __P((oid *, int *, u_char *, int *, u_short *, int, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)), struct packet_info *, int * ));

/* config file parsing routines */
void snmpd_parse_config_authtrap __P((char *, char *));
void snmpd_parse_config_trapsink __P((char *, char *));
void snmpd_parse_config_trapcommunity __P((char *, char *));

