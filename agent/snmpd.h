
extern int snmp_dump_packet;
extern int verbose;

extern int snmp_agent_parse __UCD_P((u_char *, int, u_char *, int *, u_long));
extern void init_snmp __UCD_P((void));
extern void send_easy_trap __UCD_P((int));
extern u_char *getStatPtr __UCD_P((oid *, int *, u_char *, int *, u_short *, int, int (**write) __UCD_P((int, u_char *, u_char, int, u_char *, oid *, int)), struct packet_info *, int * ));

/* config file parsing routines */
void snmpd_parse_config_authtrap __UCD_P((char *, char *));
void snmpd_parse_config_trapsink __UCD_P((char *, char *));
void snmpd_parse_config_trapcommunity __UCD_P((char *, char *));

