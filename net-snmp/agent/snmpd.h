
extern int snmp_dump_packet;
extern int verbose;
extern int (*sd_handlers[])(int);

extern int snmp_agent_parse (u_char *, int, u_char *, int *, u_long);
extern int snmp_read_packet (int);
extern void init_snmp (void);
extern void init_snmp2p (u_short);
extern int open_port (u_short);
extern void open_ports_snmp2p (void);
extern char *reverse_bytes (char *, int);
extern void send_trap_pdu (struct snmp_pdu *);
extern void send_easy_trap (int, int);
extern u_char *getStatPtr (oid *, int *, u_char *, int *, u_short *, int, WriteMethod **write_method, struct packet_info *, int * );

/* config file parsing routines */
void snmpd_parse_config_authtrap (char *, char *);
void snmpd_parse_config_trapsink (char *, char *);
void snmpd_parse_config_trap2sink (char *, char *);
void snmpd_free_trapsinks (void);
void snmpd_parse_config_trapcommunity (char *, char *);
void snmpd_free_trapcommunity (void);
void agentBoots_conf (char *, char *);
