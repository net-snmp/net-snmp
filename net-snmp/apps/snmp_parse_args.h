
int snmp_parse_args __P((int, char **, struct snmp_session *, char *));
void snmp_parse_args_descriptions __P((FILE *));
void snmp_parse_args_usage __P((FILE *));
void usage __P((void));
oid *snmp_parse_oid __P((char *,oid *,int *) );

