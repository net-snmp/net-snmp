
int snmp_parse_args (int, char **, struct snmp_session *);
void snmp_parse_args_descriptions (FILE *);
void snmp_parse_args_usage (FILE *);
void usage (void);
oid *snmp_parse_oid (char *,oid *,int *);

