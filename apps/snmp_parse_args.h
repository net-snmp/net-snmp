
int snmp_parse_args (int, char * const *, struct snmp_session *, const char *, void (*)(int, char *const *, int));
void snmp_parse_args_descriptions (FILE *);
void snmp_parse_args_usage (FILE *);
void usage (void);
oid *snmp_parse_oid (char *,oid *,size_t *);

