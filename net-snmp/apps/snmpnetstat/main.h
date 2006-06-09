
#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN	64
#endif

extern  struct snmp_session *ss;
int netsnmp_query_get(    struct variable_list *list,
                          struct snmp_session  *session);
int netsnmp_query_getnext(struct variable_list *list,
                          struct snmp_session  *session);
int netsnmp_query_walk(   struct variable_list *list,
                          struct snmp_session  *session);
#if !HAVE_STRLCPY
size_t strlcpy(char *dest, const char *src, size_t len);
#endif

#ifndef AF_INET6
#define AF_INET6	10
#endif

#ifndef NI_MAXHOST
#define NI_MAXHOST      1025
#endif
