#ifndef UCD_SNMP_PROXY_H
#define UCD_SNMP_PROXY_H

struct simple_proxy {
   struct variable2 *variables;
   oid name[MAX_OID_LEN];
   size_t name_len;
   oid base[MAX_OID_LEN];
   size_t base_len;
   struct snmp_session *sess;
   struct simple_proxy *next;
};

FindVarMethod var_simple_proxy;
WriteMethod proxy_set;
void proxy_parse_config (const char *, char *);
void init_proxy(void);

#endif /* UCD_SNMP_PROXY_H */
