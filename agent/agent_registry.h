#ifndef AGENT_REGISTRY_H
#define AGENT_REGISTRY_H

/* the structure of parameters passed to registered ACM modules */
struct view_parameters {
   struct snmp_pdu *pdu;
   oid             *name;
   size_t           namelen;
   int              errorcode; /* do not change unless you're
                                  specifying an error,
                                  as it starts in a success state. */
};

struct register_parameters {
   oid    *name;
   size_t  namelen;
};

void setup_tree (void);
int register_mib_priority (const char *, struct variable *, size_t , size_t , oid *, size_t, u_char);

#endif /* AGENT_REGISTRY_H */
