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
   int     priority;
};

#define MIB_REGISTERED_OK		 0
#define MIB_DUPLICATE_REGISTRATION	-1
#define MIB_REGISTRATION_FAILED		-2

#define MIB_UNREGISTERED_OK		 0
#define MIB_NO_SUCH_REGISTRATION	-1
#define MIB_UNREGISTRATION_FAILED	-2

void setup_tree (void);
int register_mib_priority (const char *, struct variable *, size_t , size_t , oid *, size_t, int, struct snmp_session *);
int unregister_mib_priority (oid *, size_t, int);
void unregister_mibs_by_session (struct snmp_session *);

#endif /* AGENT_REGISTRY_H */
