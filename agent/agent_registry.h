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
   int     range_subid;
   oid     range_ubound;
};

#define MIB_REGISTERED_OK		 0
#define MIB_DUPLICATE_REGISTRATION	-1
#define MIB_REGISTRATION_FAILED		-2

#define MIB_UNREGISTERED_OK		 0
#define MIB_NO_SUCH_REGISTRATION	-1
#define MIB_UNREGISTRATION_FAILED	-2

#define DEFAULT_MIB_PRIORITY		127

#define ALLOCATE_THIS_INDEX		0x0
#define ALLOCATE_ANY_INDEX		0x1
#define ALLOCATE_NEW_INDEX		0x3
	/* N.B: it's deliberate that NEW_INDEX & ANY_INDEX == ANY_INDEX */

#define ANY_INTEGER_INDEX		-1
#define ANY_STRING_INDEX		NULL
#define ANY_OID_INDEX			NULL

#define	INDEX_ERR_GENERR		-1
#define	INDEX_ERR_WRONG_TYPE		-2
#define	INDEX_ERR_NOT_ALLOCATED		-3
#define	INDEX_ERR_WRONG_SESSION		-4

char*                 register_string_index( oid *, size_t, char *);
int                   register_int_index( oid *, size_t, int);
struct variable_list* register_oid_index( oid *, size_t, oid *, size_t);
struct variable_list* register_index( struct variable_list *, int, struct snmp_session*);

int  release_index( struct variable_list *);
int  remove_index( struct variable_list *, struct snmp_session*);
void unregister_index_by_session(struct snmp_session *);
int  unregister_index(struct variable_list *, int, struct snmp_session *);

void setup_tree (void);
struct subtree *find_subtree (oid *, size_t, struct subtree *);
struct subtree *find_subtree_next (oid *, size_t, struct subtree *);
struct subtree *find_subtree_previous (oid *, size_t, struct subtree *);
struct snmp_session *get_session_for_oid( oid *, size_t);

int register_mib(const char *, struct variable *, size_t, size_t, oid *, size_t);
int register_mib_priority(const char *, struct variable *, size_t, size_t, oid *, size_t, int);
int register_mib_range(const char *, struct variable *, size_t , size_t , oid *, size_t, int, int, oid, struct snmp_session *);

int unregister_mib (oid *, size_t);
int unregister_mib_priority (oid *, size_t, int);
int unregister_mib_range (oid *, size_t, int, int, oid);
void unregister_mibs_by_session (struct snmp_session *);

struct subtree *free_subtree (struct subtree *);
int compare_tree (const oid *, size_t, const oid *, size_t);
int in_a_view(oid *, size_t *, struct snmp_pdu *, int);
int check_access(struct snmp_pdu *pdu);

/* REGISTER_MIB(): This macro simply loads register_mib with less pain:

   descr:   A short description of the mib group being loaded.
   var:     The variable structure to load.
   vartype: The variable structure used to define it (variable2, variable4, ...)
   theoid:  A *initialized* *exact length* oid pointer.
            (sizeof(theoid) *must* return the number of elements!) 
*/
#define REGISTER_MIB(descr, var, vartype, theoid)                      \
  if (register_mib(descr, (struct variable *) var, sizeof(struct vartype), \
               sizeof(var)/sizeof(struct vartype),                     \
               theoid, sizeof(theoid)/sizeof(oid)) != MIB_REGISTERED_OK ) \
	DEBUGMSGTL(("register_mib", "%s registration failed\n", descr));

#endif /* AGENT_REGISTRY_H */
