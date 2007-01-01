#ifndef VAR_STRUCT_H
#define VAR_STRUCT_H
/*
 * The subtree structure contains a subtree prefix which applies to
 * all variables in the associated variable list.
 *
 * By converting to a tree of subtree structures, entries can
 * now be subtrees of another subtree in the structure. i.e:
 * 1.2
 * 1.2.0
 */

#define UCD_REGISTRY_OID_MAX_LEN	128

struct subtree {
    oid			name[UCD_REGISTRY_OID_MAX_LEN];
					/* objid prefix of registered subtree */
    u_char 		namelen;	/* number of subid's in name above */
    oid			start[UCD_REGISTRY_OID_MAX_LEN];
					/* objid of start of covered range */
    u_char 		start_len;	/* number of subid's in start name */
    oid			end[UCD_REGISTRY_OID_MAX_LEN];
					/* objid of end of covered range */
    u_char 		end_len;	/* number of subid's in end name */
    struct variable	*variables;   /* pointer to variables array */
    int			variables_len;	/* number of entries in above array */
    int			variables_width; /* sizeof each variable entry */
    char                label[256];     /* calling module's label */
    struct snmp_session *session;
    u_char		flags;
    u_char		priority;
    int 		timeout;
    struct subtree      *next;		/* List of 'sibling' subtrees */
    struct subtree      *prev;		/* Make siblings a doubly-linked list */
    struct subtree      *children;	/* List of 'child' subtrees */
};

/*
 * This is a new variable structure that doesn't have as much memory
 * tied up in the object identifier.  It's elements have also been re-arranged
 * so that the name field can be variable length.  Any number of these
 * structures can be created with lengths tailor made to a particular
 * application.  The first 5 elements of the structure must remain constant.
 */
struct variable2 {
    u_char          magic;          /* passed to function as a hint */
    u_char          type;           /* type of variable */
    u_short         acl;            /* access control list for variable */
    FindVarMethod  *findVar;        /* function that finds variable */
    u_char          namelen;        /* length of name below */
    oid             name[2];       /* object identifier of variable */
};

struct variable4 {
    u_char          magic;          /* passed to function as a hint */
    u_char          type;           /* type of variable */
    u_short         acl;            /* access control list for variable */
    FindVarMethod  *findVar;        /* function that finds variable */
    u_char          namelen;        /* length of name below */
    oid             name[4];       /* object identifier of variable */
};

struct variable7 {
    u_char          magic;          /* passed to function as a hint */
    u_char          type;           /* type of variable */
    u_short         acl;            /* access control list for variable */
    FindVarMethod  *findVar;        /* function that finds variable */
    u_char          namelen;        /* length of name below */
    oid             name[7];       /* object identifier of variable */
};

struct variable8 {
    u_char          magic;          /* passed to function as a hint */
    u_char          type;           /* type of variable */
    u_short         acl;            /* access control list for variable */
    FindVarMethod  *findVar;        /* function that finds variable */
    u_char          namelen;        /* length of name below */
    oid             name[8];       /* object identifier of variable */
};

struct variable13 {
    u_char          magic;          /* passed to function as a hint */
    u_char          type;           /* type of variable */
    u_short         acl;            /* access control list for variable */
    FindVarMethod  *findVar;        /* function that finds variable */
    u_char          namelen;        /* length of name below */
    oid             name[13];       /* object identifier of variable */
};
#endif /* VAR_STRUCT_H */
