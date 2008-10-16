/*
 * interface data access header
 *
 * $Id$
 */
#ifndef NETSNMP_ACCESS_INTERFACE_H
#define NETSNMP_ACCESS_INTERFACE_H

#ifdef __cplusplus
extern          "C" {
#endif

/*
 * define flags to indicate the availability of certain data
 */
#define NETSNMP_INTERFACE_FLAGS_ACTIVE			0x00000001
#define NETSNMP_INTERFACE_FLAGS_HAS_BYTES		0x00000002
#define NETSNMP_INTERFACE_FLAGS_HAS_DROPS		0x00000004
#define NETSNMP_INTERFACE_FLAGS_HAS_MCAST_PKTS		0x00000008
#define NETSNMP_INTERFACE_FLAGS_HAS_HIGH_BYTES		0x00000010
#define NETSNMP_INTERFACE_FLAGS_HAS_HIGH_PACKETS	0x00000020
#define NETSNMP_INTERFACE_FLAGS_HAS_HIGH_SPEED		0x00000040
#define NETSNMP_INTERFACE_FLAGS_DYNAMIC_SPEED		0x00000080
#define NETSNMP_INTERFACE_FLAGS_HAS_LASTCHANGE		0x00000100
#define NETSNMP_INTERFACE_FLAGS_HAS_DISCONTINUITY	0x00000200
#define NETSNMP_INTERFACE_FLAGS_HAS_IF_FLAGS      	0x00000400

/*************************************************************
 * constants for enums for the MIB node
 * ifAdminStatus (INTEGER / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redifinitions of the enum values.
 */
#ifndef ifAdminStatus_ENUMS
#define ifAdminStatus_ENUMS

#define IFADMINSTATUS_UP  1
#define IFADMINSTATUS_DOWN  2
#define IFADMINSTATUS_TESTING  3

#endif                          /* ifAdminStatus_ENUMS */

/*************************************************************
 * constants for enums for the MIB node
 * ifOperStatus (INTEGER / ASN_INTEGER)
 *
 * since a Textual Convention may be referenced more than once in a
 * MIB, protect againt redifinitions of the enum values.
 */
#ifndef ifOperStatus_ENUMS
#define ifOperStatus_ENUMS

#define IFOPERSTATUS_UP  1
#define IFOPERSTATUS_DOWN  2
#define IFOPERSTATUS_TESTING  3

#endif                          /* ifOperStatus_ENUMS */

/**---------------------------------------------------------------------*/
/*
 * structure definitions
 */
typedef struct netsnmp_interface_stats_s {
    /*
     *  "Dynamic" fields
     *  Cached versions of byte/packet counters, etc
     *  (saved as a 'struct counter64' even if the
     *   high order half isn't actually used)
     *
     */
   /** input */
    struct counter64 ibytes;
    struct counter64 iucast;
    struct counter64 imcast;
    struct counter64 ibcast;
    unsigned int     ierrors;
    unsigned int     idiscards;
    unsigned int     iunknown_protos;
    unsigned int     inucast;
   /** output */
    struct counter64 obytes;
    struct counter64 oucast;
    struct counter64 omcast;
    struct counter64 obcast;
    unsigned int     oerrors;
    unsigned int     odiscards;
    unsigned int     oqlen;
    unsigned int     collisions;
    unsigned int     onucast;
} netsnmp_interface_stats;

typedef struct netsnmp_interface_entry_s {
    netsnmp_index oid_index;

    int     ns_flags; /* net-snmp flags */
    oid     index;

    /*
     *  "Static" information
     *  Typically constant for a given interface
     */
    char   *name;
    char   *descr;
    int     type;
    unsigned int     speed;
    unsigned int     speed_high;
    char   *paddr;
    int     paddr_len;
    int     mtu;

    u_long  lastchange;
    time_t  discontinuity;

   char  admin_status;
   char  oper_status;

   /** booleans (not TruthValues!) */
   char  promiscuous;
   char  connector_present;

   /*-----------------------------------------------
    * platform/arch/access specific data
    */
   unsigned int os_flags; /* iff NETSNMP_INTERFACE_FLAGS_HAS_FAMILY */

   /*
    * statistics
    */
   netsnmp_interface_stats stats;

   /** old_stats is used in netsnmp_access_interface_entry_update_stats */
   netsnmp_interface_stats *old_stats;

} netsnmp_interface_entry;

/*
 * conf file overrides
 */
typedef struct _conf_if_list {
    const char     *name;
    int             type;
    unsigned long long speed;
    struct _conf_if_list *next;
} netsnmp_conf_if_list;

    typedef netsnmp_conf_if_list conf_if_list; /* backwards compat */

/**---------------------------------------------------------------------*/
/*
 * ACCESS function prototypes
 */
void init_interface_common(void);
void netsnmp_access_interface_init(void);

/*
 * ifcontainer init
 */
netsnmp_container * netsnmp_access_interface_container_init(u_int init_flags);
#define NETSNMP_ACCESS_INTERFACE_INIT_NOFLAGS               0x0000
#define NETSNMP_ACCESS_INTERFACE_INIT_ADDL_IDX_BY_NAME      0x0001

/*
 * ifcontainer load and free
 */
netsnmp_container*
netsnmp_access_interface_container_load(netsnmp_container* container,
                                        u_int load_flags);
#define NETSNMP_ACCESS_INTERFACE_LOAD_NOFLAGS               0x0000

void netsnmp_access_interface_container_free(netsnmp_container *container,
                                             u_int free_flags);
#define NETSNMP_ACCESS_INTERFACE_FREE_NOFLAGS               0x0000
#define NETSNMP_ACCESS_INTERFACE_FREE_DONT_CLEAR            0x0001


/*
 * create/free an ifentry
 */
netsnmp_interface_entry *
netsnmp_access_interface_entry_create(const char *name, oid if_index);

void netsnmp_access_interface_entry_free(netsnmp_interface_entry * entry);

int
netsnmp_access_interface_entry_set_admin_status(netsnmp_interface_entry * entry,
	                                                int ifAdminStatus);

/*
 * find entry in container
 */
netsnmp_interface_entry *
netsnmp_access_interface_entry_get_by_name(netsnmp_container *container,
                                           const char *name);
netsnmp_interface_entry *
netsnmp_access_interface_entry_get_by_index(netsnmp_container *container,
                                            oid index);

/*
 * find ifIndex for given interface. 0 == not found.
 */
oid netsnmp_access_interface_index_find(const char *name);

/*
 * find name for given index
 */
const char *netsnmp_access_interface_name_find(oid index);

/*
 * copy interface entry data
 */
int netsnmp_access_interface_entry_copy(netsnmp_interface_entry * lhs,
                                        netsnmp_interface_entry * rhs);

void netsnmp_access_interface_entry_guess_speed(netsnmp_interface_entry *);
void netsnmp_access_interface_entry_overrides(netsnmp_interface_entry *);


netsnmp_conf_if_list *
netsnmp_access_interface_entry_overrides_get(const char * name);


/**---------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* NETSNMP_ACCESS_INTERFACE_H */
