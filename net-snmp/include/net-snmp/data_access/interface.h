/*
 * interface data access header
 *
 * $Id$
 */
#ifndef NETSNMP_ACCESS_INTERFACE_H
#define NETSNMP_ACCESS_INTERFACE_H

# ifdef __cplusplus
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
   /** output */
    struct counter64 obytes;
    struct counter64 oucast;
    struct counter64 omcast;
    struct counter64 obcast;
    unsigned int     oerrors;
    unsigned int     odiscards;
    unsigned int     oqlen;
    unsigned int     collisions;
} netsnmp_interface_stats;

typedef struct netsnmp_interface_entry_s {
    netsnmp_index oid_index;

    int     flags;
    oid     index;

    /*
     *  "Static" information
     *  Typically constant for a given interface
     */
    char   *if_name;
    char   *if_descr;
    int     if_type;
    unsigned int     if_speed;
    unsigned int     if_speed_high;
    char   *if_paddr;
    int     if_paddr_len;
    int     if_mtu;

    u_long  if_lastchange;
    time_t  if_discontinuity;

   char  if_admin_status;
   char  if_oper_status;

   /** booleans (not TruthValues!) */
   char  if_promiscuous;
   char  if_connector_present;

   /*-----------------------------------------------
    * platform/arch/access specific data
    */
   unsigned int if_flags; /* iff NETSNMP_INTERFACE_FLAGS_HAS_FAMILY */

   /*
    * statistics
    */
   netsnmp_interface_stats stats;
   netsnmp_interface_stats *old_stats;

} netsnmp_interface_entry;

/** I learned this nasty trick in kernel header files */
#define if_ibytes stats.ibytes
#define if_iucast stats.iucast
#define if_imcast stats.imcast
#define if_ibcast stats.ibcast
#define if_ierrors stats.ierrors
#define if_idiscards stats.idiscards
#define if_iunknown_protos stats.iunknown_protos
#define if_obytes stats.obytes
#define if_oucast stats.oucast
#define if_omcast stats.omcast
#define if_obcast stats.obcast
#define if_oerrors stats.oerrors
#define if_odiscards stats.odiscards
#define if_oqlen stats.oqlen
#define if_collisions stats.collisions

#define old_ibytes old_stats->ibytes
#define old_iucast old_stats->iucast
#define old_imcast old_stats->imcast
#define old_ibcast old_stats->ibcast
#define old_ierrors old_stats->ierrors
#define old_idiscards old_stats->idiscards
#define old_iunknown_protos old_stats->iunknown_protos
#define old_obytes old_stats->obytes
#define old_oucast old_stats->oucast
#define old_omcast old_stats->omcast
#define old_obcast old_stats->obcast
#define old_oerrors old_stats->oerrors
#define old_odiscards old_stats->odiscards
#define old_oqlen old_stats->oqlen
#define old_collisions old_stats->collisions

/*
 * conf file overrides
 */
typedef struct _conf_if_list {
    char           *name;
    int             type;
    u_long          speed;
    struct _conf_if_list *next;
} netsnmp_conf_if_list;


/**---------------------------------------------------------------------*/
/*
 * ACCESS function prototypes
 */

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
netsnmp_access_interface_entry_create(const char *name);

void netsnmp_access_interface_entry_free(netsnmp_interface_entry * entry);

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
 * copy interface entry data
 */
int netsnmp_access_interface_entry_copy(netsnmp_interface_entry * lhs,
                                        netsnmp_interface_entry * rhs);

void netsnmp_access_interface_entry_guess_speed(netsnmp_interface_entry *);
void netsnmp_access_interface_entry_overrides(netsnmp_interface_entry *);


netsnmp_conf_if_list *
netsnmp_access_interface_entry_overrides_get(const char * name);

/**---------------------------------------------------------------------*/

# ifdef __cplusplus
};
#endif

#endif /* NETSNMP_ACCESS_INTERFACE_H */
