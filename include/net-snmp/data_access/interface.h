/*
 * interface data access header
 *
 * $Id$
 */
#ifndef NETSNMP_ACCESS_INTERFACE_H
#define NETSNMP_ACCESS_INTERFACE_H

#ifndef NETSNMP_CPP_WRAP_START
# ifdef __cplusplus
#  define NETSNMP_CPP_WRAP_START extern          "C" {
#  define NETSNMP_CPP_WRAP_END                   };
# else
#  define NETSNMP_CPP_WRAP_START
#  define NETSNMP_CPP_WRAP_END
# endif
#endif
NETSNMP_CPP_WRAP_START  /* no semi-colon */

/*
 * define flags to indicate the availability of certain data
 */
#define NETSNMP_INTERFACE_FLAGS_ACTIVE			0x01
#define NETSNMP_INTERFACE_FLAGS_HAS_BYTES		0x02
#define NETSNMP_INTERFACE_FLAGS_HAS_DROPS		0x04
#define NETSNMP_INTERFACE_FLAGS_HAS_MCAST_PKTS		0x08
#define NETSNMP_INTERFACE_FLAGS_HAS_HIGH_BYTES		0x10
#define NETSNMP_INTERFACE_FLAGS_HAS_HIGH_PACKETS	0x20
#define NETSNMP_INTERFACE_FLAGS_HAS_HIGH_SPEED		0x40
#define NETSNMP_INTERFACE_FLAGS_DYNAMIC_SPEED		0x80
#define NETSNMP_INTERFACE_FLAGS_HAS_LASTCHANGE		0x100
#define NETSNMP_INTERFACE_FLAGS_HAS_DISCONTINUITY	0x200

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
    struct counter64 if_ibytes;
    struct counter64 if_iucast;
    struct counter64 if_imcast;
    struct counter64 if_ibcast;
    unsigned int     if_ierrors;
    unsigned int     if_idiscards;
    unsigned int     if_iunknown_protos;
   /** output */
    struct counter64 if_obytes;
    struct counter64 if_oucast;
    struct counter64 if_omcast;
    struct counter64 if_obcast;
    unsigned int     if_oerrors;
    unsigned int     if_odiscards;
    unsigned int     if_oqlen;
    unsigned int     if_collisions;
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
    char   *if_alias;
    char   *if_old_alias;
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
   char  if_link_updown_trap;
   char  if_connector_present;

   /*
    * statistics
    */
   netsnmp_interface_stats stats;

} netsnmp_interface_entry;

/** I learned this nasty trick in kernel header files */
#define if_ibytes stats.if_ibytes
#define if_iucast stats.if_iucast
#define if_imcast stats.if_imcast
#define if_ibcast stats.if_ibcast
#define if_ierrors stats.if_ierrors
#define if_idiscards stats.if_idiscards
#define if_iunknown_protos stats.if_iunknown_protos
#define if_obytes stats.if_obytes
#define if_oucast stats.if_oucast
#define if_omcast stats.if_omcast
#define if_obcast stats.if_obcast
#define if_oerrors stats.if_oerrors
#define if_odiscards stats.if_odiscards
#define if_oqlen stats.if_oqlen
#define if_collisions stats.if_collisions

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

/**---------------------------------------------------------------------*/

NETSNMP_CPP_WRAP_END

#endif /* NETSNMP_ACCESS_INTERFACE_H */
