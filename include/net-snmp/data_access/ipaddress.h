/*
 * ipaddress data access header
 *
 * $Id$
 */
#ifndef NETSNMP_ACCESS_IPADDRESS_H
#define NETSNMP_ACCESS_IPADDRESS_H

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

/**---------------------------------------------------------------------*/
/*
 * structure definitions
 */
#if defined( INET6 )
#   define NETSNMP_ACCESS_IPADDRESS_BUF_SIZE 16
#else
#   define NETSNMP_ACCESS_IPADDRESS_BUF_SIZE 4
#endif


/*
 * netsnmp_ipaddress_entry
 *   - primary ipaddress structure for both ipv4 & ipv6
 */
typedef struct netsnmp_ipaddress_s {

   netsnmp_index oid_index;   /* MUST BE FIRST!! for container use */
   oid           ns_ia_index; /* arbitrary index */

   int       flags; /* for net-snmp use */

   u_char    ia_address[NETSNMP_ACCESS_IPADDRESS_BUF_SIZE];

   oid       if_index;

   oid      *ia_prefix_oid; /* NULL == 0.0 */

   int       ia_flags;      /* ioctl flags */

   u_char    ia_address_len;/* address len, 4 | 16 */
   u_char    ia_prefix_oid_len; /* 1-128 oids */
   u_char    ia_type;       /* 1-3 */
   u_char    ia_status;     /* IpAddressStatus (1-7) */
   u_char    ia_origin;     /* IpAddressOrigin (1-6) */

} netsnmp_ipaddress_entry;


/**---------------------------------------------------------------------*/
/*
 * ACCESS function prototypes
 */
/*
 * ifcontainer init
 */
netsnmp_container * netsnmp_access_ipaddress_container_init(u_int init_flags);
#define NETSNMP_ACCESS_IPADDRESS_INIT_NOFLAGS               0x0000
//#define NETSNMP_ACCESS_IPADDRESS_INIT_ADDL_IDX_BY_NAME      0x0001

/*
 * ifcontainer load and free
 */
netsnmp_container*
netsnmp_access_ipaddress_container_load(netsnmp_container* container,
                                    u_int load_flags);
#define NETSNMP_ACCESS_IPADDRESS_LOAD_NOFLAGS               0x0000
#define NETSNMP_ACCESS_IPADDRESS_LOAD_IPV4_ONLY             0x0001

void netsnmp_access_ipaddress_container_free(netsnmp_container *container,
                                         u_int free_flags);
#define NETSNMP_ACCESS_IPADDRESS_FREE_NOFLAGS               0x0000
#define NETSNMP_ACCESS_IPADDRESS_FREE_DONT_CLEAR            0x0001
#define NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER        0x0002


/*
 * create/free a ipaddress+entry
 */
netsnmp_ipaddress_entry *
netsnmp_access_ipaddress_entry_create(void);

void netsnmp_access_ipaddress_entry_free(netsnmp_ipaddress_entry * entry);

/*
 * find entry in container
 */
/** not yet */

/**---------------------------------------------------------------------*/

NETSNMP_CPP_WRAP_END

#endif /* NETSNMP_ACCESS_IPADDRESS_H */
