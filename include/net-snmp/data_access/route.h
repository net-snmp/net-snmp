/*
 * route data access header
 *
 * $Id$
 */
#ifndef NETSNMP_ACCESS_ROUTE_H
#define NETSNMP_ACCESS_ROUTE_H

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
#   define NETSNMP_ACCESS_ROUTE_ADDR_BUF_SIZE 16
#else
#   define NETSNMP_ACCESS_ROUTE_ADDR_BUF_SIZE 4
#endif


/*
 * netsnmp_route_entry
 *   - primary route structure for both ipv4 & ipv6
 */
typedef struct netsnmp_route_s {

   netsnmp_index oid_index;   /* MUST BE FIRST!! for container use */
   u_int         ns_rt_index; /* arbitrary index */

   int       flags; /* for net-snmp use */

   oid       if_index;

   u_char    rt_dest[NETSNMP_ACCESS_ROUTE_ADDR_BUF_SIZE];
   u_char    rt_nexthop[NETSNMP_ACCESS_ROUTE_ADDR_BUF_SIZE];

#ifdef USING_IP_FORWARD_MIB_INETCIDRROUTETABLE_INETCIDRROUTETABLE_MODULE
   oid      *rt_policy;      /* NULL should be interpreted as { 0, 0 } */
   u_char    rt_policy_len;  /* 0-128 oids */
#endif

   u_char    rt_dest_len;    /* 4 | 16 since we only do ipv4|ipv6 */
   u_char    rt_dest_type;   /* InetAddressType 0-16 */
   u_char    rt_nexthop_len; /* 4 | 16 since we only do ipv4|ipv6*/
   u_char    rt_nexthop_type;/* InetAddressType 0-16 */
   u_char    rt_pfx_len;     /* 0-128 bits */
   u_char    rt_type;        /* ip(1-4) != inet(1-5) */
   u_char    rt_proto;       /* ip(enum 1-16) ?= inet(IANAipRouteProtocol 1-17) */

#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
   /** rt_info != inet_policy, because that would have made sense */
   u_int8_t  rt_info_len;    /* 0-128 oids */
   oid      *rt_info;        /* NULL should be interpreted as { 0, 0 } */

   u_int32_t rt_mask;        /* ipv4 only */
   u_int32_t rt_tos;         /* Integer32 (0..2147483647) */
#endif

   u_int32_t rt_age;         /* seconds (ip == inet) */
   int32_t   rt_nexthop_as;  /* ip(int32) == inet(InetAutonomousSystemNumber) */

   int32_t   rt_metric1;
   int32_t   rt_metric2;
   int32_t   rt_metric3;
   int32_t   rt_metric4;
   int32_t   rt_metric5;

} netsnmp_route_entry;


/**---------------------------------------------------------------------*/
/*
 * ACCESS function prototypes
 */
/*
 * ifcontainer init
 */
netsnmp_container * netsnmp_access_route_container_init(u_int init_flags);
#define NETSNMP_ACCESS_ROUTE_INIT_NOFLAGS               0x0000
#define NETSNMP_ACCESS_ROUTE_INIT_ADDL_IDX_BY_NAME      0x0001

/*
 * ifcontainer load and free
 */
netsnmp_container*
netsnmp_access_route_container_load(netsnmp_container* container,
                                    u_int load_flags);
#define NETSNMP_ACCESS_ROUTE_LOAD_NOFLAGS               0x0000
#define NETSNMP_ACCESS_ROUTE_LOAD_IPV4_ONLY             0x0001

void netsnmp_access_route_container_free(netsnmp_container *container,
                                         u_int free_flags);
#define NETSNMP_ACCESS_ROUTE_FREE_NOFLAGS               0x0000
#define NETSNMP_ACCESS_ROUTE_FREE_DONT_CLEAR            0x0001
#define NETSNMP_ACCESS_ROUTE_FREE_KEEP_CONTAINER        0x0002


/*
 * create/free a route+entry
 */
netsnmp_route_entry *
netsnmp_access_route_entry_create(void);

void netsnmp_access_route_entry_free(netsnmp_route_entry * entry);

/*
 * find entry in container
 */
/** not yet */

/**---------------------------------------------------------------------*/

NETSNMP_CPP_WRAP_END

#endif /* NETSNMP_ACCESS_ROUTE_H */
