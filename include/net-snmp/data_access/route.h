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
typedef struct netsnmp_route_s {

   netsnmp_index oid_index;

   int     flags;

   u_int32_t if_index;

   oid       rt_indexes[4];
#define rt_dest    rt_indexes[0]
#define rt_mask    rt_indexes[1]
#define rt_tos     rt_indexes[2]
#define rt_nexthop rt_indexes[3]

   u_int32_t rt_age;
   u_int32_t rt_nexthop_as;
   u_int32_t rt_metric1;
   u_int32_t rt_metric2;
   u_int32_t rt_metric3;
   u_int32_t rt_metric4;
   u_int32_t rt_metric5;

   oid      *rt_info; /* NULL should be interpreted as { 0, 0 } */
   u_int8_t  rt_info_len;

   u_int8_t  rt_type;
   u_int8_t  rt_proto;

   u_int8_t  row_status; // xxx-rks: keep in mib data

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
