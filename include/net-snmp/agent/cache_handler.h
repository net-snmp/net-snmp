#ifndef CACHE_H
#define CACHE_H

/*
 * This caching helper provides a generalised (SNMP-manageable) caching
 * mechanism.  Individual SNMP table and scalar/scalar group MIB
 * implementations can use data caching in a consistent manner, without
 * needing to handle the generic caching details themselves.
 */

#include <net-snmp/library/tools.h>

#ifdef __cplusplus
extern          "C" {
#endif

    typedef struct netsnmp_cache_s netsnmp_cache;

    typedef int  (NetsnmpCacheLoad)(netsnmp_cache*, void*);
    typedef void (NetsnmpCacheFree)(void);

    struct netsnmp_cache_s {
        /*
	 * For operation of the data caches
	 */
        int      enabled;
        int      timeout;	/* Length of time the cache is valid (in s) */
        marker_t timestamp;	/* When the cache was last loaded */

        NetsnmpCacheLoad *load_cache;
        NetsnmpCacheFree *free_cache;
        void             *magic;	/* You never know when it might
                                                     not come in useful .... */

        /*
	 * For SNMP-management of the data caches
	 */
	netsnmp_cache *next, *prev;
        oid *rootoid;
        int  rootoid_len;
    };


    netsnmp_mib_handler *netsnmp_get_cache_handler(int, NetsnmpCacheLoad *,
                                                        NetsnmpCacheFree *,
                                                        oid*, int);
    int   netsnmp_register_cache_handler(netsnmp_handler_registration *reginfo,
                                         int, NetsnmpCacheLoad *,
                                              NetsnmpCacheFree *);

    Netsnmp_Node_Handler netsnmp_cache_helper_handler;

#ifdef __cplusplus
};
#endif
#endif
