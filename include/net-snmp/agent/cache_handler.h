#ifndef NETSNMP_CACHE_HANDLER_H
#define NETSNMP_CACHE_HANDLER_H

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

#define CACHE_NAME "cache_info"

    typedef struct netsnmp_cache_s netsnmp_cache;

    typedef int  (NetsnmpCacheLoad)(netsnmp_cache *, void*);
    typedef void (NetsnmpCacheFree)(netsnmp_cache *, void*);

    struct netsnmp_cache_s {
        /*
	 * For operation of the data caches
	 */
        int      flags;
        int      enabled;
        int      valid;
        char     expired;
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


    netsnmp_cache* netsnmp_extract_cache_info(netsnmp_agent_request_info *);
    int            netsnmp_cache_check_expired(netsnmp_cache *cache);
    int            netsnmp_cache_is_valid(    netsnmp_agent_request_info *);
    /** for backwards compat */
    int            netsnmp_is_cache_valid(    netsnmp_agent_request_info *);
    netsnmp_mib_handler *netsnmp_get_cache_handler(int, NetsnmpCacheLoad *,
                                                        NetsnmpCacheFree *,
                                                        oid*, int);
    int   netsnmp_register_cache_handler(netsnmp_handler_registration *reginfo,
                                         int, NetsnmpCacheLoad *,
                                              NetsnmpCacheFree *);

    Netsnmp_Node_Handler netsnmp_cache_helper_handler;

    netsnmp_cache *
    netsnmp_cache_create(int timeout, NetsnmpCacheLoad * load_hook,
                         NetsnmpCacheFree * free_hook,
                         oid * rootoid, int rootoid_len);
    netsnmp_mib_handler *
    netsnmp_cache_handler_get(netsnmp_cache* cache);

    netsnmp_cache * netsnmp_cache_find_by_oid(oid * rootoid,
                                              int rootoid_len);

#define NETSNMP_CACHE_DONT_INVALIDATE_ON_SET                0x0001
#define NETSNMP_CACHE_DONT_FREE_EXPIRED                     0x0002
#define NETSNMP_CACHE_DONT_AUTO_RELEASE                     0x0004
#define NETSNMP_CACHE_PRELOAD                               0x0008

#ifdef __cplusplus
};
#endif
#endif /* NETSNMP_CACHE_HANDLER_H */
