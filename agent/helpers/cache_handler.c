#include <net-snmp/net-snmp-config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/cache_handler.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

netsnmp_cache       *cache_head = NULL;

/** @defgroup cache_handler cache_handler: Maintains a cache of data for use by lower level handlers.
 *  @ingroup handler
 *  This helper checks to see whether the data has been loaded "recently"
 *  (according to the timeout for that particular cache) and calls the
 *  registered "load_cache" routine if necessary.
 *  The lower handlers can then work with this local cached data.
 *  @{
 */

/** returns a cache handler that can be injected into a given handler chain.  
 */
netsnmp_mib_handler *
netsnmp_get_cache_handler(int timeout, NetsnmpCacheLoad *load_hook,
                                       NetsnmpCacheFree *free_hook,
                                       oid *rootoid, int rootoid_len)
{
    netsnmp_mib_handler *ret   = NULL;
    netsnmp_cache       *cache = NULL;

    ret = netsnmp_create_handler("cache_handler",
                                  netsnmp_cache_helper_handler);
    if (ret) {
        cache = SNMP_MALLOC_TYPEDEF(netsnmp_cache);
        if (cache) {
            cache->timeout     = timeout;
            cache->load_cache  = load_hook;
            cache->free_cache  = free_hook;

            /*
	     * Add the registered OID information, and tack
	     * this onto the list for cache SNMP management
	     *
	     * Note that this list is not ordered.
	     *    table_iterator rules again!
	     */
            cache->rootoid     = snmp_duplicate_objid(rootoid, rootoid_len);
            cache->rootoid_len = rootoid_len;
	    cache->next = cache_head;
	    if (cache_head)
	        cache_head->prev = cache;
	    cache_head = cache;
	}
        ret->myvoid = (void *) cache;
    }
    return ret;
}

/** functionally the same as calling netsnmp_register_handler() but also
 * injects a cache handler at the same time for you. */
int
netsnmp_register_cache_handler(netsnmp_handler_registration *reginfo,
                               int timeout, NetsnmpCacheLoad *load_hook,
                                            NetsnmpCacheFree *free_hook)
{
    netsnmp_mib_handler *handler = NULL;
    handler = netsnmp_get_cache_handler(timeout, load_hook, free_hook,
		    		reginfo->rootoid, reginfo->rootoid_len);

    netsnmp_inject_handler(reginfo, handler);
    return netsnmp_register_handler(reginfo);
}


/** Implements the cache handler */
int
netsnmp_cache_helper_handler(netsnmp_mib_handler *handler,
                                 netsnmp_handler_registration *reginfo,
                                 netsnmp_agent_request_info *reqinfo,
                                 netsnmp_request_info *requests)
{
    netsnmp_cache       *cache = NULL;

    DEBUGMSGTL(("helper:cache_handler", "Got request\n"));
    DEBUGMSGOID(("helper:cache_handler", reginfo->rootoid, reginfo->rootoid_len));

    cache = (netsnmp_cache *)handler->myvoid;
    /*
     * If the cache is out-of-date (or invalid),
     * call the load hook, and update the cache timestamp
     */
    if (!atime_ready(cache->timestamp, 1000*cache->timeout)) {
        cache->load_cache(cache);	/* XXX - what if this fails? */
        if (cache->timestamp)
       	    atime_setMarker(cache->timestamp);
	else
            cache->timestamp = atime_newMarker();
        DEBUGMSG(("helper:cache_handler", "loaded\n"));
    } else {
        DEBUGMSG(("helper:cache_handler", "cached\n"));
    }

    return netsnmp_call_next_handler(handler, reginfo, reqinfo,
                                     requests);
}

