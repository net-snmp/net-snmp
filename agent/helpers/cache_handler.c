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

static netsnmp_cache  *cache_head = NULL;
static int             cache_outstanding_valid = 0;
static int             _cache_load( netsnmp_cache *cache );

#define CACHE_RELEASE_FREQUENCY 60      /* Check for expired caches every 60s */

void            release_cached_resources(unsigned int regNo,
                                         void *clientargs);

/** @defgroup cache_handler cache_handler: Maintains a cache of data for use by lower level handlers.
 *  @ingroup utilities
 *  This helper checks to see whether the data has been loaded "recently"
 *  (according to the timeout for that particular cache) and calls the
 *  registered "load_cache" routine if necessary.
 *  The lower handlers can then work with this local cached data.
 *
 *  To minimze resource use by the agent, a periodic callback checks for
 *  expired caches, and will call the free_cache function for any expired
 *  cache.
 *
 *  The load_cache route should return a negative number if the cache
 *  was not successfully loaded. 0 or any positive number indicates successs.
 *
 *
 *  Several flags can be set to affect the operations on the cache.
 *
 *  If NETSNMP_CACHE_DONT_INVALIDATE_ON_SET is set, the free_cache method
 *  will not be called after a set request has processed. It is assumed that
 *  the lower mib handler using the cache has maintained cache consistency.
 *
 *  If NETSNMP_CACHE_DONT_FREE_EXPIRED is set, the free_cache method will
 *  not be called with the cache expires. The expired flag will be set, but
 *  the valid flag will not be cleared. It is assumed that the load_cache
 *  routine will properly deal with being called with a valid cache.
 *
 *  If NETSNMP_CACHE_PRELOAD is set when a the cache handler is created,
 *  the cache load routine will be called immediately.
 *
 *  If NETSNMP_CACHE_DONT_AUTO_RELEASE is set, the periodic callback that
 *  checks for expired caches will skip the cache. The cache will only be
 *  checked for expiration when a request triggers the cache handler. This
 *  is useful if the cache has it's own periodic callback to keep the cache
 *  fresh.
 *
 *  @{
 */

/** get cache head
 * @internal
 * unadvertised function to get cache head. You really should not
 * do this, since the internal storage mechanism might change.
 */
netsnmp_cache *
netsnmp_cache_get_head(void)
{
    return cache_head;
}

/** find existing cache
 */
netsnmp_cache *
netsnmp_cache_find_by_oid(oid * rootoid, int rootoid_len)
{
    netsnmp_cache  *cache;

    for (cache = cache_head; cache; cache = cache->next) {
        if (0 == netsnmp_oid_equals(cache->rootoid, cache->rootoid_len,
                                    rootoid, rootoid_len))
            return cache;
    }
    
    return NULL;
}

/** returns a cache
 */
netsnmp_cache *
netsnmp_cache_create(int timeout, NetsnmpCacheLoad * load_hook,
                     NetsnmpCacheFree * free_hook,
                     oid * rootoid, int rootoid_len)
{
    netsnmp_cache  *cache = NULL;

    cache = SNMP_MALLOC_TYPEDEF(netsnmp_cache);
    if (NULL == cache) {
        snmp_log(LOG_ERR,"malloc error in netsnmp_cache_create\n");
        return NULL;
    }
    cache->timeout = timeout;
    cache->load_cache = load_hook;
    cache->free_cache = free_hook;
    cache->enabled = 1;

    if(0 == cache->timeout)
        cache->timeout = netsnmp_ds_get_int(NETSNMP_DS_APPLICATION_ID,
                                            NETSNMP_DS_AGENT_CACHE_TIMEOUT);

    
    /*
     * Add the registered OID information, and tack
     * this onto the list for cache SNMP management
     *
     * Note that this list is not ordered.
     *    table_iterator rules again!
     */
    cache->rootoid = snmp_duplicate_objid(rootoid, rootoid_len);
    cache->rootoid_len = rootoid_len;
    cache->next = cache_head;
    if (cache_head)
        cache_head->prev = cache;
    cache_head = cache;

    return cache;
}

/** returns a cache handler that can be injected into a given handler chain.  
 */
netsnmp_mib_handler *
netsnmp_cache_handler_get(netsnmp_cache* cache)
{
    netsnmp_mib_handler *ret = NULL;

    ret = netsnmp_create_handler("cache_handler",
                                 netsnmp_cache_helper_handler);
    if (ret) {
        ret->flags |= MIB_HANDLER_AUTO_NEXT;
        ret->myvoid = (void *) cache;

        if((cache->flags & NETSNMP_CACHE_PRELOAD) && ! cache->valid) {
            /*
             * load cache, ignore rc (failed load doesn't affect registration)
             */
            (void)_cache_load(cache);
        }
    }
    return ret;
}

/** returns a cache handler that can be injected into a given handler chain.  
 */
netsnmp_mib_handler *
netsnmp_get_cache_handler(int timeout, NetsnmpCacheLoad * load_hook,
                          NetsnmpCacheFree * free_hook,
                          oid * rootoid, int rootoid_len)
{
    netsnmp_mib_handler *ret = NULL;
    netsnmp_cache  *cache = NULL;

    ret = netsnmp_cache_handler_get(NULL);
    if (ret) {
        cache = netsnmp_cache_create(timeout, load_hook, free_hook,
                                     rootoid, rootoid_len);
        ret->myvoid = (void *) cache;
    }
    return ret;
}

/** functionally the same as calling netsnmp_register_handler() but also
 * injects a cache handler at the same time for you. */
int
netsnmp_cache_handler_register(netsnmp_handler_registration * reginfo,
                               netsnmp_cache* cache)
{
    netsnmp_mib_handler *handler = NULL;
    handler = netsnmp_cache_handler_get(cache);

    netsnmp_inject_handler(reginfo, handler);
    return netsnmp_register_handler(reginfo);
}

/** functionally the same as calling netsnmp_register_handler() but also
 * injects a cache handler at the same time for you. */
int
netsnmp_register_cache_handler(netsnmp_handler_registration * reginfo,
                               int timeout, NetsnmpCacheLoad * load_hook,
                               NetsnmpCacheFree * free_hook)
{
    netsnmp_mib_handler *handler = NULL;
    handler = netsnmp_get_cache_handler(timeout, load_hook, free_hook,
                                        reginfo->rootoid,
                                        reginfo->rootoid_len);

    netsnmp_inject_handler(reginfo, handler);
    return netsnmp_register_handler(reginfo);
}

/** Extract the cache information for a given request */
netsnmp_cache  *
netsnmp_extract_cache_info(netsnmp_agent_request_info * reqinfo)
{
    return netsnmp_agent_get_list_data(reqinfo, CACHE_NAME);
}


/** Check if the cache timeout has passed. Sets and return the expired flag. */
int
netsnmp_cache_check_expired(netsnmp_cache *cache)
{
    if(NULL == cache)
        return 0;
    
    if(!cache->valid || (NULL == cache->timestamp))
        cache->expired = 1;
    else
        cache->expired = atime_ready(cache->timestamp, 1000 * cache->timeout);
    
    return cache->expired;
}

/** Is the cache valid for a given request? */
int
netsnmp_cache_is_valid(netsnmp_agent_request_info * reqinfo)
{
    netsnmp_cache  *cache = netsnmp_extract_cache_info(reqinfo);
    return (cache && cache->valid);
}

/** Is the cache valid for a given request?
 * for backwards compatability. netsnmp_cache_is_valid() is preferred.
 */
int
netsnmp_is_cache_valid(netsnmp_agent_request_info * reqinfo)
{
    return netsnmp_cache_is_valid(reqinfo);
}

/** Implements the cache handler */
int
netsnmp_cache_helper_handler(netsnmp_mib_handler * handler,
                             netsnmp_handler_registration * reginfo,
                             netsnmp_agent_request_info * reqinfo,
                             netsnmp_request_info * requests)
{
    netsnmp_cache  *cache = NULL;
    int             ret;

    DEBUGMSGTL(("helper:cache_handler", "Got request (%d): ",
                reqinfo->mode));
    DEBUGMSGOID(("helper:cache_handler", reginfo->rootoid,
                 reginfo->rootoid_len));

    netsnmp_assert(handler->flags & MIB_HANDLER_AUTO_NEXT);

    cache = (netsnmp_cache *) handler->myvoid;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_NO_CACHING) ||
        !cache || !cache->enabled || !cache->load_cache) {
        DEBUGMSG(("helper:cache_handler", " caching disabled or "
                  "cache not found, disabled or had no load method\n"));
        return SNMP_ERR_NOERROR;
    }

    switch (reqinfo->mode) {

    case MODE_GET:
    case MODE_GETNEXT:
    case MODE_GETBULK:
        /*
         * only touch cache once per pdu request
         */
        if(netsnmp_cache_is_valid(reqinfo))
            return SNMP_ERR_NOERROR;

        /*
         * call the load hook, and update the cache timestamp.
         */
        if (!cache->valid || netsnmp_cache_check_expired(cache))
            ret = _cache_load( cache );
        else {
            DEBUGMSG(("helper:cache_handler", " cached (%d)\n",
                      cache->timeout));
        }
        netsnmp_agent_add_list_data(reqinfo,
                                    netsnmp_create_data_list(CACHE_NAME,
                                                             cache, NULL));
        break;

        /*
         * A (successful) SET request wouldn't typically trigger a reload of
         *  the cache, but might well invalidate the current contents.
         * Only do this on the last pass through.
         */
    case MODE_SET_RESERVE1:
    case MODE_SET_RESERVE2:
    case MODE_SET_FREE:
    case MODE_SET_ACTION:
    case MODE_SET_UNDO:
        break;
    case MODE_SET_COMMIT:
        if (cache->valid && 
            ! (cache->flags & NETSNMP_CACHE_DONT_INVALIDATE_ON_SET) ) {
            cache->free_cache(cache, cache->magic);
            cache->valid = 0;
        }
        break;

    default:
        snmp_log(LOG_WARNING, "cache_handler: Unrecognised mode (%d)\n",
                 reqinfo->mode);
    }

    return SNMP_ERR_NOERROR;
}

static void
_cache_free( netsnmp_cache *cache )
{
    if ((NULL != cache->free_cache) && 
        ! (cache->flags & NETSNMP_CACHE_DONT_FREE_EXPIRED)) {
        cache->free_cache(cache, cache->magic);
        cache->valid = 0;
    }
}

static int
_cache_load( netsnmp_cache *cache )
{
    int ret;

    /*
     * If we've got a valid cache, then release it before reloading
     */
    if (cache->valid )
        _cache_free(cache);

    ret = cache->load_cache(cache, cache->magic);
    if (ret < 0) {
        DEBUGMSG(("helper:cache_handler", " load failed (%d)\n",
                  ret));
        cache->valid = 0;
        return ret;
    }
    cache->valid = 1;
    
    /*
     * If we didn't previously have any valid caches outstanding,
     *   then schedule a pass of the auto-release routine.
     */
    if (!cache_outstanding_valid) {
        snmp_alarm_register(CACHE_RELEASE_FREQUENCY,
                            0, release_cached_resources, NULL);
        cache_outstanding_valid = 1;
    }
    if (cache->timestamp)
        atime_setMarker(cache->timestamp);
    else
        cache->timestamp = atime_newMarker();
    DEBUGMSG(("helper:cache_handler", " loaded (%d)\n",
              cache->timeout));

    return ret;
}



/** run regularly to automatically release cached resources.
 * xxx - method to prevent cache from expiring while a request
 *     is being processed (e.g. delegated request). proposal:
 *     set a flag, which would be cleared when request finished
 *     (which could be acomplished by a dummy data list item in
 *     agent req info & custom free function).
 */
void
release_cached_resources(unsigned int regNo, void *clientargs)
{
    netsnmp_cache  *cache = NULL;

    cache_outstanding_valid = 0;
    DEBUGMSGTL(("helper:cache_handler", "running auto-release\n"));
    for (cache = cache_head; cache; cache = cache->next) {
        DEBUGMSGTL(("helper:cache_handler"," checking %p (flags 0x%x)\n",
                     cache, cache->flags));
        if (cache->valid &&
            ! (cache->flags & NETSNMP_CACHE_DONT_AUTO_RELEASE)) {
            DEBUGMSGTL(("helper:cache_handler","  releasing %p\n", cache));
            /*
             * Check to see if this cache has timed out.
             * If so, release the cached resources.
             * Otherwise, note that we still have at
             *   least one active cache.
             */
            if (netsnmp_cache_check_expired(cache)) {
                _cache_free(cache);
            } else {
                cache_outstanding_valid = 1;
            }
        }
    }
    /*
     * If there are any caches still valid & active,
     *   then schedule another pass.
     */
    if (cache_outstanding_valid) {
        snmp_alarm_register(CACHE_RELEASE_FREQUENCY,
                            0, release_cached_resources, NULL);
    }
}
