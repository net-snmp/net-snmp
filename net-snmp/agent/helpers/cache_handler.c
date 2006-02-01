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
long                 caching_enabled       = 1;
long                 cache_default_timeout = 5;		/* in seconds */
int                  cache_outstanding_valid = 0;

#define CACHE_RELEASE_FREQUENCY	60	/* Check for expired caches every 60s */

void release_cached_resources( unsigned int regNo, void *clientargs );

/** @defgroup cache_handler cache_handler
 *  Maintains a cache of data for use by lower level handlers.
 *  @ingroup utilities
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
            cache->enabled     = 1;

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

/** Extract the cache information for a given request */
netsnmp_cache  *
netsnmp_extract_cache_info(netsnmp_agent_request_info *reqinfo)
{
    return netsnmp_agent_get_list_data(reqinfo, CACHE_NAME);
}

/** Is the cache valid for a given request? */
int
netsnmp_is_cache_valid(netsnmp_agent_request_info *reqinfo)
{
    netsnmp_cache  *cache = netsnmp_extract_cache_info(reqinfo);
    return (cache && cache->valid);
}

/** Implements the cache handler */
int
netsnmp_cache_helper_handler(netsnmp_mib_handler *handler,
                                 netsnmp_handler_registration *reginfo,
                                 netsnmp_agent_request_info *reqinfo,
                                 netsnmp_request_info *requests)
{
  netsnmp_cache       *cache = NULL;
  long cache_timeout;
  int  ret;

  DEBUGMSGTL(("helper:cache_handler", "Got request (%d): ", reqinfo->mode));
  DEBUGMSGOID(("helper:cache_handler", reginfo->rootoid, reginfo->rootoid_len));

  cache = (netsnmp_cache *)handler->myvoid;
  switch (reqinfo->mode) {

  case MODE_GET:
  case MODE_GETNEXT:
  case MODE_GETBULK:
    /*
     * If caching is active, and the cache is out-of-date (or invalid),
     * call the load hook, and update the cache timestamp.
     */
    if (caching_enabled && cache && cache->enabled) {
        cache_timeout = cache->timeout;
        if (cache_timeout == 0)
            cache_timeout = cache_default_timeout;
        if (!cache->valid || !cache->timestamp ||
             atime_ready(cache->timestamp, 1000*cache_timeout)) {
            /*
             * If we've got a valid cache, then release it before reloading
             */
            if (cache->valid) {
                cache->free_cache(cache, cache->magic);
                cache->valid = 0;
            }
            ret = cache->load_cache(cache, cache->magic);
            if (ret < 0) {
                DEBUGMSG(("helper:cache_handler", " load failed (%d)\n", ret));
                goto done;	/* XXX - or return ? */
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
            DEBUGMSG(("helper:cache_handler", " loaded (%d)\n", cache_timeout));
        } else {
            DEBUGMSG(("helper:cache_handler", " cached (%d)\n", cache_timeout));
        }
        netsnmp_agent_add_list_data(reqinfo,
                                    netsnmp_create_data_list(CACHE_NAME,
                                                             cache, NULL));
    } else {
        DEBUGMSG(("helper:cache_handler", " skipped\n"));
    }

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
    if (cache && cache->valid /* && some flag ? */) {
        cache->free_cache(cache, cache->magic);
        cache->valid = 0;
    }
    break;

  default:
    snmp_log(LOG_WARNING, "cache_handler: Unrecognised mode (%d)\n", 
                           reqinfo->mode);
  }

done:
  return netsnmp_call_next_handler(handler, reginfo, reqinfo,
                                   requests);
}



/** run regularly to automatically release cached resources.
 */
void
release_cached_resources( unsigned int regNo, void *clientargs ) {
    netsnmp_cache *cache = NULL;
    long cache_timeout;

    cache_outstanding_valid = 0;
    DEBUGMSGTL(("helper:cache_handler", "running auto-release\n"));
    for (cache=cache_head; cache; cache=cache->next) {
        if (cache->valid) {
            /*
             * Check to see if this cache has timed out.
             * If so, release the cached resources.
             * Otherwise, note that we still have at
             *   least one active cache.
             */
            cache_timeout = cache->timeout;
            if (cache_timeout == 0)
                cache_timeout = cache_default_timeout;
            if (!cache->timestamp ||
                 atime_ready(cache->timestamp, 1000*cache_timeout)) {
                cache->free_cache(cache, cache->magic);
                cache->valid = 0;
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
