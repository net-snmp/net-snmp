#include <config.h>

#include <sys/types.h>

#if HAVE_STRING_H
#include <string.h>
#endif

#include <mibincl.h>
#include <data_list.h>
#include <snmp_agent.h>
#include <agent_handler.h>
#include <agent_registry.h>
#include <data_list.h>
/***********************************************************************/
/* New Handler based API */
/***********************************************************************/
/** @defgroup handler Agent handler API
 *  @ingroup agent
 *
 *  The basic theory goes something like this: In the past, with the
 *  original mib module api (which derived from the original CMU SNMP
 *  code) the underlying mib modules were passed very little
 *  information (only the truly most basic information about a
 *  request).  This worked well at the time but in todays world of
 *  subagents, device instrumentation, low resource consumption, etc,
 *  it just isn't flexible enough.  "handlers" are here to fix all that.
 *
 *  With the rewrite of the agent internals for the net-snmp 5.0
 *  release, we introduce a modular calling scheme that allows agent
 *  modules to be written in a very flexible manner, and more
 *  importantly allows reuse of code in a decent way (and without the
 *  memory and speed overheads of OO languages like C++).
 *
 *  Functionally, the notion of what a handler does is the same as the
 *  older api: A handler is @link create_handler() created@endlink and
 *  then @link register_handler() registered@endlink with the main
 *  agent at a given OID in the OID tree and gets called any time a
 *  request is made that it should respond to.  You probably should
 *  use one of the convenience helpers instead of doing anything else
 *  yourself though:
 *
 *  Most importantly, though, is that the handlers are built on the
 *  notion of modularity and reuse.  Specifically, rather than do all
 *  the really hard work (like parsing table indexes out of an
 *  incoming oid request) in each module, the API is designed to make
 *  it easy to write "helper" handlers that merely process some aspect
 *  of the request before passing it along to the final handler that
 *  returns the real answer.  Most people will want to make use of the
 *  @link instance instance@endlink, @link table table@endlink, @link
 *  table_iterator table_iterator@endlink, @link data_table
 *  data_table@endlink, or @link dataset_table dataset_table@endlink
 *  helpers to make their life easier.  These "helpers" interpert
 *  important aspects of the request and pass them on to you.
 *
 *  For instance, the @link table table@endlink helper is designed to
 *  hand you a list of extracted index values from an incoming
 *  request.  THe @link table_iterator table_iterator@endlink helper
 *  is built on top of the table helper, and is designed to help you
 *  iterate through data stored elsewhere (like in a kernel) that is
 *  not in OID lexographical order (ie, don't write your own index/oid
 *  sorting routine, use this helper instead).  The beauty of the
 *  @link table_iterator table_iterator helper@, as well as the @link
 *  instance instance@ helper is that they take care of the complex
 *  GETNEXT processing entirely for you and hand you everything you
 *  need to merely return the data as if it was a GET request.  Much
 *  less code and hair pulling.  I've pulled all my hair out to help
 *  you so that only one of us has to be bald.
 *
 * @{
 */

/** creates a mib_handler structure given a name and a access method.
 *  The returned handler should then be @link register_handler()
 *  registered.@endlink
 *  @see create_handler_registration()
 *  @see register_handler()
 */
mib_handler *
create_handler(const char *name, NodeHandler *handler_access_method) {
    mib_handler *ret = SNMP_MALLOC_TYPEDEF(mib_handler);
    ret->handler_name = strdup(name);
    ret->access_method = handler_access_method;
    return ret;
}

/** creates a handler registration structure given a name, a
 *  access_method function, a registration location oid and the modes
 *  the handler supports. If modes == 0, then modes will automatically
 *  be set to the default value of only HANDLER_CAN_DEFAULT, which is
 *  by default read-only GET and GETNEXT requests.
 *  @note This ends up calling create_handler(name, handler_access_method)
 *  @see create_handler()
 *  @see register_handler()
 */
handler_registration *
create_handler_registration(const char *name,
                            NodeHandler *handler_access_method,
                            oid *reg_oid, size_t reg_oid_len,
                            int modes) {
    handler_registration *the_reg;
    the_reg = SNMP_MALLOC_TYPEDEF(handler_registration);
    if (!the_reg)
        return NULL;

    if (modes)
        the_reg->modes = modes;
    else
        the_reg->modes = HANDLER_CAN_DEFAULT;

    the_reg->handler = create_handler(name, handler_access_method);
    memdup((u_char **) &the_reg->rootoid, (const u_char *) reg_oid,
           reg_oid_len * sizeof(oid));
    the_reg->rootoid_len = reg_oid_len;
    return the_reg;
}

/** register a handler, as defined by the handler_registration pointer. */ 
int
register_handler(handler_registration *reginfo) {
    mib_handler *handler;
    DEBUGIF("handler::register") {
        DEBUGMSGTL(("handler::register", "Registering "));
        for(handler = reginfo->handler; handler;
            handler = handler->next) {
            DEBUGMSG(("handler::register","::%s", handler->handler_name));
        }
            
        DEBUGMSG(("handler::register", " at "));
        if (reginfo->rootoid) {
            DEBUGMSGOID(("handler::register", reginfo->rootoid,
                         reginfo->rootoid_len));
        } else {
            DEBUGMSG(("handler::register", "[null]"));
        }
        DEBUGMSG(("handler::register", "\n"));
    }

    /* don't let them register for absolutely nothing.  Probably a mistake */
    if (0 == reginfo->modes) {
        reginfo->modes = HANDLER_CAN_DEFAULT;
    }

    return register_mib_context2(reginfo->handler->handler_name,
                         NULL, 0, 0,
                         reginfo->rootoid, reginfo->rootoid_len,
                         reginfo->priority,
                         reginfo->range_subid, reginfo->range_ubound,
                         NULL,
                         reginfo->contextName,
                         reginfo->timeout,
                         0, reginfo);
}

/** inject a new handler into the calling chain of the handlers
   definedy by the handler_registration pointer.  The new handler is
   injected at the top of the list and hence will be the new handler
   to be called first.*/ 
int
inject_handler(handler_registration *reginfo, mib_handler *handler) {
    DEBUGMSGTL(("handler:inject", "injecting %s before %s\n", \
                handler->handler_name, reginfo->handler->handler_name));
    handler->next = reginfo->handler;
    if (reginfo->handler)
        reginfo->handler->prev = handler;
    reginfo->handler = handler;
    return SNMPERR_SUCCESS;
}

/** @internal
 *  calls all the handlers for a given mode.
 */
int call_handlers(handler_registration *reginfo,
                  agent_request_info   *reqinfo,
                  request_info         *requests) {
    NodeHandler *nh;
    int status;
    
    if (reginfo == NULL || reqinfo == NULL || requests == NULL) {
        snmp_log(LOG_ERR, "call_handlers() called illegally");
        return  SNMP_ERR_GENERR;
    }

    if (reginfo->handler == NULL) {
        snmp_log(LOG_ERR, "no handler specified.");
        return  SNMP_ERR_GENERR;
    }

    switch(reqinfo->mode) {
        case MODE_GET:
        case MODE_GETNEXT:
            if (!(reginfo->modes & HANDLER_CAN_GETANDGETNEXT))
                return SNMP_ERR_NOERROR; /* legal */
            break;

        case MODE_SET_RESERVE1:
        case MODE_SET_RESERVE2:
        case MODE_SET_ACTION:
        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
        case MODE_SET_UNDO:
            if (!(reginfo->modes & HANDLER_CAN_SET)) {
                for(; requests; requests = requests->next) {
                    set_request_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
                }
                return SNMP_ERR_NOERROR;
            }
            break;

        case MODE_GETBULK:
            if (!(reginfo->modes & HANDLER_CAN_GETBULK))
                return SNMP_ERR_NOERROR; /* XXXWWW: should never get
                                            here after we force a
                                            getbulk->getnext helper on
                                            them during registration
                                            process. */
            break;
            
        default:
            snmp_log(LOG_ERR, "unknown mode in call_handlers! bug!\n");
            return SNMP_ERR_GENERR;
    }
    DEBUGMSGTL(("handler:calling", "calling main handler %s\n",
                 reginfo->handler->handler_name));
    
    nh = reginfo->handler->access_method;
    if (!nh) {
        snmp_log(LOG_ERR, "no handler access method specified.");
        return SNMP_ERR_GENERR;
    }

    /* XXX: define acceptable return statuses */
    status = (*nh)(reginfo->handler, reginfo, reqinfo, requests);

    return status;
}

/** calls a handler with with appropriate NULL checking of arguments, etc. */
inline int call_handler(mib_handler          *next_handler,
                        handler_registration *reginfo,
                        agent_request_info   *reqinfo,
                        request_info         *requests) {
    NodeHandler *nh;
    int ret;
    
    if (next_handler == NULL || reginfo == NULL || reqinfo == NULL ||
        requests == NULL) {
        snmp_log(LOG_ERR, "call_next_handler() called illegally");
        return  SNMP_ERR_GENERR;
    }

    nh = next_handler->access_method;
    if (!nh) {
        snmp_log(LOG_ERR, "no access method specified in handler %s.",
                 next_handler->handler_name);
        return SNMP_ERR_GENERR;
    }

    DEBUGMSGTL(("handler:calling", "calling handler %s\n",
                 next_handler->handler_name));

    ret = (*nh)(next_handler, reginfo, reqinfo, requests);

    DEBUGMSGTL(("handler:returned", "handler %s returned %d\n",
                 next_handler->handler_name, ret));

    return ret;
}

/** calls the next handler in the chain after the current one with
   with appropriate NULL checking, etc. */
inline int call_next_handler(mib_handler          *current,
                             handler_registration *reginfo,
                             agent_request_info   *reqinfo,
                             request_info         *requests) {

    if (current == NULL || reginfo == NULL || reqinfo == NULL ||
        requests == NULL) {
        snmp_log(LOG_ERR, "call_next_handler() called illegally");
        return  SNMP_ERR_GENERR;
    }

    return call_handler(current->next, reginfo, reqinfo, requests);
}

/** creates a cache of information which can be saved for future
   reference.  Use handler_check_cache() later to make sure it's still
   valid before referencing it in the future. */
inline delegated_cache *
create_delegated_cache(mib_handler               *handler,
                       handler_registration      *reginfo,
                       agent_request_info        *reqinfo,
                       request_info              *requests,
                       void                      *localinfo) {
    delegated_cache *ret;

    ret = SNMP_MALLOC_TYPEDEF(delegated_cache);
    if (ret) {
        ret->transaction_id = reqinfo->asp->pdu->transid;
        ret->handler = handler;
        ret->reginfo = reginfo;
        ret->reqinfo = reqinfo;
        ret->requests = requests;
        ret->localinfo = localinfo;
    }
    return ret;
}

/** check's a given cache and returns it if it is still valid (ie, the
   agent still considers it to be an outstanding request.  Returns
   NULL if it's no longer valid. */
inline delegated_cache *
handler_check_cache(delegated_cache *dcache)
{
    if (!dcache)
        return dcache;
    
    if (check_transaction_id(dcache->transaction_id) == SNMPERR_SUCCESS)
        return dcache;

    return NULL;
}

/** marks a list of requests as delegated (or not if isdelegaded = 0) */
void
handler_mark_requests_as_delegated(request_info *requests, int isdelegated) 
{
    while(requests) {
        requests->delegated = isdelegated;
        requests = requests->next;
    }
}

/** add data to a request that can be extracted later by submodules */
inline void
request_add_list_data(request_info *request, data_list *node) 
{
  if (request) {
    if (request->parent_data)
      add_list_data(&request->parent_data, node);
    else
      request->parent_data = node;
  }
}

/** extract data from a request that was added previously by a parent module */
inline void *
request_get_list_data(request_info *request, const char *name)
{
  if (request)
    return get_list_data(request->parent_data,name);
  return NULL;
}

/** Free the extra data stored in a request */
inline void
free_request_data_set(request_info *request)
{
  if (request)
    free_list_data(request->parent_data);
}

/** Free the extra data stored in a bunch of requests (all data in the chain) */
inline void
free_request_data_sets(request_info *request) 
{
  if (request)
    free_all_list_data(request->parent_data);
}

/** Returns a handler from a chain based on the name */
mib_handler *
find_handler_by_name(handler_registration *reginfo, char *name) 
{
    mib_handler *it;
    for(it = reginfo->handler; it; it = it->next) {
        if (strcmp(it->handler_name, name) == 0) {
            return it;
        }
    }
    return NULL;
}

/** Returns a handler's void * pointer from a chain based on the name.
 This probably shouldn't be used by the general public as the void *
 data may change as a handler evolves.  Handlers should really
 advertise some function for you to use instead. */
void *
find_handler_data_by_name(handler_registration *reginfo,
                          char *name) 
{
    mib_handler *it = find_handler_by_name(reginfo, name);
    if (it)
        return it->myvoid;
    return NULL;
}

/** clones a mib handler (it's name and access methods onlys; not myvoid)
 */
mib_handler *
clone_handler(mib_handler *it) 
{
    return create_handler(it->handler_name, it->access_method);
}

static data_list *handler_reg = NULL;

/** registers a given handler by name so that it can be found easily later.
 */
void
register_handler_by_name(const char *name, mib_handler *handler) 
{
    add_list_data(&handler_reg, create_data_list(name, (void *) handler, NULL));
    DEBUGMSGTL(("handler_registry", "registering helper %s\n", name));
}

/** @internal
 *  injects a handler into a subtree, peers and children when a given
 *  subtrees name matches a passed in name.
 */
void
inject_handler_into_subtree(struct subtree *tp, const char *name,
                            mib_handler *handler) 
{
    struct subtree *tptr;
    mib_handler *mh;
    
    for(tptr = tp; tptr; tptr = tptr->next) {
/*         if (tptr->children) { */
/*             inject_handler_into_subtree(tptr->children, name, handler); */
/*         } */
        if (strcmp(tptr->label, name) == 0) {
            DEBUGMSGTL(("injectHandler", "injecting handler %s into %s\n",
                        handler->handler_name,
                        tptr->label));
            inject_handler(tptr->reginfo, clone_handler(handler));
        } else if (tptr->reginfo &&
                   tptr->reginfo->handlerName &&
                   strcmp(tptr->reginfo->handlerName, name) == 0) {
            DEBUGMSGTL(("injectHandler", "injecting handler into %s/%s\n",
                        tptr->label, tptr->reginfo->handlerName));
            inject_handler(tptr->reginfo, clone_handler(handler));
        } else {
            for(mh = tptr->reginfo->handler; mh; mh = mh->next) {
                if (strcmp(mh->handler_name, name) == 0) {
                    DEBUGMSGTL(("injectHandler", "injecting handler into %s\n",
                                tptr->label));
                    inject_handler(tptr->reginfo, clone_handler(handler));
                    break;
                } else {
                    DEBUGMSGTL(("yyyinjectHandler", "not injecting handler into %s\n",
                                mh->handler_name));
                }
            }
        }
    }
}

static int doneit = 0;
/** @internal
 *  parses the "injectHandler" token line.
 */
void
parse_injectHandler_conf(const char *token, char *cptr) 
{
    char handler_to_insert[256];
    subtree_context_cache *stc;
    mib_handler *handler;
    
    /* XXXWWW: ensure instead that handler isn't inserted twice */
    if (doneit) /* we only do this once without restart the agent */
        return;

    cptr = copy_nword(cptr, handler_to_insert, sizeof(handler_to_insert));
    handler = get_list_data(handler_reg, handler_to_insert);
    if (!handler) {
        config_perror("no such \"%s\" handler registered.");
        return;
    }
    
    if (!cptr) {
        config_perror("no INTONAME specified.  Can't do insertion.");
        return;
    }
    for(stc = get_top_context_cache(); stc; stc = stc->next) {
        DEBUGMSGTL(("injectHandler", "Checking context tree %s\n",
                    stc->context_name));
        inject_handler_into_subtree(stc->first_subtree, cptr, handler);
    }
}

/** @internal
 *  callback to ensure injectHandler parser doesn't do things twice
 *  @todo replace this with a method to check the handler chain instead.
 */
static int
handler_mark_doneit(int majorID, int minorID,
                    void *serverarg, void *clientarg) {
    doneit = 1;
    return 0;
}

/** @internal
 *  register's the injectHandle parser token.
 */
void
init_handler_conf(void) 
{
    snmpd_register_config_handler("injectHandler",
                                  parse_injectHandler_conf,
                                  NULL,
                                  "injectHandler NAME INTONAME");
    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
                           SNMP_CALLBACK_POST_READ_CONFIG,
                           handler_mark_doneit, NULL);
}

/** @} */
