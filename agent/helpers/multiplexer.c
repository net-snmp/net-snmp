#include <config.h>

#include <sys/types.h>

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "agent_registry.h"
#include "multiplexer.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/** @defgroup multiplexer multiplexer: splits mode requests into calls to different handlers.
 *  @ingroup handler
 * The multiplexer helper lets you split the calling chain depending
 * on the calling mode (get vs getnext vs set).  Useful if you want
 * different routines to handle different aspects of SNMP requests,
 * which is very common for GET vs SET type actions.
 *
 * Functionally:
 *
 * -# GET requests call the get_method
 * -# GETNEXT requests call the getnext_method, or if not present, the
 *    get_method.
 * -# GETBULK requests call the getbulk_method, or if not present, the
 *    getnext_method, or if even that isn't present the get_method.
 * -# SET requests call the set_method, or if not present return a
 *    SNMP_ERR_NOTWRITABLE error.
 *  @{
 */

/** returns a multiplixer handler given a mib_handler_methods structure of subhandlers.
 */
mib_handler *
get_multiplexer_handler(mib_handler_methods *req) {
    mib_handler *ret = NULL;
    
    if (!req) {
        snmp_log(LOG_INFO, "get_multiplexer_handler(NULL) called\n");
        return NULL;
    }
    
    ret = create_handler("multiplexer", multiplexer_helper_handler);
    if (ret) {
        ret->myvoid = (void *) req;
    }
    return ret;
}

/** implements the multiplexer helper */
int
multiplexer_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    mib_handler_methods *methods;
    
    if (!handler->myvoid) {
        snmp_log(LOG_INFO, "improperly registered multiplexer found\n");
        return SNMP_ERR_GENERR;
    }

    methods = (mib_handler_methods *) handler->myvoid;

    switch(reqinfo->mode) {
        case MODE_GET:
            handler = methods->get_handler;
            if (!handler) {
                set_all_requests_error(reqinfo, requests, SNMP_NOSUCHOBJECT);
            }
            break;

        case MODE_GETNEXT:
            handler = methods->getnext_handler;
            if (!handler) /* fallback to get handler */
                handler = methods->get_handler;
            break;

        case MODE_GETBULK:
            /* XXX: this needs to do better getbulk -> getnext
               handling (probably via a separate helper) */
            handler = methods->getbulk_handler;
            if (!handler) /* fallback to getnext handler */
                handler = methods->getnext_handler;
            if (!handler) /* fallback to getnext handler */
                handler = methods->get_handler;
            break;

        case MODE_SET_RESERVE1:
        case MODE_SET_RESERVE2:
        case MODE_SET_ACTION:
        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
        case MODE_SET_UNDO:
            handler = methods->set_handler;
            if (!handler) {
                set_all_requests_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
                return SNMP_ERR_NOERROR;
            }
            break;
            
        /* XXX: process SETs specially, and possibly others */
        default:
            snmp_log(LOG_ERR, "unsupported mode for multiplexer: %d\n",
                     reqinfo->mode);
            return SNMP_ERR_GENERR;
    }
    if (!handler) {
        snmp_log(LOG_ERR, "No handler enabled for mode %d in multiplexer\n",
                 reqinfo->mode);
        return SNMP_ERR_GENERR;
    }
    return call_handler(handler, reginfo, reqinfo, requests);
}
