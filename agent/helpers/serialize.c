#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "serialize.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/** @defgroup serialize serialize: Calls sub handlers one request at a time.
 *  @ingroup handler
 *  This functionally passes in one request at a time
 *  into lower handlers rather than a whole bunch of requests at once.
 *  This is useful for handlers that don't want to iterate through the
 *  request lists themselves.  Generally, this is probably less
 *  efficient so use with caution.  The serialize handler might be
 *  useable to dynamically fix handlers with broken looping code,
 *  however.
 *  @{
 */

/** returns a serialize handler that can be injected into a given
 *  handler chain.  
 */
mib_handler *
get_serialize_handler(void) {
    return create_handler("serialize", serialize_helper_handler);
}

/** functionally the same as calling register_handler() but also
 * injects a serialize handler at the same time for you. */
int
register_serialize(handler_registration *reginfo) {
    inject_handler(reginfo, get_serialize_handler());
    return register_handler(reginfo);
}

/** Implements the serial handler */
int
serialize_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    request_info              *request;

    DEBUGMSGTL(("helper:serialize", "Got request\n"));
    /* loop through requests */
    for(request = requests; request; request = request->next) {
        int ret;
        
        ret = call_next_handler(handler, reginfo, reqinfo, requests);
        if (ret != SNMP_ERR_NOERROR)
            return ret;
    }

    return SNMP_ERR_NOERROR;
}

/** 
 *  initializes the serialize helper which then registers a serialize
 *  handler as a run-time injectable handler for configuration file
 *  use.
 */
void
init_serialize(void) 
{
    register_handler_by_name("serialize", get_serialize_handler());
}
