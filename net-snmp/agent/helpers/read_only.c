#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "read_only.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/** @defgroup read_only read_only: make your handler read_only automatically 
 *  The only purpose of this handler is to return an
 *  appropriate error for any requests passed to it in a SET mode.
 *  Inserting it into your handler chain will ensure you're never
 *  asked to perform a SET request so you can ignore those error
 *  conditions.
 *  @ingroup handler
 *  @{
 */

/** returns a read_only handler that can be injected into a given
 *  handler chain.
 */
mib_handler *
get_read_only_handler(void) {
    return create_handler("read_only", read_only_helper);
}

/** @internal Implements the read_only handler */
int
read_only_helper(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    DEBUGMSGTL(("helper:read_only", "Got request\n"));

    switch(reqinfo->mode) {
        
        case MODE_SET_RESERVE1:
        case MODE_SET_RESERVE2:
        case MODE_SET_ACTION:
        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
        case MODE_SET_UNDO:
            set_all_requests_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
            return SNMP_ERR_NOERROR;
            
        default:
            return call_next_handler(handler, reginfo, reqinfo, requests);
    }
    return SNMP_ERR_GENERR; /* should never get here */
}

/** initializes the read_only helper which then registers a read_only
 *  handler as a run-time injectable handler for configuration file
 *  use.
 */
void
init_read_only_helper(void) 
{
    register_handler_by_name("read_only", get_read_only_handler());
}
