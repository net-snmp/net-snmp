#include <net-snmp/net-snmp-config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/debug_handler.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/** @defgroup debug debug: print out debugging information about the handler chain being called.
 *  This is a useful module for run-time
 *  debugging of requests as the pass this handler in a calling chain.
 *  All debugging output is done via the standard debugging routines
 *  with a token name of "helper:debug", so use the -Dhelper:debug
 *  command line flag to see the output when running the snmpd
 *  demon. It's not recommended you compile this into a handler chain
 *  during compile time, but instead use the "injectHandler" token in
 *  the snmpd.conf file (or similar) to add it to the chain later:
 *
 *     injectHandler debug my_module_name
 *
 *  to see an example output, try:
 *
 *     injectHandler debug mibII/system
 *
 *  and then run snmpwalk on the "system" group.
 *
 *  @ingroup handler
 *  @{
 */

/** returns a debug handler that can be injected into a given
 *  handler chain.
 */
mib_handler *
get_debug_handler(void) {
    return create_handler("debug", debug_helper);
}

/** @internal debug print variables in a chain */
void
debug_print_requests(request_info              *requests) 
{
    size_t buf_len = 256;
    size_t out_len = 0;
    u_char *buf = malloc(buf_len);
    request_info              *request;
    
    if (buf == NULL) {
	DEBUGMSGTL(("helper:debug",
		    "malloc() failure in debug_print_requests()\n"));
	return;
    }

    for (request = requests; request; request = request->next) {
        out_len = 0;
        sprint_realloc_variable(&buf, &buf_len, &out_len, 1,
                                request->requestvb->name,
                                request->requestvb->name_length,
                                request->requestvb);
        DEBUGMSGTL(("helper:debug", "      #%2d: %s\n", request->index, buf));
        if (request->processed)
            DEBUGMSGTL(("helper:debug", "        [processed]\n"));
        if (request->processed)
            DEBUGMSGTL(("helper:debug", "        [delegated]\n"));
        if (request->status)
            DEBUGMSGTL(("helper:debug", "        [status = %d]\n",
                        request->status));
        if (request->parent_data) {
            data_list *lst;
            DEBUGMSGTL(("helper:debug", "        [parent data ="));
            for(lst = request->parent_data; lst; lst = lst->next) {
                DEBUGMSG(("helper:debug", " %s", lst->name));
            }
            DEBUGMSG(("helper:debug", "]\n"));
        }
    }
    free(buf);
}


/** @internal Implements the debug handler */
int
debug_helper(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    mib_handler               *hptr;
    int i, ret, count;
    
    DEBUGMSGTL(("helper:debug", "Entering Debugging Helper:\n"));
    DEBUGMSGTL(("helper:debug", "  Handler Registration Info:\n"));
    DEBUGMSGTL(("helper:debug", "    Name:        %s\n",
                reginfo->handlerName));
    DEBUGMSGTL(("helper:debug", "    Context:     %s\n",
                reginfo->contextName));
    DEBUGMSGTL(("helper:debug", "    Base OID:    "));
    DEBUGMSGOID(("helper:debug", reginfo->rootoid, reginfo->rootoid_len));
    DEBUGMSG(("helper:debug", "\n"));

    DEBUGMSGTL(("helper:debug", "    Modes:       0x%x = ", reginfo->modes));
    for(count = 0, i = reginfo->modes; i ; i = i >> 1, count++) {
        if (i & 0x01) {
            DEBUGMSG(("helper:debug", "%s | ",
                      se_find_label_in_slist("handler_can_mode",
                                             0x01 << count)));
        }
    }
    DEBUGMSG(("helper:debug", "\n"));
            
    DEBUGMSGTL(("helper:debug", "    Priority:    %d\n", reginfo->priority));

    DEBUGMSGTL(("helper:debug", "  Handler Calling Chain:\n"));
    DEBUGMSGTL(("helper:debug", "   "));
    for(hptr = reginfo->handler; hptr; hptr = hptr->next) {
        DEBUGMSG(("helper:debug", " -> %s", hptr->handler_name));
        if (hptr->myvoid)
            DEBUGMSG(("helper:debug", " [myvoid = %x]", hptr->myvoid));
    }
    DEBUGMSG(("helper:debug", "\n"));

    DEBUGMSGTL(("helper:debug", "  Request information:\n"));
    DEBUGMSGTL(("helper:debug", "    Mode:        %s (%d = 0x%x)\n", 
                se_find_label_in_slist("agent_mode", reqinfo->mode),
                reqinfo->mode, reqinfo->mode));
    DEBUGMSGTL(("helper:debug", "    Request Variables:\n"));
    debug_print_requests(requests);
        
    DEBUGMSGTL(("helper:debug", "  --- calling next handler --- \n"));
    ret = call_next_handler(handler, reginfo, reqinfo, requests);
    
    DEBUGMSGTL(("helper:debug", "  Results:\n"));
    DEBUGMSGTL(("helper:debug", "    Returned code: %d\n", ret));
    DEBUGMSGTL(("helper:debug", "    Returned Variables:\n"));
    debug_print_requests(requests);

    DEBUGMSGTL(("helper:debug", "Exiting Debugging Helper:\n"));
    return ret;
}

/** initializes the debug helper which then registers a debug
 *  handler as a run-time injectable handler for configuration file
 *  use.
 */
void
init_debug_helper(void) 
{
    register_handler_by_name("debug", get_debug_handler());
}
