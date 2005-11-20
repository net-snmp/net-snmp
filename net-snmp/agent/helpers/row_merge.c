#include <net-snmp/net-snmp-config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/row_merge.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/** @defgroup row_merge row_merge: Calls sub handlers with request for one row at a time.
 *  @ingroup utilities
 *  This helper splits a whole bunch of requests into chunks based on the row
 *  index that they refer to, and passes all requests for a given row to the lower handlers.
 *  This is useful for handlers that don't want to process multiple rows at the
 *  same time, but are happy to iterate through the request list for a single row.
 *  @{
 */

/** returns a row_merge handler that can be injected into a given
 *  handler chain.  
 */
netsnmp_mib_handler *
netsnmp_get_row_merge_handler(int prefix_len)
{
    netsnmp_mib_handler *ret = NULL;
    ret = netsnmp_create_handler("row_merge",
                                  netsnmp_row_merge_helper_handler);
    if (ret) {
        ret->myvoid = (void *) prefix_len;
    }
    return ret;
}

/** functionally the same as calling netsnmp_register_handler() but also
 * injects a row_merge handler at the same time for you. */
int
netsnmp_register_row_merge(netsnmp_handler_registration *reginfo)
{
    netsnmp_inject_handler(reginfo,
		    netsnmp_get_row_merge_handler(reginfo->rootoid_len+1));
    return netsnmp_register_handler(reginfo);
}

#define ROW_MERGE_WAITING 0
#define ROW_MERGE_ACTIVE  1
#define ROW_MERGE_DONE    2

/** Implements the row_merge handler */
int
netsnmp_row_merge_helper_handler(netsnmp_mib_handler *handler,
                                 netsnmp_handler_registration *reginfo,
                                 netsnmp_agent_request_info *reqinfo,
                                 netsnmp_request_info *requests)
{
    netsnmp_request_info *request, **saved_requests;
    char *saved_status;
    int i, j, ret, tail, count = 0;

    /*
     * xxx-rks - for sets, should store this info in agent request info, so it
     *           doesn't need to be done for every mode.
     *
     * Use the prefix length as supplied during registration, rather
     *  than trying to second-guess what the MIB implementer wanted.
     */
    int SKIP_OID = (int)handler->myvoid;

    DEBUGMSGTL(("helper:row_merge", "Got request (%d)\n", SKIP_OID));
    DEBUGMSGOID(("helper:row_merge", reginfo->rootoid, reginfo->rootoid_len));
    DEBUGMSG(("helper:row_merge", "\n"));

    /*
     * Count the requests, and set up an array to keep
     *  track of the original order.
     */
    for (request = requests; request; request = request->next) 
	count++;

    /*
     * Optimization: skip all this if there is just one request
     */
    if(count == 1) {
        DEBUGMSGTL(("helper:row_merge", "  only one varbind\n"));
        return netsnmp_call_next_handler(handler, reginfo, reqinfo, requests);
    }

    /*
     * allocate memory for saved structure
     */
    saved_requests = (netsnmp_request_info**)calloc(count+1, sizeof(netsnmp_request_info*));
    saved_status   =                  (char*)calloc(count,   sizeof(char));

    /*
     * set up saved requests, and set any processed requests to done
     */
    i = 0;
    for (request = requests; request; request = request->next, i++) {
        if (request->processed) {
            saved_status[i] = ROW_MERGE_DONE;
            DEBUGMSGTL(("helper:row_merge", "  skipping processed oid: "));
            DEBUGMSGOID(("helper:row_merge", request->requestvb->name,
                         request->requestvb->name_length));
            DEBUGMSG(("helper:row_merge", "\n"));
        }
        saved_requests[i] = request;
    }

    /*
     * Note that saved_requests[count] is valid
     *    (because of the 'count+1' in the calloc above),
     * but NULL (since it's past the end of the list).
     * This simplifies the re-linking later.
     */

    /*
     * Work through the (unprocessed) requests in order.
     * For each of these, search the rest of the list for any
     *   matching indexes, and link them into a new list.
     */
    for (i=0; i<count; i++) {
	if (saved_status[i] != ROW_MERGE_WAITING) {
	    /*
	     * Already processed, so just re-link into the original list
	     */
	    saved_requests[i]->next = saved_requests[i+1];
	    continue;
	}

        DEBUGMSGTL(("helper:row_merge", "  oid[%d]: ", i));
        DEBUGMSGOID(("helper:row_merge", saved_requests[i]->requestvb->name, saved_requests[i]->requestvb->name_length));
        DEBUGMSG(("helper:row_merge", "\n"));

	saved_requests[i]->next = NULL;
	saved_status[i] = ROW_MERGE_ACTIVE;
	tail = i;
        for (j=i+1; j<count; j++) {
	    if (saved_status[j] != ROW_MERGE_WAITING) {
	        continue;
	    }
            DEBUGMSGTL(("helper:row_merge", "? oid[%d]: ", j));
            DEBUGMSGOID(("helper:row_merge", saved_requests[j]->requestvb->name, saved_requests[j]->requestvb->name_length));
            DEBUGMSG(("helper:row_merge", "\n"));
            if (!snmp_oid_compare(
                    saved_requests[i]->requestvb->name+SKIP_OID,
                    saved_requests[i]->requestvb->name_length-SKIP_OID,
                    saved_requests[j]->requestvb->name+SKIP_OID,
                    saved_requests[j]->requestvb->name_length-SKIP_OID)) {
                DEBUGMSGTL(("helper:row_merge", "merged\n"));
                saved_requests[tail]->next = saved_requests[j];
                saved_requests[j]->next    = NULL;
	        saved_status[j] = ROW_MERGE_ACTIVE;
	        tail = j;
            }
        }

        /*
         * call the next handler with this list, and 
         * restore the original next pointer 
         */
        ret = netsnmp_call_next_handler(handler, reginfo, reqinfo,
			                saved_requests[i]);
	saved_requests[i]->next = saved_requests[i+1];

        if (ret != SNMP_ERR_NOERROR) {
	    /* 
	     * Something went wrong.
	     * Re-link the rest of the original list,
	     *   clean up, and report back.
	     */
            for (j=0; j<count; j++)
	        saved_requests[j]->next = saved_requests[j+1];
	    free(saved_requests);
	    free(saved_status);
            return ret;
	}
    }

    free(saved_requests);
    free(saved_status);
    return SNMP_ERR_NOERROR;
}

/** 
 *  initializes the row_merge helper which then registers a row_merge
 *  handler as a run-time injectable handler for configuration file
 *  use.
 */
void
netsnmp_init_row_merge(void)
{
    netsnmp_register_handler_by_name("row_merge",
                                     netsnmp_get_row_merge_handler(-1));
}
