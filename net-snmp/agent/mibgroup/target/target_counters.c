#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "target_counters.h"
#include "snmp_agent.h"

#include "snmp_api.h"
#include "snmp_client.h"
#include "helpers/instance.h"

static oid unavailable_context_oid[] = {1,3,6,1,6,3,12,1,4,0};
static oid unknown_context_oid[]     = {1,3,6,1,6,3,12,1,5,0};

void
init_target_counters(void) {
    DEBUGMSGTL(("target_counters", "initializing\n"));

    /*
     * unknown contexts
     */

    register_read_only_instance(
        create_handler_registration("myInstance",
                                    get_unknown_context_count,
                                    unknown_context_oid,
                                    sizeof(unknown_context_oid)/sizeof(oid),
				    HANDLER_CAN_RONLY));

    /*
     * unavailable available
     */

    register_read_only_instance(
        create_handler_registration("myInstance",
                                    get_unavailable_context_count,
                                    unavailable_context_oid,
                                    sizeof(unavailable_context_oid) /
                                    sizeof(oid),
				    HANDLER_CAN_RONLY));

}

int
get_unknown_context_count(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {
    /* we're only called for GETs of the right node, so this is easy: */

    u_long long_ret = snmp_get_statistic(STAT_SNMPUNKNOWNCONTEXTS);
    snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER,
                             (u_char *) &long_ret,
                             sizeof(long_ret));
    return SNMP_ERR_NOERROR;
}


int
get_unavailable_context_count(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {
    /* we're only called for GETs of the right node, so this is easy: */

    u_long long_ret = snmp_get_statistic(STAT_SNMPUNAVAILABLECONTEXTS);
    snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER,
                             (u_char *) &long_ret,
                             sizeof(long_ret));
    return SNMP_ERR_NOERROR;
}

