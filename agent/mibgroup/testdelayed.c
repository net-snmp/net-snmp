#include <net-snmp/net-snmp-config.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <unistd.h>

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "testdelayed.h"

#include <net-snmp/agent/table.h>
#include <net-snmp/agent/instance.h>
#include <net-snmp/agent/serialize.h>

static oid my_delayed_oid[5] = {1,2,3,99,1};

static u_long accesses = 0;

void
init_testdelayed(void) {
    /*
     * delayed handler test
     */
    netsnmp_handler_registration *my_test;
    my_test = SNMP_MALLOC_TYPEDEF(netsnmp_handler_registration);
    if (!my_test)
        return;

    my_test->modes = HANDLER_CAN_RWRITE;
    my_test->rootoid = my_delayed_oid;
    my_test->rootoid_len = 4; /* [sic] */
    my_test->handler = netsnmp_create_handler("myDelayed", my_test_delayed_handler);

    register_serialize(my_test);

}

#define TESTDELAYED_SET_NAME "test_delayed"
u_long sleeptime = 1;

void
return_delayed_response(unsigned int clientreg, void *clientarg) {
    netsnmp_delegated_cache *cache = (netsnmp_delegated_cache *) clientarg;
    int cmp;
    netsnmp_request_info              *requests;
    netsnmp_agent_request_info        *reqinfo;
    u_long *sleeptime_cache = NULL;

    cache = netsnmp_handler_check_cache(cache);
    
    if (!cache) {
        snmp_log(LOG_ERR,"illegal call to return delayed response\n");
        return;
    }

    reqinfo = cache->reqinfo;
    requests = cache->requests;

    DEBUGMSGTL(("testdelayed", "continuing delayed request, mode = %d\n",
                cache->reqinfo->mode));
    
    requests->delegated = 0; /* mark it as completed, because it will be */
    switch(cache->reqinfo->mode) {
        case MODE_GET:
            if (requests->requestvb->name_length == 5 &&
                snmp_oid_compare(requests->requestvb->name, 4,
                                 my_delayed_oid, 4) == 0 &&
                requests->requestvb->name[4] < 5) {
                snmp_set_var_typed_value(cache->requests->requestvb,
                                         ASN_INTEGER,
                                         (u_char *) &accesses,
                                         sizeof(accesses));
            } else {
                requests->requestvb->type = SNMP_NOSUCHOBJECT;
            }
            break;
            
        case MODE_GETNEXT:
            cmp = snmp_oid_compare(requests->requestvb->name, 4,
                                   my_delayed_oid, 4);
            if (cmp == 0) {
                if (requests->requestvb->name_length < 5) {
                    snmp_set_var_objid(requests->requestvb,
                                       my_delayed_oid, 5); /* [sic] */
                    requests->requestvb->name[4] = 1;
                    snmp_set_var_typed_value(requests->requestvb,
                                             ASN_INTEGER,
                                             (u_char *) &accesses,
                                             sizeof(accesses));
                } else {
                    if (requests->requestvb->name[4] < 5) {
                        requests->requestvb->name[4]++;
                        requests->requestvb->name_length = 5;
                        snmp_set_var_typed_value(requests->requestvb,
                                                 ASN_INTEGER,
                                                 (u_char *) &accesses,
                                                 sizeof(accesses));
                    } else {
                        requests->requestvb->type = ASN_NULL;
                    }
                }
            } else if (cmp < 0) {
                    snmp_set_var_objid(requests->requestvb,
                                       my_delayed_oid, 5);
                    requests->requestvb->name[4] = 1;
                    snmp_set_var_typed_value(requests->requestvb,
                                             ASN_INTEGER,
                                             (u_char *) &accesses,
                                             sizeof(accesses));
            } else {
                requests->requestvb->type = ASN_NULL;
            }
            break;

        case MODE_SET_RESERVE1:
            /* check type */
            if (requests->requestvb->type != ASN_INTEGER) {
                netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_WRONGTYPE);
                netsnmp_free_delegated_cache(cache);
                return;
            }
            break;

        case MODE_SET_RESERVE2:
            /* store old info for undo later */
            memdup((u_char **) &sleeptime_cache,
                   (u_char *) &accesses, sizeof(accesses));
            if (sleeptime_cache == NULL) {
                netsnmp_set_request_error(reqinfo, requests,
                                  SNMP_ERR_RESOURCEUNAVAILABLE);
                netsnmp_free_delegated_cache(cache);
                return;
            }
            netsnmp_request_netsnmp_add_list_data(requests,
                                  netsnmp_create_netsnmp_data_list(TESTDELAYED_SET_NAME,
                                                   sleeptime_cache, free));
            break;

        case MODE_SET_ACTION:
            /* update current */
            sleeptime = *(requests->requestvb->val.integer);
            DEBUGMSGTL(("testhandler","updated accesses -> %d\n", accesses));
            break;
            
        case MODE_SET_UNDO:
            sleeptime =
                *((u_long *) netsnmp_request_netsnmp_get_list_data(requests,
                                                   TESTDELAYED_SET_NAME));
            break;
            
        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
            break;
    }
    netsnmp_free_delegated_cache(cache);
    accesses++;
}

int
my_test_delayed_handler(
    netsnmp_mib_handler               *handler,
    netsnmp_handler_registration      *reginfo,
    netsnmp_agent_request_info        *reqinfo,
    netsnmp_request_info              *requests) {

    DEBUGMSGTL(("testdelayed", "Got request, mode = %d:\n", reqinfo->mode));

    switch(reqinfo->mode) {
        default:
            /* mark this variable as something that can't be handled now */
            requests->delegated = 1;
            /* register an alarm to update the results at a later time */
            snmp_alarm_register(sleeptime, 0, return_delayed_response,
                                (void *)
                                netsnmp_create_delegated_cache(handler, reginfo,
                                                       reqinfo, requests,
                                                       NULL));
            break;

    }

    return SNMP_ERR_NOERROR;
}
