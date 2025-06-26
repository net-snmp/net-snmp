/*
 * Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 *
 * Portions of this file are copyrighted by:
 * Copyright (c) 2016 VMware, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/serialize.h>

/** @defgroup serialize serialize
 *  Calls sub handlers one request at a time.
 *  @ingroup utilities
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
netsnmp_mib_handler *
netsnmp_get_serialize_handler(void)
{
    return netsnmp_create_handler("serialize",
                                  netsnmp_serialize_helper_handler);
}

/** functionally the same as calling netsnmp_register_handler() but also
 * injects a serialize handler at the same time for you. */
int
netsnmp_register_serialize(netsnmp_handler_registration *reginfo)
{
    netsnmp_mib_handler *handler = netsnmp_get_serialize_handler();
    if (!handler ||
        (netsnmp_inject_handler(reginfo, handler) != SNMPERR_SUCCESS)) {
        snmp_log(LOG_ERR, "could not create serialize handler\n");
        netsnmp_handler_free(handler);
        netsnmp_handler_registration_free(reginfo);
        return MIB_REGISTRATION_FAILED;
    }

    return netsnmp_register_handler(reginfo);
}

/** Implements the serial handler */
int
netsnmp_serialize_helper_handler(netsnmp_mib_handler *handler,
                                 netsnmp_handler_registration *reginfo,
                                 netsnmp_agent_request_info *reqinfo,
                                 netsnmp_request_info *requests)
{

    netsnmp_request_info *request, *requesttmp;

    DEBUGMSGTL(("helper:serialize", "Got request\n"));
    /*
     * loop through requests 
     */
    for (request = requests; request; request = request->next) {
        int             ret;

        /*
         * store next pointer and delete it 
         */
        requesttmp = request->next;
        request->next = NULL;

        /*
         * call the next handler 
         */
        ret =
            netsnmp_call_next_handler(handler, reginfo, reqinfo, request);

        /*
         * restore original next pointer 
         */
        request->next = requesttmp;

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
netsnmp_init_serialize(void)
{
    netsnmp_mib_handler *handler = netsnmp_get_serialize_handler();
    if (!handler) {
        snmp_log(LOG_ERR, "could not create serialize handler\n");
        return;
    }
    netsnmp_register_handler_by_name("serialize", handler);
}
/**  @} */

