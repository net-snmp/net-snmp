/*
 * snmptrapd_auth.c - authorize notifications for further processing
 *
 */
#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>
#include "snmptrapd_handlers.h"
#include "snmptrapd_auth.h"

/**
 * initializes the snmptrapd authorization code registering needed
 * handlers and config parsers.
 */
void
init_netsnmp_trapd_auth(void)
{
    netsnmp_trapd_handler *traph;
    traph = netsnmp_add_global_traphandler(NETSNMPTRAPD_AUTH_HANDLER,
                                           netsnmp_trapd_auth);
}


/**
 * authorizes incoming notifications for further processing
 */
int
netsnmp_trapd_auth(netsnmp_pdu           *pdu,
                   netsnmp_transport     *transport,
                   netsnmp_trapd_handler *handler)
{

    /* No policy was met, so we drop the PDU from further processing */
    DEBUGMSGTL(("snmptrapd:auth", "Dropping unauthorized message\n"));
    return NETSNMPTRAPD_HANDLER_FINISH;
}
