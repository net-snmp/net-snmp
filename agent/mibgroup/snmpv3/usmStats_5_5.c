/*
 * usmStats.c: implements the usmStats portion of the SNMP-USER-BASED-SM-MIB
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/sysORTable.h>

#include "usmStats_5_5.h"

#define snmpUsmMIB 1, 3, 6, 1, 6, 3, 15
#define usmMIBCompliances snmpUsmMIB, 2, 1

static oid usmStats[] = { snmpUsmMIB, 1, 1 };

static int
handle_usmStats(netsnmp_mib_handler *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests)
{
    if (reqinfo->mode == MODE_GET) {
        const oid idx = requests->requestvb->name[OID_LENGTH(usmStats)] - 1;
        const uint32_t value = snmp_get_statistic(idx + STAT_USM_STATS_START);
        snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER,
                                 (const u_char*)&value, sizeof(value));
        return SNMP_ERR_NOERROR;
    }
    return SNMP_ERR_GENERR;
}

static netsnmp_handler_registration* usmStats_reg = NULL;
static oid usmMIBCompliance[] = { usmMIBCompliances, 1 };

void
init_usmStats_5_5(void)
{
    netsnmp_handler_registration* s =
        netsnmp_create_handler_registration(
            "usmStats", handle_usmStats, usmStats, OID_LENGTH(usmStats),
            HANDLER_CAN_RONLY);
    if (s && netsnmp_register_scalar_group(s, 1, 6) == MIB_REGISTERED_OK) {
        REGISTER_SYSOR_ENTRY(usmMIBCompliance,
                             "The MIB for Message Processing and Dispatching.");
        usmStats_reg = s;
    }
}

void
shutdown_usmStats_5_5(void)
{
    UNREGISTER_SYSOR_ENTRY(usmMIBCompliance);
    if (usmStats_reg) {
        netsnmp_unregister_handler(usmStats_reg);
        usmStats_reg = NULL;
    }
}
