/*
 * snmpMPDStats.c: tallies errors for SNMPv3 message processing.
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/sysORTable.h>

#include "snmpMPDStats_5_5.h"

#define snmpMPDMIBObjects 1, 3, 6, 1, 6, 3, 11, 2
#define snmpMPDMIBCompliances snmpMPDMIBObjects, 3, 1

static oid snmpMPDStats[] = { snmpMPDMIBObjects, 1 };

static int
handle_snmpMPDStats(netsnmp_mib_handler *handler,
                    netsnmp_handler_registration *reginfo,
                    netsnmp_agent_request_info *reqinfo,
                    netsnmp_request_info *requests)
{
    if (reqinfo->mode == MODE_GET) {
        const oid idx = requests->requestvb->name[OID_LENGTH(snmpMPDStats)] - 1;
        const uint32_t value = snmp_get_statistic(idx + STAT_MPD_STATS_START);
        snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER,
                                 (const u_char*)&value, sizeof(value));
        return SNMP_ERR_NOERROR;
    }
    return SNMP_ERR_GENERR;
}

static netsnmp_handler_registration* snmpMPDStats_reg = NULL;
static oid snmpMPDCompliance[] = { snmpMPDMIBCompliances, 1 };

void
init_snmpMPDStats_5_5(void)
{
    netsnmp_handler_registration* s =
        netsnmp_create_handler_registration(
            "snmpMPDStats", handle_snmpMPDStats,
            snmpMPDStats, OID_LENGTH(snmpMPDStats),
            HANDLER_CAN_RONLY);
    if (s && netsnmp_register_scalar_group(s, 1, 3) == MIB_REGISTERED_OK) {
        REGISTER_SYSOR_ENTRY(snmpMPDCompliance,
                             "The MIB for Message Processing and Dispatching.");
        snmpMPDStats_reg = s;
    }
}

void
shutdown_snmpMPDStats_5_5(void)
{
    UNREGISTER_SYSOR_ENTRY(snmpMPDCompliance);
    if (snmpMPDStats_reg) {
        netsnmp_unregister_handler(snmpMPDStats_reg);
        snmpMPDStats_reg = NULL;
    }
}
