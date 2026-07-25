#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "entity.h"

static int
_lct_handler(netsnmp_mib_handler *handler,
             netsnmp_handler_registration *reginfo,
             netsnmp_agent_request_info *reqinfo,
             netsnmp_request_info *requests)
{
    netsnmp_cache_check_and_reload(netsnmp_entity_get_cache());
    snmp_set_var_typed_value(requests->requestvb, ASN_TIMETICKS,
                             (u_char *)&entity_last_change,
                             sizeof(entity_last_change));
    return SNMP_ERR_NOERROR;
}

void init_entLastChangeTime(void)
{
    static oid oid_lct[] = { 1,3,6,1,2,1,47,1,4,1,0 };

    netsnmp_register_read_only_instance(
        netsnmp_create_handler_registration(
            "entLastChangeTime", _lct_handler,
            oid_lct, OID_LENGTH(oid_lct),
            HANDLER_CAN_RONLY));
}
