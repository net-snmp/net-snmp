#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "snmp_get_statistic.h"

static int
netsnmp_get_statistic_helper_handler(netsnmp_mib_handler *handler,
                                     netsnmp_handler_registration *reginfo,
                                     netsnmp_agent_request_info *reqinfo,
                                     netsnmp_request_info *requests)
{
    if (reqinfo->mode == MODE_GET) {
        const oid idx = requests->requestvb->name[reginfo->rootoid_len - 2] +
            (((char*)handler->myvoid) - ((char*)0));
        const uint32_t value = snmp_get_statistic(idx);
        snmp_set_var_typed_value(requests->requestvb, ASN_COUNTER,
                                 (const u_char*)&value, sizeof(value));
        return SNMP_ERR_NOERROR;
    }
    return SNMP_ERR_GENERR;
}

static netsnmp_mib_handler *
netsnmp_get_statistic_handler(int offset)
{
    netsnmp_mib_handler *ret =
        netsnmp_create_handler("get_statistic",
                               netsnmp_get_statistic_helper_handler);
    if (ret) {
        ret->flags |= MIB_HANDLER_AUTO_NEXT;
        ret->myvoid = ((char*)0) + offset;
    }
    return ret;
}

int
netsnmp_register_statistic_handler(netsnmp_handler_registration *reginfo,
                                   oid start, int begin, int end)
{
    netsnmp_inject_handler(reginfo,
                           netsnmp_get_statistic_handler(begin - start));
    return netsnmp_register_scalar_group(reginfo, start, start + (end - begin));
}
