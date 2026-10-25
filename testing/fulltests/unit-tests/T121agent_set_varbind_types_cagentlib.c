/* HEADER Testing SET varbind type checks (handle_pdu, IP-MIB scalars) */

#include <net-snmp/net-snmp-features.h>
#include <net-snmp/agent/mib_module_config.h>
#include <net-snmp/agent/agent_module_config.h>

#ifdef NETSNMP_NO_WRITE_SUPPORT
OK(1, "skipped: write support disabled");
#else

extern int handle_pdu(netsnmp_agent_session *asp);
#ifdef USING_IP_MIB_IP_SCALARS_MODULE
extern void init_ip_scalars(void);
#endif
#ifdef USING_TSM_MIB_SNMPTSMCONFIGURATIONUSEPREFIX_MODULE
extern void init_snmpTsmConfigurationUsePrefix(void);
#endif

SOCK_STARTUP;

init_agent("snmpd");
init_snmp("snmpd");

/*
 * 1. handle_pdu() refuses SET varbinds whose type carries no value.
 */
{
    static const int              commands[] = {
        SNMP_MSG_SET,
        SNMP_MSG_INTERNAL_SET_BEGIN,
        SNMP_MSG_INTERNAL_SET_RESERVE1
    };
    static const u_char           types[] = {
        ASN_NULL, SNMP_NOSUCHOBJECT, SNMP_NOSUCHINSTANCE, SNMP_ENDOFMIBVIEW
    };
    oid                           int_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 121, 1, 0 };
    oid                           val_oid[] = { 1, 3, 6, 1, 4, 1, 99999, 121, 2, 0 };
    long                          val = 1;
    netsnmp_pdu                  *pdu;
    netsnmp_variable_list        *var;
    netsnmp_agent_session        *asp;
    int                           c, i, status;

    for (c = 0; c < (int) (sizeof(commands) / sizeof(commands[0])); c++) {
        for (i = 0; i < (int) sizeof(types); i++) {
            pdu = snmp_pdu_create(commands[c]);
            snmp_pdu_add_variable(pdu, int_oid, OID_LENGTH(int_oid),
                                  ASN_INTEGER, &val, sizeof(val));
            var = snmp_pdu_add_variable(pdu, val_oid, OID_LENGTH(val_oid),
                                        types[i], NULL, 0);
            /* As decoded by snmp_pdu_parse(): no value */
            var->val.string = NULL;
            var->val_len = 0;
            asp = init_agent_snmp_session(NULL, pdu);
            OK(asp != NULL, "init_agent_snmp_session succeeded");
            if (asp) {
                status = handle_pdu(asp);
                OKF(status == SNMP_ERR_WRONGTYPE && asp->index == 2,
                    ("handle_pdu (cmd %d) refuses SET varbind of type 0x%02x "
                     "with wrongType at index 2 (status %d, index %d)",
                     commands[c], types[i], status, asp->index));
                free_agent_snmp_session(asp);
            }
            snmp_free_pdu(pdu);
        }
    }
}

/*
 * 2. IP-MIB scalar SET handlers check the varbind type in RESERVE1.
 */
#ifdef USING_IP_MIB_IP_SCALARS_MODULE
{
    static const struct {
        const char *name;
        oid         instance[9];
    } scalars[] = {
        { "ipForwarding",      { 1, 3, 6, 1, 2, 1, 4, 1, 0 } },
        { "ipDefaultTTL",      { 1, 3, 6, 1, 2, 1, 4, 2, 0 } },
        { "ipv6IpForwarding",  { 1, 3, 6, 1, 2, 1, 4, 25, 0 } },
        { "ipAddressSpinLock", { 1, 3, 6, 1, 2, 1, 4, 33, 0 } },
    };
    netsnmp_subtree              *st;
    netsnmp_mib_handler          *h;
    netsnmp_agent_request_info    reqinfo;
    netsnmp_request_info          request;
    netsnmp_variable_list         vb;
    oid                           name[9];
    int                           i;

    init_ip_scalars();

    for (i = 0; i < (int) (sizeof(scalars) / sizeof(scalars[0])); i++) {
        h = NULL;
        st = netsnmp_subtree_find(scalars[i].instance, 9, NULL, "");
        if (st && st->reginfo)
            h = netsnmp_find_handler_by_name(st->reginfo, scalars[i].name);
        OKF(h != NULL, ("found the %s handler", scalars[i].name));
        if (!h)
            continue;

        memset(&reqinfo, 0, sizeof(reqinfo));
        memset(&request, 0, sizeof(request));
        memset(&vb, 0, sizeof(vb));
        memcpy(name, scalars[i].instance, sizeof(name));
        vb.name = name;
        vb.name_length = 9;
        vb.type = SNMP_NOSUCHOBJECT;
        request.requestvb = &vb;
        reqinfo.mode = MODE_SET_RESERVE1;
        h->access_method(h, st->reginfo, &reqinfo, &request);
        OKF(request.status == SNMP_ERR_WRONGTYPE,
            ("%s RESERVE1 refuses a noSuchObject varbind with wrongType (%d)",
             scalars[i].name, request.status));

        memset(&request, 0, sizeof(request));
        vb.type = ASN_OCTET_STR;
        vb.val.string = vb.buf;
        memcpy(vb.buf, "1", 1);
        vb.val_len = 1;
        request.requestvb = &vb;
        h->access_method(h, st->reginfo, &reqinfo, &request);
        OKF(request.status == SNMP_ERR_WRONGTYPE,
            ("%s RESERVE1 refuses an OCTET STRING varbind with wrongType (%d)",
             scalars[i].name, request.status));
    }
}
#endif

#ifdef USING_TSM_MIB_SNMPTSMCONFIGURATIONUSEPREFIX_MODULE
{
    oid                           instance[] = { 1, 3, 6, 1, 2, 1, 190, 1, 2, 1, 0 };
    netsnmp_subtree              *st;
    netsnmp_mib_handler          *h = NULL;
    netsnmp_agent_request_info    reqinfo;
    netsnmp_request_info          request;
    netsnmp_variable_list         vb;
    u_char                       *short_buf;

    init_snmpTsmConfigurationUsePrefix();

    st = netsnmp_subtree_find(instance, OID_LENGTH(instance), NULL, "");
    if (st && st->reginfo)
        h = netsnmp_find_handler_by_name(st->reginfo,
                                         "snmpTsmConfigurationUsePrefix");
    OK(h != NULL, "found the snmpTsmConfigurationUsePrefix handler");
    if (h) {
        memset(&reqinfo, 0, sizeof(reqinfo));
        memset(&request, 0, sizeof(request));
        memset(&vb, 0, sizeof(vb));
        vb.name = instance;
        vb.name_length = OID_LENGTH(instance);
        vb.type = SNMP_NOSUCHOBJECT;
        request.requestvb = &vb;
        reqinfo.mode = MODE_SET_RESERVE1;
        h->access_method(h, st->reginfo, &reqinfo, &request);
        OKF(request.status == SNMP_ERR_WRONGTYPE,
            ("snmpTsmConfigurationUsePrefix RESERVE1 refuses a noSuchObject "
             "varbind with wrongType (%d)", request.status));

        short_buf = calloc(1, 1);
        memset(&request, 0, sizeof(request));
        vb.type = ASN_BIT_STR;
        vb.val.bitstring = short_buf;
        vb.val_len = 1;
        request.requestvb = &vb;
        h->access_method(h, st->reginfo, &reqinfo, &request);
        OKF(request.status == SNMP_ERR_WRONGTYPE,
            ("snmpTsmConfigurationUsePrefix RESERVE1 refuses a 1-byte BIT "
             "STRING varbind with wrongType (%d)", request.status));
        free(short_buf);
    }
}
#endif

snmp_shutdown("snmpd");
shutdown_agent();

SOCK_CLEANUP;
#endif /* !NETSNMP_NO_WRITE_SUPPORT */
