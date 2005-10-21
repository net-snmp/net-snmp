/*
 * snmptrapd_auth.c - authorize notifications for further processing
 *
 */
#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>
#include "snmptrapd_handlers.h"
#include "snmptrapd_auth.h"
#include "snmptrapd_ds.h"
#include "mibII/vacm_conf.h"

/* **************************************/
/* authorization parsing token handlers */
/* **************************************/

void
vacm_parse_ipv4logcommunity(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV4,
                       VACM_VIEW_LOG_BIT);
}

void
vacm_parse_ipv4executecommunity(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV4,
                       VACM_VIEW_EXECUTE_BIT);
}

void
vacm_parse_ipv4netcommunity(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV4,
                       VACM_VIEW_NET_BIT);
}

void
vacm_parse_ipv6logcommunity(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV6,
                       VACM_VIEW_LOG_BIT);
}

void
vacm_parse_ipv6executecommunity(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV6,
                       VACM_VIEW_EXECUTE_BIT);
}

void
vacm_parse_ipv6netcommunity(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV6,
                       VACM_VIEW_NET_BIT);
}

void
vacm_parse_loguser(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_V3,
                       VACM_VIEW_LOG_BIT);
}

void
vacm_parse_executeuser(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_V3,
                       VACM_VIEW_EXECUTE_BIT);
}

void
vacm_parse_netuser(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_V3,
                       VACM_VIEW_NET_BIT);
}

void
vacm_parse_authuser(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_V3,
                       VACM_VIEW_NO_BITS);
}

void
vacm_parse_ipv4authcommunity(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV4,
                       VACM_VIEW_NO_BITS);
}

void
vacm_parse_ipv6authcommunity(const char *token, char *confline)
{
    vacm_create_simple(token, confline, VACM_CREATE_SIMPLE_COMIPV6,
                       VACM_VIEW_NO_BITS);
}

/**
 * initializes the snmptrapd authorization code registering needed
 * handlers and config parsers.
 */
void
init_netsnmp_trapd_auth(void)
{
    const char *commhelp = "[-v viewtype...] community [default|hostname|network/bits [oid]]";
    const char *userhelp = "[-s secmodel] user [noauth|auth|priv [oid]]";
    
    /* register our function as a authorization handler */
    netsnmp_trapd_handler *traph;
    traph = netsnmp_add_global_traphandler(NETSNMPTRAPD_AUTH_HANDLER,
                                           netsnmp_trapd_auth);
    traph->authtypes = TRAP_AUTH_NONE;

    /* register our configuration tokens for VACM configs */
    init_vacm_config_tokens();

    /* register a config token for turning off the authorization entirely */
    netsnmp_ds_register_config(ASN_BOOLEAN, "snmptrapd", "disableAuthorization",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_APP_NO_AUTHORIZATION);

    /* ipv4 community auth handlers */
    snmpd_register_config_handler("ipv4logcommunity",
                                  vacm_parse_ipv4logcommunity,
                                  NULL, commhelp);
    snmpd_register_config_handler("ipv4executecommunity",
                                  vacm_parse_ipv4executecommunity,
                                  NULL, commhelp);
    snmpd_register_config_handler("ipv4netcommunity",
                                  vacm_parse_ipv4netcommunity,
                                  NULL, commhelp);
    snmpd_register_config_handler("ipv4authcommunity",
                                  vacm_parse_ipv4authcommunity,
                                  NULL, commhelp);

    /* ipv6 community auth handlers */
    snmpd_register_config_handler("ipv6logcommunity",
                                  vacm_parse_ipv6logcommunity,
                                  NULL, commhelp);
    snmpd_register_config_handler("ipv6executecommunity",
                                  vacm_parse_ipv6executecommunity,
                                  NULL, commhelp);
    snmpd_register_config_handler("ipv6netcommunity",
                                  vacm_parse_ipv6netcommunity,
                                  NULL, commhelp);
    snmpd_register_config_handler("ipv6authcommunity",
                                  vacm_parse_ipv6authcommunity,
                                  NULL, commhelp);

    /* snmpv3 user auth handlers */
    snmpd_register_config_handler("loguser",
                                  vacm_parse_loguser,
                                  NULL, userhelp);
    snmpd_register_config_handler("executeuser",
                                  vacm_parse_executeuser,
                                  NULL, userhelp);
    snmpd_register_config_handler("netuser",
                                  vacm_parse_netuser,
                                  NULL, userhelp);
    snmpd_register_config_handler("authuser",
                                  vacm_parse_authuser,
                                  NULL, userhelp);
}

/* XXX: store somewhere in the PDU instead */
static int lastlookup;

/**
 * Authorizes incoming notifications for further processing
 */
int
netsnmp_trapd_auth(netsnmp_pdu           *pdu,
                   netsnmp_transport     *transport,
                   netsnmp_trapd_handler *handler)
{
    int ret = 0;
    oid snmptrapoid[] = { 1,3,6,1,6,3,1,1,4,1,0 };
    size_t snmptrapoid_len = OID_LENGTH(snmptrapoid);
    int i;
    netsnmp_pdu *newpdu = pdu;
    netsnmp_variable_list *var;

    /* check to see if authorization was not disabled */
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_APP_NO_AUTHORIZATION)) {
        DEBUGMSGTL(("snmptrapd:auth",
                    "authorization turned off: not checking\n"));
        return NETSNMPTRAPD_HANDLER_OK;
    }

    /* bail early if called illegally */
    if (!pdu || !transport || !handler)
        return NETSNMPTRAPD_HANDLER_FINISH;
    
    /* convert to v2 so we can check it in a consistent manner */
    if (pdu->version == SNMP_VERSION_1)
        newpdu = convert_v1pdu_to_v2(pdu);

    if (!newpdu) {
        snmp_log(LOG_ERR, "Failed to duplicate incoming PDU.  Refusing to authorize.\n");
        return NETSNMPTRAPD_HANDLER_FINISH;
    }

    /* loop through each variable and find the snmpTrapOID.0 var
       indicating what the trap is we're staring at. */
    for (var = newpdu->variables; var != NULL; var = var->next_variable) {
        if (netsnmp_oid_equals(var->name, var->name_length,
                               snmptrapoid, snmptrapoid_len) == 0)
            break;
    }

    /* make sure we can continue: we found the snmpTrapOID.0 and its an oid */
    if (!var || var->type != ASN_OBJECT_ID) {
        snmp_log(LOG_ERR, "Can't determine trap identifier; refusing to authorize it\n");
        if (newpdu != pdu)
            snmp_free_pdu(newpdu);
        return NETSNMPTRAPD_HANDLER_FINISH;
    }

    /* check the pdu against each typo of VACM access we may want to
       check up on later.  We cache the results for future lookup on
       each call to netsnmp_trapd_check_auth */
    for(i = 0; i < VACM_MAX_VIEWS; i++) {
        /* pass the PDU to the VACM routine for handling authorization */
        DEBUGMSGTL(("snmptrapd:auth", "Calling VACM for checking phase %d:%s\n",
                    i, se_find_label_in_slist(VACM_VIEW_ENUM_NAME, i)));
        if (vacm_check_view(newpdu, var->val.objid,
                            var->val_len/sizeof(oid), 0, i) == VACM_SUCCESS) {
            DEBUGMSGTL(("snmptrapd:auth", "  result: authorized\n"));
            ret |= 1 << i;
        } else {
            DEBUGMSGTL(("snmptrapd:auth", "  result: not authorized\n"));
        }
    }
    DEBUGMSGTL(("snmptrapd:auth", "Final bitmask auth: %x\n", ret));

    if (ret) {
        /* we have policy to at least do "something".  Remember and continue. */
        lastlookup = ret;
        if (newpdu != pdu)
            snmp_free_pdu(newpdu);
        return NETSNMPTRAPD_HANDLER_OK;
    }

    /* No policy was met, so we drop the PDU from further processing */
    DEBUGMSGTL(("snmptrapd:auth", "Dropping unauthorized message\n"));
    if (newpdu != pdu)
        snmp_free_pdu(newpdu);
    return NETSNMPTRAPD_HANDLER_FINISH;
}

/**
 * Checks to see if the pdu is authorized for a set of given action types.
 * @returns 1 if authorized, 0 if not.
 */
int
netsnmp_trapd_check_auth(int authtypes)
{
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_APP_NO_AUTHORIZATION)) {
        DEBUGMSGTL(("snmptrapd:auth", "authorization turned off\n"));
        return 1;
    }

    DEBUGMSGTL(("snmptrapd:auth",
                "Comparing auth types: result=%d, request=%d, result=%d\n",
                lastlookup, authtypes,
                ((authtypes & lastlookup) == authtypes)));
    return ((authtypes & lastlookup) == authtypes);
}

