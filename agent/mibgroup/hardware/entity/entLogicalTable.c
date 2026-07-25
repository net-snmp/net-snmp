#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "entity.h"
#include "entLogicalTable.h"

/*
 * entLogicalTable — RFC 6933 section 5.2
 *
 * OID: 1.3.6.1.2.1.47.1.2.1
 * Index: entLogicalIndex (Integer32)
 * Columns 2–8: descr, type, community, taddress, tdomain,
 *              contextEngineID, contextName
 *
 * One row per SNMP context known to the agent.  The default (empty)
 * context is always index 1.
 */

#define COL_DESCR             2
#define COL_TYPE              3
#define COL_COMMUNITY         4
#define COL_TADDRESS          5
#define COL_TDOMAIN           6
#define COL_CONTEXT_ENGINE_ID 7
#define COL_CONTEXT_NAME      8

static oid _logical_table_oid[] = { 1,3,6,1,2,1,47,1,2,1 };

/* ---- Iterator ------------------------------------------------------------ */

static netsnmp_variable_list *
_logical_get_first(void **loop_ctx, void **data_ctx,
                   netsnmp_variable_list *put_index_data,
                   netsnmp_iterator_info *iinfo)
{
    netsnmp_entity_logical_row *r;

    netsnmp_cache_check_and_reload(netsnmp_entity_get_cache());
    r = netsnmp_entity_logical_get_first();
    if (!r)
        return NULL;

    *loop_ctx = r;
    *data_ctx = r;
    snmp_set_var_typed_integer(put_index_data, ASN_INTEGER, r->idx);
    return put_index_data;
}

static netsnmp_variable_list *
_logical_get_next(void **loop_ctx, void **data_ctx,
                  netsnmp_variable_list *put_index_data,
                  netsnmp_iterator_info *iinfo)
{
    netsnmp_entity_logical_row *r =
        netsnmp_entity_logical_get_next(
            (netsnmp_entity_logical_row *)*loop_ctx);
    if (!r)
        return NULL;

    *loop_ctx = r;
    *data_ctx = r;
    snmp_set_var_typed_integer(put_index_data, ASN_INTEGER, r->idx);
    return put_index_data;
}

/* ---- Handler ------------------------------------------------------------- */

static int
_logical_handler(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_agent_request_info *reqinfo,
                 netsnmp_request_info *requests)
{
    netsnmp_request_info         *req;
    netsnmp_table_request_info   *tinfo;
    netsnmp_entity_logical_row   *r;
    static u_char                 empty_str[] = "";

    for (req = requests; req; req = req->next) {
        if (req->processed)
            continue;

        r     = (netsnmp_entity_logical_row *)
                    netsnmp_extract_iterator_context(req);
        tinfo = netsnmp_extract_table_info(req);
        if (!r || !tinfo) {
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
            continue;
        }

        switch (tinfo->colnum) {
        case COL_DESCR:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     (u_char *)r->descr, strlen(r->descr));
            break;
        case COL_TYPE:
            snmp_set_var_typed_value(req->requestvb, ASN_OBJECT_ID,
                                     (u_char *)r->type_oid,
                                     r->type_oid_len * sizeof(oid));
            break;
        case COL_COMMUNITY:
            /* Deprecated — always return empty string */
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     empty_str, 0);
            break;
        case COL_TADDRESS:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     r->taddress, r->taddress_len);
            break;
        case COL_TDOMAIN:
            snmp_set_var_typed_value(req->requestvb, ASN_OBJECT_ID,
                                     (u_char *)r->tdomain,
                                     r->tdomain_len * sizeof(oid));
            break;
        case COL_CONTEXT_ENGINE_ID:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     r->context_engine_id,
                                     r->context_engine_id_len);
            break;
        case COL_CONTEXT_NAME:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     (u_char *)r->context_name,
                                     strlen(r->context_name));
            break;
        default:
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
            break;
        }
    }
    return SNMP_ERR_NOERROR;
}

/* ---- Registration -------------------------------------------------------- */

void init_entLogicalTable(void)
{
    netsnmp_handler_registration    *reg;
    netsnmp_table_registration_info *tinfo;
    netsnmp_iterator_info            *iinfo;

    reg = netsnmp_create_handler_registration(
            "entLogicalTable", _logical_handler,
            _logical_table_oid, OID_LENGTH(_logical_table_oid),
            HANDLER_CAN_RONLY);
    if (!reg)
        return;

    tinfo = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    if (!tinfo)
        return;
    netsnmp_table_helper_add_indexes(tinfo, ASN_INTEGER, 0);
    tinfo->min_column = COL_DESCR;
    tinfo->max_column = COL_CONTEXT_NAME;

    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    if (!iinfo) {
        SNMP_FREE(tinfo);
        return;
    }
    iinfo->get_first_data_point = _logical_get_first;
    iinfo->get_next_data_point  = _logical_get_next;
    iinfo->table_reginfo        = tinfo;

    netsnmp_register_table_iterator2(reg, iinfo);
}
