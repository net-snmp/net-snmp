#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "entity.h"
#include "entPhysicalTable.h"

/* entPhysicalEntry column numbers */
#define COL_DESCR          2
#define COL_VENDORTYPE     3
#define COL_CONTAINEDIN    4
#define COL_CLASS          5
#define COL_PARENTRELPOS   6
#define COL_NAME           7
#define COL_HWREV          8
#define COL_FWREV          9
#define COL_SWREV         10
#define COL_SERIAL        11
#define COL_MFGNAME       12
#define COL_MODELNAME     13
#define COL_ALIAS         14
#define COL_ASSETID       15
#define COL_ISFRU         16
#define COL_MFGDATE       17
#define COL_URIS          18
#define COL_UUID          19

static oid _ent_physical_table_oid[]  = { 1,3,6,1,2,1,47,1,1,1 };
static oid _ent_contains_table_oid[]  = { 1,3,6,1,2,1,47,1,3,3 };

static oid _zero_dot_zero[] = { 0, 0 };
static u_char _empty_string[] = "";

/* ---- entPhysicalTable iterator ------------------------------------------ */

static netsnmp_variable_list *
_phys_get_first(void **loop_ctx, void **data_ctx,
                netsnmp_variable_list *put_index_data,
                netsnmp_iterator_info *iinfo)
{
    netsnmp_entity_info *e;

    netsnmp_cache_check_and_reload(netsnmp_entity_get_cache());
    e = netsnmp_entity_get_first();
    while (e && e->hidden)
        e = netsnmp_entity_get_next(e);
    if (!e)
        return NULL;

    *loop_ctx = e;
    *data_ctx = e;
    snmp_set_var_typed_integer(put_index_data, ASN_INTEGER, e->idx);
    return put_index_data;
}

static netsnmp_variable_list *
_phys_get_next(void **loop_ctx, void **data_ctx,
               netsnmp_variable_list *put_index_data,
               netsnmp_iterator_info *iinfo)
{
    netsnmp_entity_info *e = netsnmp_entity_get_next((netsnmp_entity_info *)*loop_ctx);
    while (e && e->hidden)
        e = netsnmp_entity_get_next(e);
    if (!e)
        return NULL;

    *loop_ctx = e;
    *data_ctx = e;
    snmp_set_var_typed_integer(put_index_data, ASN_INTEGER, e->idx);
    return put_index_data;
}

static int
_phys_handler(netsnmp_mib_handler *handler,
              netsnmp_handler_registration *reginfo,
              netsnmp_agent_request_info *reqinfo,
              netsnmp_request_info *requests)
{
    netsnmp_request_info        *req;
    netsnmp_table_request_info  *tinfo;
    netsnmp_entity_info         *e;

    for (req = requests; req; req = req->next) {
        if (req->processed)
            continue;

        e = (netsnmp_entity_info *)netsnmp_extract_iterator_context(req);
        tinfo = netsnmp_extract_table_info(req);
        if (!e || !tinfo) {
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
            continue;
        }

        switch (tinfo->colnum) {
        case COL_DESCR:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     (u_char *)e->descr, strlen(e->descr));
            break;
        case COL_VENDORTYPE:
            snmp_set_var_typed_value(req->requestvb, ASN_OBJECT_ID,
                                     (u_char *)_zero_dot_zero,
                                     sizeof(_zero_dot_zero));
            break;
        case COL_CONTAINEDIN:
            snmp_set_var_typed_integer(req->requestvb, ASN_INTEGER,
                                       e->parent_idx);
            break;
        case COL_CLASS:
            snmp_set_var_typed_integer(req->requestvb, ASN_INTEGER,
                                       e->iana_class);
            break;
        case COL_PARENTRELPOS:
            snmp_set_var_typed_integer(req->requestvb, ASN_INTEGER,
                                       e->parent_rel_pos < -1 ? -1 :
                                       e->parent_rel_pos);
            break;
        case COL_NAME:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     (u_char *)e->name, strlen(e->name));
            break;
        case COL_HWREV:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     (u_char *)e->hw_rev, strlen(e->hw_rev));
            break;
        case COL_FWREV:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     (u_char *)e->fw_rev, strlen(e->fw_rev));
            break;
        case COL_SWREV:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     (u_char *)e->sw_rev, strlen(e->sw_rev));
            break;
        case COL_SERIAL:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     netsnmp_entity_sensitive_data ?
                                     (u_char *)e->serial : _empty_string,
                                     netsnmp_entity_sensitive_data ?
                                     strlen(e->serial) : 0);
            break;
        case COL_MFGNAME:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     (u_char *)e->mfg_name, strlen(e->mfg_name));
            break;
        case COL_MODELNAME:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     (u_char *)e->model_name,
                                     strlen(e->model_name));
            break;
        case COL_ALIAS:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     netsnmp_entity_sensitive_data ?
                                     (u_char *)e->alias : _empty_string,
                                     netsnmp_entity_sensitive_data ?
                                     strlen(e->alias) : 0);
            break;
        case COL_ASSETID:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     netsnmp_entity_sensitive_data ?
                                     (u_char *)e->asset_id : _empty_string,
                                     netsnmp_entity_sensitive_data ?
                                     strlen(e->asset_id) : 0);
            break;
        case COL_ISFRU:
            snmp_set_var_typed_integer(req->requestvb, ASN_INTEGER, e->is_fru);
            break;
        case COL_MFGDATE:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     _empty_string, 0);
            break;
        case COL_URIS:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     netsnmp_entity_sensitive_data ?
                                     (u_char *)e->uris : _empty_string,
                                     netsnmp_entity_sensitive_data ?
                                     strlen(e->uris) : 0);
            break;
        case COL_UUID:
            snmp_set_var_typed_value(req->requestvb, ASN_OCTET_STR,
                                     netsnmp_entity_sensitive_data ? e->uuid :
                                     _empty_string,
                                     netsnmp_entity_sensitive_data ?
                                     e->uuid_len : 0);
            break;
        default:
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
            break;
        }
    }
    return SNMP_ERR_NOERROR;
}

/* ---- entPhysicalContainsTable iterator ----------------------------------- */

static netsnmp_variable_list *
_contains_get_first(void **loop_ctx, void **data_ctx,
                    netsnmp_variable_list *put_index_data,
                    netsnmp_iterator_info *iinfo)
{
    netsnmp_entity_contains_row *row;

    netsnmp_cache_check_and_reload(netsnmp_entity_get_cache());
    if (netsnmp_entity_contains_count() == 0)
        return NULL;

    row = netsnmp_entity_contains_get(0);
    *loop_ctx = (void *)(intptr_t)0;   /* index into contains array */
    *data_ctx = row;
    snmp_set_var_typed_integer(put_index_data, ASN_INTEGER, row->parent_idx);
    snmp_set_var_typed_integer(put_index_data->next_variable, ASN_INTEGER,
                               row->child_idx);
    return put_index_data;
}

static netsnmp_variable_list *
_contains_get_next(void **loop_ctx, void **data_ctx,
                   netsnmp_variable_list *put_index_data,
                   netsnmp_iterator_info *iinfo)
{
    int n = (int)(intptr_t)*loop_ctx + 1;
    netsnmp_entity_contains_row *row = netsnmp_entity_contains_get(n);

    if (!row)
        return NULL;

    *loop_ctx = (void *)(intptr_t)n;
    *data_ctx = row;
    snmp_set_var_typed_integer(put_index_data, ASN_INTEGER, row->parent_idx);
    snmp_set_var_typed_integer(put_index_data->next_variable, ASN_INTEGER,
                               row->child_idx);
    return put_index_data;
}

static int
_contains_handler(netsnmp_mib_handler *handler,
                  netsnmp_handler_registration *reginfo,
                  netsnmp_agent_request_info *reqinfo,
                  netsnmp_request_info *requests)
{
    netsnmp_request_info        *req;
    netsnmp_table_request_info  *tinfo;
    netsnmp_entity_contains_row *row;

    for (req = requests; req; req = req->next) {
        if (req->processed)
            continue;

        row   = (netsnmp_entity_contains_row *)netsnmp_extract_iterator_context(req);
        tinfo = netsnmp_extract_table_info(req);
        if (!row || !tinfo) {
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
            continue;
        }

        /* column 1 = entPhysicalChildIndex */
        snmp_set_var_typed_integer(req->requestvb, ASN_INTEGER, row->child_idx);
    }
    return SNMP_ERR_NOERROR;
}

/* ---- Registration -------------------------------------------------------- */

void init_entPhysicalTable(void)
{
    netsnmp_handler_registration    *reg;
    netsnmp_table_registration_info *tinfo;
    netsnmp_iterator_info            *iinfo;

    /* entPhysicalTable */
    reg = netsnmp_create_handler_registration(
            "entPhysicalTable", _phys_handler,
            _ent_physical_table_oid, OID_LENGTH(_ent_physical_table_oid),
            HANDLER_CAN_RONLY);
    if (!reg)
        return;

    tinfo = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    if (!tinfo)
        return;
    netsnmp_table_helper_add_indexes(tinfo, ASN_INTEGER, 0);
    tinfo->min_column = COL_DESCR;
    tinfo->max_column = COL_UUID;

    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    if (!iinfo) {
        SNMP_FREE(tinfo);
        return;
    }
    iinfo->get_first_data_point = _phys_get_first;
    iinfo->get_next_data_point  = _phys_get_next;
    iinfo->table_reginfo        = tinfo;

    netsnmp_register_table_iterator2(reg, iinfo);

    /* entPhysicalContainsTable */
    reg = netsnmp_create_handler_registration(
            "entPhysicalContainsTable", _contains_handler,
            _ent_contains_table_oid, OID_LENGTH(_ent_contains_table_oid),
            HANDLER_CAN_RONLY);
    if (!reg)
        return;

    tinfo = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    if (!tinfo)
        return;
    netsnmp_table_helper_add_indexes(tinfo, ASN_INTEGER, ASN_INTEGER, 0);
    tinfo->min_column = 1;
    tinfo->max_column = 1;

    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    if (!iinfo) {
        SNMP_FREE(tinfo);
        return;
    }
    iinfo->get_first_data_point = _contains_get_first;
    iinfo->get_next_data_point  = _contains_get_next;
    iinfo->table_reginfo        = tinfo;

    netsnmp_register_table_iterator2(reg, iinfo);
}
