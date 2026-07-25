#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "entity.h"
#include "entAliasMappingTable.h"

/*
 * entAliasMappingTable — RFC 6933 section 5.3
 *
 * OID: 1.3.6.1.2.1.47.1.3.2
 * Indexes: entPhysicalIndex (Integer32), entAliasLogicalIndexOrZero (Integer32)
 * Column 2: entAliasMappingIdentifier (OID / RowPointer)
 *
 * Each physical port entity with a known ifIndex gets one row with
 * entAliasLogicalIndexOrZero = 0 (agent-wide, not bound to a specific logical entity) and
 * entAliasMappingIdentifier pointing to ifEntry.ifIndex.N.
 */

static oid _alias_table_oid[] = { 1, 3, 6, 1, 2, 1, 47, 1, 3, 2 };

/* ---- Iterator ------------------------------------------------------------ */

static netsnmp_variable_list *
_alias_get_first(void **loop_ctx, void **data_ctx,
                 netsnmp_variable_list *put_index_data,
                 netsnmp_iterator_info *iinfo)
{
    netsnmp_entity_alias_row *row;

    netsnmp_cache_check_and_reload(netsnmp_entity_get_cache());
    if (netsnmp_entity_alias_count() == 0)
        return NULL;

    row = netsnmp_entity_alias_get(0);
    *loop_ctx = (void *)(intptr_t)0;
    *data_ctx = row;
    snmp_set_var_typed_integer(put_index_data, ASN_INTEGER, row->phys_idx);
    snmp_set_var_typed_integer(put_index_data->next_variable, ASN_INTEGER,
                               row->logical_idx);
    return put_index_data;
}

static netsnmp_variable_list *
_alias_get_next(void **loop_ctx, void **data_ctx,
                netsnmp_variable_list *put_index_data,
                netsnmp_iterator_info *iinfo)
{
    int n = (int)(intptr_t)*loop_ctx + 1;
    netsnmp_entity_alias_row *row = netsnmp_entity_alias_get(n);

    if (!row)
        return NULL;

    *loop_ctx = (void *)(intptr_t)n;
    *data_ctx = row;
    snmp_set_var_typed_integer(put_index_data, ASN_INTEGER, row->phys_idx);
    snmp_set_var_typed_integer(put_index_data->next_variable, ASN_INTEGER,
                               row->logical_idx);
    return put_index_data;
}

/* ---- Handler ------------------------------------------------------------- */

static int
_alias_handler(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_agent_request_info *reqinfo,
               netsnmp_request_info *requests)
{
    netsnmp_request_info       *req;
    netsnmp_table_request_info *tinfo;
    netsnmp_entity_alias_row   *row;

    for (req = requests; req; req = req->next) {
        if (req->processed)
            continue;

        row   = (netsnmp_entity_alias_row *)
                    netsnmp_extract_iterator_context(req);
        tinfo = netsnmp_extract_table_info(req);
        if (!row || !tinfo) {
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHINSTANCE);
            continue;
        }

        /* Column 2: entAliasMappingIdentifier */
        if (tinfo->colnum == 2) {
            snmp_set_var_typed_value(req->requestvb, ASN_OBJECT_ID,
                                     (u_char *)row->target_oid,
                                     row->target_oid_len * sizeof(oid));
        } else {
            netsnmp_set_request_error(reqinfo, req, SNMP_NOSUCHOBJECT);
        }
    }
    return SNMP_ERR_NOERROR;
}

/* ---- Registration -------------------------------------------------------- */

void init_entAliasMappingTable(void)
{
    netsnmp_handler_registration    *reg;
    netsnmp_table_registration_info *tinfo;
    netsnmp_iterator_info            *iinfo;

    reg = netsnmp_create_handler_registration(
            "entAliasMappingTable", _alias_handler,
            _alias_table_oid, OID_LENGTH(_alias_table_oid),
            HANDLER_CAN_RONLY);
    if (!reg)
        return;

    tinfo = SNMP_MALLOC_TYPEDEF(netsnmp_table_registration_info);
    if (!tinfo)
        return;
    netsnmp_table_helper_add_indexes(tinfo, ASN_INTEGER, ASN_INTEGER, 0);
    tinfo->min_column = 2;
    tinfo->max_column = 2;

    iinfo = SNMP_MALLOC_TYPEDEF(netsnmp_iterator_info);
    if (!iinfo) {
        SNMP_FREE(tinfo);
        return;
    }
    iinfo->get_first_data_point = _alias_get_first;
    iinfo->get_next_data_point  = _alias_get_next;
    iinfo->table_reginfo        = tinfo;

    netsnmp_register_table_iterator2(reg, iinfo);
}
