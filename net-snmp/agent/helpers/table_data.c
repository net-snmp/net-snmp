#include <net-snmp/net-snmp-config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/table.h>
#include <net-snmp/agent/table_data.h>
#include <net-snmp/agent/read_only.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/**
 * generates the index portion of an table oid from a varlist.
 */
void
netsnmp_table_data_generate_index_oid(netsnmp_table_row *row)
{
    build_oid(&row->index_oid, &row->index_oid_len, NULL,
              0, row->indexes);
}

/**
 * Adds a row of data to a given table (stored in proper lexographical order).
 *
 * returns SNMPERR_SUCCESS on successful addition.
 *      or SNMPERR_GENERR  on failure (E.G., indexes already existed)
 */
int
netsnmp_table_data_add_row(table_data *table, netsnmp_table_row *row)
{
    netsnmp_table_row *nextrow, *prevrow;
    
    if (row->indexes)
        netsnmp_table_data_generate_index_oid(row);

    /* we don't store the index info as it
       takes up memory. */
    snmp_free_varbind(row->indexes);
    row->indexes = NULL;

    if (!row->index_oid) {
        snmp_log(LOG_ERR, "illegal data attempted to be added to table %s\n",
                 table->name);
        return SNMPERR_GENERR;
    }

    /* insert it into the table in the proper oid-lexographical order */
    for(nextrow = table->first_row, prevrow = NULL;
        nextrow != NULL;
        prevrow = nextrow, nextrow = nextrow->next) {
        if (snmp_oid_compare(nextrow->index_oid, nextrow->index_oid_len,
                             row->index_oid, row->index_oid_len) > 0)
            break;
        if (snmp_oid_compare(nextrow->index_oid, nextrow->index_oid_len,
                             row->index_oid, row->index_oid_len) == 0) {
            /* exact match.  Duplicate entries illegal */
            snmp_log(LOG_WARNING,
                     "duplicate table data attempted to be entered\n");
            return SNMPERR_GENERR;
        }
    }


    /* ok, we have the location of where it should go */
    /* (after prevrow, and before nextrow) */
    row->next = nextrow;
    row->prev = prevrow;
    
    if (row->next)
        row->next->prev = row;

    if (row->prev)
        row->prev->next = row;

    if (NULL == row->prev)       /* it's the (new) first row */
        table->first_row = row;
    
    DEBUGMSGTL(("table_data_add_data", "added something...\n"));

    return SNMPERR_SUCCESS;
}

/**
 * removes a row of data to a given table and returns it (no free's called)
 *
 * returns the row pointer itself on successful removing.
 *      or NULL on failure (bad arguments)
 */
netsnmp_table_row *
netsnmp_table_data_remove_row(table_data *table, netsnmp_table_row *row)
{
    if (!row || !table)
        return NULL;
    
    if (row->prev)
        row->prev->next = row->next;
    else
        table->first_row = row->next;

    if (row->next)
        row->next->prev = row->prev;
            
    return row;
}

/**
 * removes and frees a row of data to a given table and returns the void *
 *
 * returns the void * data on successful deletion.
 *      or NULL on failure (bad arguments)
 */
void *
netsnmp_table_data_delete_row(table_data *table, netsnmp_table_row *row)
{
    void *data;
    
    if (!row || !table)
        return NULL;
    
    /* remove it from the list */
    netsnmp_table_data_remove_row(table,row);
    
    /* free the memory we can */
    if (row->indexes)
        snmp_free_varbind(row->indexes);
    SNMP_FREE(row->index_oid);
    data = row->data;
    free(row);

    /* return the void * pointer */
    return data;
}


/** finds the data in "datalist" stored at "indexes" */
netsnmp_table_row *
netsnmp_table_data_get(table_data *table,
               netsnmp_variable_list *indexes) {
    oid searchfor[MAX_OID_LEN];
    size_t searchfor_len = MAX_OID_LEN;
    
    build_oid_noalloc(searchfor, MAX_OID_LEN, &searchfor_len, NULL, 0, indexes);
    return netsnmp_table_data_get_from_oid(table, searchfor, searchfor_len);
}

/** finds the data in "datalist" stored at the searchfor oid */
netsnmp_table_row *
netsnmp_table_data_get_from_oid(table_data *table,
                        oid *searchfor, size_t searchfor_len) {
    netsnmp_table_row *row;
    for(row = table->first_row; row != NULL; row = row->next) {
        if (snmp_oid_compare(searchfor, searchfor_len,
                             row->index_oid, row->index_oid_len) == 0)
            return row;
    }
    return NULL;
}

/** Creates a table_data handler and returns it */
netsnmp_mib_handler *
netsnmp_get_table_data_handler(table_data *table)
{
    netsnmp_mib_handler *ret = NULL;
  
    if (!table) {
        snmp_log(LOG_INFO, "netsnmp_get_table_data_handler(NULL) called\n");
        return NULL;
    }
  
    ret = netsnmp_create_handler(TABLE_DATA_NAME, netsnmp_table_data_helper_handler);
    if (ret) {
        ret->myvoid = (void *) table;
    }
    return ret;
}

/** registers a handler as a data table.
 *  If table_info != NULL, it registers it as a normal table too. */
int
netsnmp_register_table_data(netsnmp_handler_registration *reginfo,
                    table_data *table,
                    netsnmp_table_registration_info *table_info) {
    netsnmp_inject_handler(reginfo, netsnmp_get_table_data_handler(table));
    return netsnmp_register_table(reginfo, table_info);
}

/** registers a handler as a read-only data table
 *  If table_info != NULL, it registers it as a normal table too. */
int
netsnmp_register_read_only_table_data(netsnmp_handler_registration *reginfo,
                              table_data *table,
                              netsnmp_table_registration_info *table_info) {
    netsnmp_inject_handler(reginfo, netsnmp_get_read_only_handler());
    return netsnmp_register_table_data(reginfo, table, table_info);
}


/**
 * The helper handler that takes care of passing a specific row of
 * data down to the lower handler(s).  It sets request->processed if
 * the request should not be handled.
 */
int
netsnmp_table_data_helper_handler(
    netsnmp_mib_handler               *handler,
    netsnmp_handler_registration      *reginfo,
    netsnmp_agent_request_info        *reqinfo,
    netsnmp_request_info              *requests) {

    table_data *table = (table_data *) handler->myvoid;
    netsnmp_request_info *request;
    int valid_request = 0;
    netsnmp_table_row *row;
    netsnmp_table_request_info *table_info;
    netsnmp_table_registration_info *table_reg_info =
        netsnmp_find_netsnmp_table_registration_info(reginfo);
    int result, regresult;
    
    for(request = requests; request; request = request->next) {
        if (request->processed)
            continue;

        table_info = netsnmp_extract_table_info(request);
        if (!table_info)
            continue; /* ack */

        /* find the row in question */
        switch(reqinfo->mode) {
            case MODE_GETNEXT:
            case MODE_GETBULK: /* XXXWWW */
                if (request->requestvb->type != ASN_NULL)
                    continue;
                /* loop through data till we find the next row */
                result = snmp_oid_compare(request->requestvb->name,
                                          request->requestvb->name_length,
                                          reginfo->rootoid,
                                          reginfo->rootoid_len);
                regresult = snmp_oid_compare(request->requestvb->name,
                                             SNMP_MIN(request->requestvb->name_length, reginfo->rootoid_len),
                                             reginfo->rootoid,
                                             reginfo->rootoid_len);
                if (regresult == 0 &&
                    request->requestvb->name_length < reginfo->rootoid_len)
                    regresult = -1;
                
                if (result < 0 || 0 == result) {
                    /* before us entirely, return the first */
                    row = table->first_row;
                    table_info->colnum = table_reg_info->min_column;
                } else if (regresult == 0 && request->requestvb->name_length ==
                           reginfo->rootoid_len + 1) {
                    /* exactly to the entry */
                    row = table->first_row;
                    table_info->colnum = table_reg_info->min_column;
                } else if (regresult == 0 && request->requestvb->name_length ==
                           reginfo->rootoid_len + 2 &&
                           request->requestvb->name[reginfo->rootoid_len-2] ==
                           1) {
                    /* exactly to the column */
                    row = table->first_row;
                } else {
                    /* loop through all rows looking for the first one
                       that is equal to the request or greater than it */
                    for(row = table->first_row; row; row = row->next) {
                        /* compare the index of the request to the row */
                        result =
                            snmp_oid_compare(row->index_oid,
                                             row->index_oid_len,
                                             request->requestvb->name + 2 +
                                             reginfo->rootoid_len,
                                             request->requestvb->name_length -
                                             2 - reginfo->rootoid_len);
                        if (result == 0) {
                            /* equal match, return the next row */
                            if (row) {
                                row = row->next;
                            }
                            break;
                        } else if (result > 0) {
                            /* the current row is greater than the
                               request, use it */
                            break;
                        }
                    }
                }
                if (!row) {
                    table_info->colnum++;
                    if (table_info->colnum <= table_reg_info->max_column) {
                        row = table->first_row;
                    }
                }
                if (row) {
                    valid_request = 1;
                    netsnmp_request_netsnmp_add_list_data(request, netsnmp_create_netsnmp_data_list(TABLE_DATA_NAME, row, NULL));
                } else { /* no decent result found.  Give up. It's beyond us. */
                        request->processed = 1;
                }
                break;

            case MODE_GET:
                if (request->requestvb->type != ASN_NULL)
                    continue;
                /* find the row in question */
                if (request->requestvb->name_length <
                    (reginfo->rootoid_len + 3)) {  /* table.entry.column... */
                    /* request too short */
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOSUCHNAME);
                    break;
                } else if (NULL ==
                           (row =
                            netsnmp_table_data_get_from_oid(table,
                                                    request->requestvb->name +
                                                    reginfo->rootoid_len + 2,
                                                    request->requestvb->name_length -
                                                    reginfo->rootoid_len -
                                                    2))) {
                    /* no such row */
                    netsnmp_set_request_error(reqinfo, request, SNMP_ERR_NOSUCHNAME);
                    break;
                } else {
                    valid_request = 1;
                    netsnmp_request_netsnmp_add_list_data(request, netsnmp_create_netsnmp_data_list(TABLE_DATA_NAME, row, NULL));
                }
                break;

            case MODE_SET_RESERVE1:
                valid_request = 1;
                if (NULL !=
                    (row =
                     netsnmp_table_data_get_from_oid(table,
                                             request->requestvb->name +
                                             reginfo->rootoid_len + 2,
                                             request->requestvb->name_length -
                                             reginfo->rootoid_len -
                                             2))) {
                    netsnmp_request_netsnmp_add_list_data(request, netsnmp_create_netsnmp_data_list(TABLE_DATA_NAME, row, NULL));
                }
                break;

            case MODE_SET_RESERVE2:
            case MODE_SET_ACTION:
            case MODE_SET_COMMIT:
            case MODE_SET_FREE:
            case MODE_SET_UNDO:
                valid_request = 1;

        }
    }

    if (valid_request)
        return netsnmp_call_next_handler(handler, reginfo, reqinfo, requests);
    else
        return SNMP_ERR_NOERROR;
}

/** creates and returns a pointer to table data set */
table_data *
netsnmp_create_table_data(const char *name) 
{
    table_data *table = SNMP_MALLOC_TYPEDEF(table_data);
    if (name)
        table->name = strdup(name);
    return table;
}

/** creates and returns a pointer to table data set */
netsnmp_table_row *
netsnmp_create_table_data_row(void) 
{
    netsnmp_table_row *row = SNMP_MALLOC_TYPEDEF(netsnmp_table_row);
    return row;
}

/** extracts the row being accessed passed from the table_data helper */
netsnmp_table_row *netsnmp_extract_netsnmp_table_row(netsnmp_request_info *request) 
{
    return (netsnmp_table_row *) netsnmp_request_netsnmp_get_list_data(request, TABLE_DATA_NAME);
}

/** extracts the data from the row being accessed passed from the
 * table_data helper */
void *netsnmp_extract_netsnmp_table_row_data(netsnmp_request_info *request) 
{
    return (netsnmp_extract_netsnmp_table_row(request))->data;
}

/** builds a result given a row, a varbind to set and the data */
int
netsnmp_table_data_build_result(netsnmp_handler_registration *reginfo,
                        netsnmp_agent_request_info   *reqinfo,
                        netsnmp_request_info *request,
                        netsnmp_table_row *row,
                        int column,
                        u_char type,
                        u_char *result_data, size_t result_data_len) 
{
    oid build_space[MAX_OID_LEN];

    if (reqinfo->mode == MODE_GETNEXT ||
        reqinfo->mode == MODE_GETBULK) {
        /* only need to do this for getnext type cases where oid is changing */
        memcpy(build_space, reginfo->rootoid, /* registered oid */
               reginfo->rootoid_len * sizeof(oid));
        build_space[reginfo->rootoid_len] = 1; /* entry */
        build_space[reginfo->rootoid_len+1] = column; /* column */
        memcpy(build_space + reginfo->rootoid_len + 2, /* index data */
               row->index_oid, row->index_oid_len * sizeof(oid));
        snmp_set_var_objid(request->requestvb, build_space,
                           reginfo->rootoid_len + 2 + row->index_oid_len);
    }
    snmp_set_var_typed_value(request->requestvb, type,
                             result_data, result_data_len);
    return SNMPERR_SUCCESS; /* WWWXXX: check for bounds */
}

    
