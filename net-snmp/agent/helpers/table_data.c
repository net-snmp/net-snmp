#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "table.h"
#include "table_data.h"
#include "read_only.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/**
 * generates the index portion of an table oid from a varlist.
 */
void
table_data_generate_index_oid(table_row *row)
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
table_data_add_row(table_data *table, table_row *row)
{
    table_row *nextrow, *prevrow;
    
    if (row->indexes)
        table_data_generate_index_oid(row);

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

/** finds the data in "datalist" stored at "indexes" */
table_row *
table_data_get(table_data *table,
               struct variable_list *indexes) {
    oid searchfor[MAX_OID_LEN];
    size_t searchfor_len = MAX_OID_LEN;
    
    build_oid_noalloc(searchfor, MAX_OID_LEN, &searchfor_len, NULL, 0, indexes);
    return table_data_get_from_oid(table, searchfor, searchfor_len);
}

/** finds the data in "datalist" stored at the searchfor oid */
table_row *
table_data_get_from_oid(table_data *table,
                        oid *searchfor, size_t searchfor_len) {
    table_row *row;
    for(row = table->first_row; row != NULL; row = row->next) {
        if (snmp_oid_compare(searchfor, searchfor_len,
                             row->index_oid, row->index_oid_len) == 0)
            return row;
    }
    return NULL;
}

/** Creates a table_data handler and returns it */
mib_handler *
get_table_data_handler(table_data *table)
{
    mib_handler *ret = NULL;
  
    if (!table) {
        snmp_log(LOG_INFO, "get_table_data_handler(NULL) called\n");
        return NULL;
    }
  
    ret = create_handler(TABLE_DATA_NAME, table_data_helper_handler);
    if (ret) {
        ret->myvoid = (void *) table;
    }
    return ret;
}

/** registers a handler as a data table.
 *  If table_info != NULL, it registers it as a normal table too. */
int
register_table_data(handler_registration *reginfo,
                    table_data *table,
                    table_registration_info *table_info) {
    inject_handler(reginfo, get_table_data_handler(table));
    return register_table(reginfo, table_info);
}

/** registers a handler as a read-only data table
 *  If table_info != NULL, it registers it as a normal table too. */
int
register_read_only_table_data(handler_registration *reginfo,
                              table_data *table,
                              table_registration_info *table_info) {
    inject_handler(reginfo, get_read_only_handler());
    return register_table_data(reginfo, table, table_info);
}


/**
 * The helper handler that takes care of passing a specific row of
 * data down to the lower handler(s).  It sets request->processed if
 * the request should not be handled.
 */
int
table_data_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    table_data *table = (table_data *) handler->myvoid;
    request_info *request;
    int valid_request = 0;
    table_row *row;
    table_request_info *table_info;
    table_registration_info *table_reg_info =
        find_table_registration_info(reginfo);
    int result, regresult;
    
    for(request = requests; request; request = request->next) {
        if (request->processed)
            continue;

        table_info = extract_table_info(request);
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
                    request_add_list_data(request, create_data_list(TABLE_DATA_NAME, row, NULL));
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
                    set_request_error(reqinfo, request, SNMP_ERR_NOSUCHNAME);
                    break;
                } else if (NULL ==
                           (row =
                            table_data_get_from_oid(table,
                                                    request->requestvb->name +
                                                    reginfo->rootoid_len + 2,
                                                    request->requestvb->name_length -
                                                    reginfo->rootoid_len -
                                                    2))) {
                    /* no such row */
                    set_request_error(reqinfo, request, SNMP_ERR_NOSUCHNAME);
                    break;
                } else {
                    valid_request = 1;
                    request_add_list_data(request, create_data_list(TABLE_DATA_NAME, row, NULL));
                }
                break;

            case MODE_SET_RESERVE1:
                valid_request = 1;
                if (NULL !=
                    (row =
                     table_data_get_from_oid(table,
                                             request->requestvb->name +
                                             reginfo->rootoid_len + 2,
                                             request->requestvb->name_length -
                                             reginfo->rootoid_len -
                                             2))) {
                    request_add_list_data(request, create_data_list(TABLE_DATA_NAME, row, NULL));
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
        return call_next_handler(handler, reginfo, reqinfo, requests);
    else
        return SNMP_ERR_NOERROR;
}

/** creates and returns a pointer to table data set */
table_data *
create_table_data(const char *name) 
{
    table_data *table = SNMP_MALLOC_TYPEDEF(table_data);
    if (name)
        table->name = strdup(name);
    return table;
}

/** creates and returns a pointer to table data set */
table_row *
create_table_data_row(void) 
{
    table_row *row = SNMP_MALLOC_TYPEDEF(table_row);
    return row;
}

/** extracts the row being accessed passed from the table_data helper */
table_row *extract_table_row(request_info *request) 
{
    return (table_row *) request_get_list_data(request, TABLE_DATA_NAME);
}

/** extracts the data from the row being accessed passed from the
 * table_data helper */
void *extract_table_row_data(request_info *request) 
{
    return (extract_table_row(request))->data;
}

/** builds a result given a row, a varbind to set and the data */
int
table_data_build_result(handler_registration *reginfo,
                        agent_request_info   *reqinfo,
                        request_info *request,
                        table_row *row,
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

    
