#include <net-snmp/net-snmp-config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/table.h>
#include <net-snmp/agent/table_data2.h>
#include <net-snmp/agent/table_container.h>
#include <net-snmp/agent/read_only.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/** @defgroup table_data2 table_data2: Helps you implement a table with datamatted storage.
 *  @ingroup table
 *
 *  This helper helps you implement a table where all the indexes are
 *  expected to be stored within the agent itself and not in some
 *  external storage location.  It can be used to store a list of
 *  rows, where a row consists of the indexes to the table and a
 *  generic data pointer.  You can then implement a subhandler which
 *  is passed the exact row definition and data it must return data
 *  for or accept data for.  Complex GETNEXT handling is greatly
 *  simplified in this case.
 *
 *  @{
 */

/**
 * generates the index portion of an table oid from a varlist.
 */
void
netsnmp_table_data2_generate_index_oid(netsnmp_table_data2row *row)
{
    build_oid(&row->oid_index.oids, &row->oid_index.len, NULL, 0, row->indexes);
}

/**
 * Adds a row of data to a given table (stored in proper lexographical order).
 *
 * returns SNMPERR_SUCCESS on successful addition.
 *      or SNMPERR_GENERR  on failure (E.G., indexes already existed)
 */
int
netsnmp_table_data2_add_row(netsnmp_table_data2 *table,
                           netsnmp_table_data2row *row)
{
    if (!row || !table)
        return SNMPERR_GENERR;

    if (row->indexes)
        netsnmp_table_data2_generate_index_oid(row);

    /*
     * we don't store the index info as it
     * takes up memory. 
     */
    if (!table->store_indexes) {
        snmp_free_varbind(row->indexes);
        row->indexes = NULL;
    }

    if (!row->oid_index.oids) {
        snmp_log(LOG_ERR,
                 "illegal data attempted to be added to table %s (no index)\n",
                 table->name);
        return SNMPERR_GENERR;
    }

    /*
     * add this row to the stored table
     */
    CONTAINER_INSERT( table->container, row );
    DEBUGMSGTL(("table_data2_add_data2", "added something...\n"));

    return SNMPERR_SUCCESS;
}

/**
 * removes a row of data to a given table and returns it (no free's called)
 *
 * returns the row pointer itself on successful removing.
 *      or NULL on failure (bad arguments)
 */
netsnmp_table_data2row *
netsnmp_table_data2_remove_row(netsnmp_table_data2 *table,
                              netsnmp_table_data2row *row)
{
    if (!row || !table)
        return NULL;

    CONTAINER_REMOVE( table->container, row );
    return row;
}

/** deletes a row's memory.
 *  returns the void data that it doesn't know how to delete. */
void           *
netsnmp_table_data2_delete_row(netsnmp_table_data2row *row)
{
    void           *data;

    if (!row)
        return NULL;

    /*
     * free the memory we can 
     */
    if (row->indexes)
        snmp_free_varbind(row->indexes);
    SNMP_FREE(row->oid_index.oids);
    data = row->data;
    free(row);

    /*
     * return the void * pointer 
     */
    return data;
}

/**
 * removes and frees a row of data to a given table and returns the void *
 *
 * returns the void * data on successful deletion.
 *      or NULL on failure (bad arguments)
 */
void           *
netsnmp_table_data2_remove_and_delete_row(netsnmp_table_data2 *table,
                                         netsnmp_table_data2row *row)
{
    if (!row || !table)
        return NULL;

    /*
     * remove it from the list 
     */
    netsnmp_table_data2_remove_row(table, row);
    return netsnmp_table_data2_delete_row(row);
}

/** swaps out origrow with newrow.  This does *not* delete/free anything! */
NETSNMP_INLINE void
netsnmp_table_data2_replace_row(netsnmp_table_data2 *table,
                               netsnmp_table_data2row *origrow,
                               netsnmp_table_data2row *newrow)
{
    netsnmp_table_data2_remove_row(table, origrow);
    netsnmp_table_data2_add_row(table, newrow);
}

/** finds the data in "datalist" stored at "indexes" */
netsnmp_table_data2row *
netsnmp_table_data2_get(netsnmp_table_data2 *table,
                       netsnmp_variable_list * indexes)
{
    oid             searchfor[MAX_OID_LEN];
    size_t          searchfor_len = MAX_OID_LEN;

    build_oid_noalloc(searchfor, MAX_OID_LEN, &searchfor_len, NULL, 0,
                      indexes);
    return netsnmp_table_data2_get_from_oid(table, searchfor,
                                           searchfor_len);
}

/** finds the data in "datalist" stored at the searchfor oid */
netsnmp_table_data2row *
netsnmp_table_data2_get_from_oid(netsnmp_table_data2 *table,
                                oid * searchfor, size_t searchfor_len)
{
    netsnmp_index index;
    if (!table)
        return NULL;

    index.oids = searchfor;
    index.len  = searchfor_len;
    return CONTAINER_FIND( table->container, &index );
}

/** returns the first row in the table */
netsnmp_table_data2row *
netsnmp_table_data2_get_first_row(netsnmp_table_data2 *table)
{
    return (netsnmp_table_data2row *)CONTAINER_FIRST( table->container );
}

/** returns the next row in the table */
netsnmp_table_data2row *
netsnmp_table_data2_get_next_row(netsnmp_table_data2 *table,
                                netsnmp_table_data2row  *row)
{
    return (netsnmp_table_data2row *)CONTAINER_NEXT( table->container, row  );
}

/** Creates a table_data2 handler and returns it */
netsnmp_mib_handler *
netsnmp_get_table_data2_handler(netsnmp_table_data2 *table)
{
    netsnmp_mib_handler *ret = NULL;

    if (!table) {
        snmp_log(LOG_INFO,
                 "netsnmp_get_table_data2_handler(NULL) called\n");
        return NULL;
    }

    ret =
        netsnmp_create_handler(TABLE_DATA2_NAME,
                               netsnmp_table_data2_helper_handler);
    if (ret) {
        ret->flags |= MIB_HANDLER_AUTO_NEXT;
        ret->myvoid = (void *) table;
    }
    return ret;
}

/** registers a handler as a data table.
 *  If table_info != NULL, it registers it as a normal table too. */
int
netsnmp_register_table_data2(netsnmp_handler_registration *reginfo,
                            netsnmp_table_data2 *table,
                            netsnmp_table_registration_info *table_info)
{
    netsnmp_inject_handler(reginfo, netsnmp_get_table_data2_handler(table));
    return netsnmp_container_table_register(reginfo, table_info,
                  table->container, TABLE_CONTAINER_KEY_NETSNMP_INDEX);
}

/** registers a handler as a read-only data table
 *  If table_info != NULL, it registers it as a normal table too. */
int
netsnmp_register_read_only_table_data2(netsnmp_handler_registration
                                      *reginfo, netsnmp_table_data2 *table,
                                      netsnmp_table_registration_info
                                      *table_info)
{
    netsnmp_inject_handler(reginfo, netsnmp_get_read_only_handler());
    return netsnmp_register_table_data2(reginfo, table, table_info);
}


/**
 * The helper handler that takes care of passing a specific row of
 * data down to the lower handler(s).  The table_container helper
 * has already taken care of identifying the appropriate row of the
 * table (and converting GETNEXT requests into an equivalent GET request)
 * So all we need to do here is make sure that the row is accessible
 * using table_data2-style retrieval techniques as well.
 */
int
netsnmp_table_data2_helper_handler(netsnmp_mib_handler *handler,
                                  netsnmp_handler_registration *reginfo,
                                  netsnmp_agent_request_info *reqinfo,
                                  netsnmp_request_info *requests)
{
    netsnmp_table_data2 *table = (netsnmp_table_data2 *) handler->myvoid;
    netsnmp_request_info       *request;
    netsnmp_table_request_info *table_info;
    netsnmp_table_data2row          *row;

    switch ( reqinfo->mode ) {
    case MODE_GET:
    case MODE_SET_RESERVE1:

        for (request = requests; request; request = request->next) {
            if (request->processed)
                continue;
    
            table_info = netsnmp_extract_table_info(request);
            if (!table_info)
                continue;           /* ack */
            row = netsnmp_container_table_row_extract( request );

            netsnmp_request_add_list_data(request,
                                      netsnmp_create_data_list(
                                          TABLE_DATA2_TABLE, table, NULL));
            netsnmp_request_add_list_data(request,
                                      netsnmp_create_data_list(
                                          TABLE_DATA2_ROW,   row,   NULL));
        }
    }

    /* next handler called automatically - 'AUTO_NEXT' */
    return SNMP_ERR_NOERROR;
}

/** creates and returns a pointer to table data set */
netsnmp_table_data2 *
netsnmp_create_table_data2(const char *name)
{
    netsnmp_table_data2 *table = SNMP_MALLOC_TYPEDEF(netsnmp_table_data2);
    if ( !table )
        return NULL;

    if (name)
        table->name = strdup(name);
    table->container = netsnmp_container_find( "table_container" );
    return table;
}

/** creates and returns a pointer to table data set */
netsnmp_table_data2row *
netsnmp_create_table_data2_row(void)
{
    netsnmp_table_data2row *row = SNMP_MALLOC_TYPEDEF(netsnmp_table_data2row);
    return row;
}

/** inserts a newly created table_data2 row into a request */
NETSNMP_INLINE void
netsnmp_insert_table_data2row(netsnmp_request_info *request,
                         netsnmp_table_data2row *row)
{
    netsnmp_container_table_row_insert(request, (netsnmp_index *)row);
}

/** extracts the row being accessed passed from the table_data2 helper */
netsnmp_table_data2row *
netsnmp_extract_table_data2row(netsnmp_request_info *request)
{
    return (netsnmp_table_data2row *) netsnmp_container_table_row_extract(request);
}

/** extracts the table being accessed passed from the table_data2 helper */
netsnmp_table_data2 *
netsnmp_extract_table_data2(netsnmp_request_info *request)
{
    return (netsnmp_table_data2 *) netsnmp_request_get_list_data(request,
                                                               TABLE_DATA2_TABLE);
}

/** extracts the data from the row being accessed passed from the
 * table_data2 helper */
void           *
netsnmp_extract_table_data2row_data2(netsnmp_request_info *request)
{
    netsnmp_table_data2row *row;
    row = (netsnmp_table_data2row *) netsnmp_extract_table_data2row(request);
    if (row)
        return row->data;
    else
        return NULL;
}

/* builds a result given a row, a varbind to set and the data
   OBSOLETE */
int
netsnmp_table_data2_build_result(netsnmp_handler_registration *reginfo,
                                netsnmp_agent_request_info *reqinfo,
                                netsnmp_request_info *request,
                                netsnmp_table_data2row *row,
                                int column,
                                u_char type,
                                u_char * result_data2,
                                size_t result_data2_len)
{
    oid             build_space[MAX_OID_LEN];
    if (!reginfo || !reqinfo || !request)
        return SNMPERR_GENERR;

    if (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GETBULK) {
        /*
         * only need to do this for getnext type cases where oid is changing 
         */
        memcpy(build_space, reginfo->rootoid,   /* registered oid */
               reginfo->rootoid_len * sizeof(oid));
        build_space[reginfo->rootoid_len] = 1;  /* entry */
        build_space[reginfo->rootoid_len + 1] = column; /* column */
        memcpy(build_space + reginfo->rootoid_len + 2,  /* index data */
               row->oid_index.oids, row->oid_index.len * sizeof(oid));
        snmp_set_var_objid(request->requestvb, build_space,
                           reginfo->rootoid_len + 2 + row->oid_index.len);
    }
    snmp_set_var_typed_value(request->requestvb, type,
                             result_data2, result_data2_len);
    return SNMPERR_SUCCESS;     /* WWWXXX: check for bounds */

    netsnmp_assert("netsnmp_table_data2_build_result" == "implemented");
    return SNMPERR_GENERR;
}

/** clones a data row. DOES NOT CLONE THE CONTAINED DATA. */
netsnmp_table_data2row *
netsnmp_table_data2_clone_row(netsnmp_table_data2row *row)
{
    netsnmp_table_data2row *newrow = NULL;
    if (!row)
        return NULL;

    memdup((u_char **) & newrow, (u_char *) row,
           sizeof(netsnmp_table_data2row));
    if (!newrow)
        return NULL;

    if (row->indexes) {
        newrow->indexes = snmp_clone_varbind(newrow->indexes);
        if (!newrow->indexes)
            return NULL;
    }

    if (row->oid_index.oids) {
        memdup((u_char **) & newrow->oid_index.oids,
               (u_char *) row->oid_index.oids,
               row->oid_index.len * sizeof(oid));
        if (!newrow->oid_index.oids)
            return NULL;
    }

    return newrow;
}

int
netsnmp_table_data2_num_rows(netsnmp_table_data2 *table)
{
    if (!table)
        return 0;
    return CONTAINER_SIZE( table->container );
}
/*
 * @} 
 */
