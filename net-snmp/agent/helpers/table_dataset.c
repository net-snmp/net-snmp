#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "table.h"
#include "table_data.h"
#include "table_dataset.h"
#include "parse.h"
#include "data_list.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

static data_list *auto_tables;

typedef struct data_set_tables_s {
   table_data_set *table_set;
} data_set_tables;

typedef struct data_set_cache_s {
   void *data;
   size_t data_len;
} data_set_cache;

/** Create a table_data_set structure given a table_data definition */
table_data_set *
create_table_data_set(const char *table_name) 
{
    table_data_set *table_set = SNMP_MALLOC_TYPEDEF(table_data_set);
    table_set->table = create_table_data(table_name);
    return table_set;
}

/** Given a table_data_set definition, create a handler for it */
mib_handler *
get_table_data_set_handler(table_data_set *data_set)
{
    mib_handler *ret = NULL;

    if (!data_set) {
        snmp_log(LOG_INFO, "get_table_data_set_handler(NULL) called\n");
        return NULL;
    }
    
    ret = create_handler(TABLE_DATA_SET_NAME, table_data_set_helper_handler);
    if (ret) {
        ret->myvoid = (void *) data_set;
    }
    return ret;
}


/** register a given data_set at a given oid (specified in the
    handler_registration pointer).  The
    reginfo->handler->access_method *may* be null if the call doesn't
    ever want to be called for SNMP operations.
*/
int
register_table_data_set(handler_registration *reginfo, table_data_set *data_set,
                        table_registration_info *table_info)
{
    if (NULL == table_info) {
        /* allocate the table if one wasn't allocated */
        table_info = SNMP_MALLOC_TYPEDEF(table_registration_info);
    }

    if (NULL == table_info->indexes && data_set->table->indexes_template) {
        /* copy the indexes in */
        table_info->indexes =
            snmp_clone_varbind(data_set->table->indexes_template);
    }
    
    if ((!table_info->min_column || !table_info->max_column) &&
        (data_set->default_row)) {
        /* determine min/max columns */
        unsigned int mincol = 0xffffffff, maxcol = 0;
        table_data_set_storage *row;
        
        for(row = data_set->default_row; row; row = row->next) {
            mincol = SNMP_MIN(mincol, row->column);
            maxcol = SNMP_MAX(maxcol, row->column);
        }
        if (!table_info->min_column)
            table_info->min_column = mincol;
        if (!table_info->max_column)
            table_info->max_column = maxcol;
    }

    inject_handler(reginfo, get_table_data_set_handler(data_set));
    return register_table_data(reginfo, data_set->table, table_info);
}

/** Finds a column within a given storage set, given the pointer to
   the start of the storage set list.
*/
table_data_set_storage *
table_data_set_find_column(table_data_set_storage *start, int column) 
{
    while(start && start->column != column)
        start = start->next;
    return start;
}

/**
 * extracts a table_data_set pointer from a given request
 */
inline table_data_set *
extract_table_data_set(request_info *request)
{
    return (table_data_set *)
        request_get_list_data(request, TABLE_DATA_SET_NAME);
}

/**
 * marks a given column in a row as writable or not.
 */
int
mark_row_column_writable(table_row *row, int column, int writable) 
{
    table_data_set_storage *data = (table_data_set_storage *) row->data;
    data = table_data_set_find_column(data, column);

    if (!data) {
        /* create it */
        data = SNMP_MALLOC_TYPEDEF(table_data_set_storage);
        if (!data) {
            snmp_log(LOG_CRIT, "no memory in set_row_column");
            return SNMPERR_MALLOC;
        }
        data->column = column;
        data->writable = writable;
        data->next = row->data;
        row->data = data;
    } else {
        data->writable = writable;
    }
    return SNMPERR_SUCCESS;
}


/**
 * sets a given column in a row with data given a type, value, and
 * length.  Data is memdup'ed by the function.
 */
int
set_row_column(table_row *row, unsigned int column, int type,
               const char *value, size_t value_len) 
{
    table_data_set_storage *data = (table_data_set_storage *) row->data;
    data = table_data_set_find_column(data, column);

    if (!data) {
        /* create it */
        data = SNMP_MALLOC_TYPEDEF(table_data_set_storage);
        if (!data) {
            snmp_log(LOG_CRIT, "no memory in set_row_column");
            return SNMPERR_MALLOC;
        }
        
        data->column = column;
        data->type = type;
        data->next = row->data;
        row->data = data;
    }
    
    if (data) {
        if (data->type != type)
            return SNMPERR_GENERR;
        
        SNMP_FREE(data->data.voidp);
        if (memdup(&data->data.string, value, value_len) != SNMPERR_SUCCESS) {
            snmp_log(LOG_CRIT, "no memory in set_row_column");
            return SNMPERR_MALLOC;
        }
        data->data_len = value_len;
    }
    return SNMPERR_SUCCESS;
}

/**
 * adds a new default row to a table_set.
 * returns SNMPERR_SUCCESS or SNMPERR_FAILURE
 */
int
table_set_add_default_row(table_data_set *table_set, unsigned int column,
                          int type, int writable) 
{
    
    table_data_set_storage *new_col, *ptr;

    /* double check */
    new_col = table_data_set_find_column(table_set->default_row, column);
    if (new_col != NULL) {
        if (new_col->type == type &&
            new_col->writable == writable)
            return SNMPERR_SUCCESS;
        return SNMPERR_GENERR;
    }

    new_col = SNMP_MALLOC_TYPEDEF(table_data_set_storage);
    new_col->type = type;
    new_col->writable = writable;
    new_col->column = column;
    if (table_set->default_row == NULL)
        table_set->default_row = new_col;
    else {
        for(ptr = table_set->default_row; ptr->next; ptr = ptr->next) {
        }
        ptr->next = new_col;
    }
    return SNMPERR_SUCCESS;
}

int
table_data_set_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    table_data_set_storage *data = NULL;
    table_row *row;
    table_request_info *table_info;
    data_set_cache *cache;
    request_info *request;

    DEBUGMSGTL(("table_data_set", "handler starting"));
    for(request = requests; request; request = request->next) {
        if (request->processed)
            continue;

        /* extract our stored data and table info */
        row = extract_table_row(request);
        table_info = extract_table_info(request);

        if (row)
            data = (table_data_set_storage *) row->data;
        if (!row || !table_info || !data) {
            if (MODE_IS_SET(reqinfo->mode)) {
                /* ack */
                /* XXXWWW creation */
                set_request_error(reqinfo, request, SNMP_ERR_NOSUCHNAME);
            }
            continue;
        }

        data = table_data_set_find_column(data, table_info->colnum);

        switch(reqinfo->mode) {
            case MODE_GET:
            case MODE_GETNEXT:
            case MODE_GETBULK: /* XXXWWW */
                if (!data) {
                    table_row *newrow;
                    table_data_set_storage *newdata = NULL;
                    int column = table_info->colnum;
                    table_data_set *datatable =
                        (table_data_set *) handler->myvoid;

                    while(column <= table_info->reg_info->max_column) {
                        if (column != table_info->colnum) {
                            /* start with a new row */
                            row = datatable->table->first_row;
                        }
                        for(newrow = row; newrow; newrow = newrow->next) {
                            newdata = (table_data_set_storage *) newrow->data;
                            if (newdata)
                                newdata =
                                    table_data_set_find_column(newdata,
                                                               column);
                            if (newdata) {
                                /* this is it */
                                data = newdata;
                                row = newrow;
                                table_info->colnum = column;
                                goto done;
                            }
                        }
                        column++;
                    }
                }
          done:
                if (data)
                    table_data_build_result(reginfo, reqinfo, request, row,
                                            table_info->colnum,
                                            data->type,
                                            data->data.voidp, data->data_len);
                else {
                    /* deal with holes by going to the next data set
                       in the row or possibly onward to new columns */
                    snmp_log(LOG_ERR, "ack\n");
                }
                break;

            case MODE_SET_RESERVE1:
                if (data) {
                    /* modify existing */
                    if (!data->writable) {
                        set_request_error(reqinfo, request,
                                          SNMP_ERR_NOTWRITABLE);
                    } else if (request->requestvb->type != data->type) {
                        set_request_error(reqinfo, request,
                                          SNMP_ERR_WRONGTYPE);
                    }
                } else {
                    /* XXXWWW: create data, possibly new row */
                }
                break;

            case MODE_SET_RESERVE2:
                if (data) {
                    /* cache old data for later undo */
                    cache = SNMP_MALLOC_TYPEDEF(data_set_cache);
                    if (!cache) {
                        set_request_error(reqinfo, request,
                                          SNMP_ERR_RESOURCEUNAVAILABLE);
                    } else {
                        cache->data = data->data.voidp;
                        cache->data_len = data->data_len;
                        request_add_list_data(request, create_data_list(TABLE_DATA_SET_NAME, cache, free));
                    }
                } else {
                    /* XXXWWW */
                }
                break;

            case MODE_SET_ACTION:
                if (data) {
                    memdup(&data->data.string, request->requestvb->val.string,
                           request->requestvb->val_len);
                    data->data_len = request->requestvb->val_len;
                } else {
                    /* XXXWWW */
                }
                break;
                
            case MODE_SET_UNDO:
                SNMP_FREE(data->data.voidp);
                
                cache = (data_set_cache *)
                    request_get_list_data(request, TABLE_DATA_SET_NAME);
                data->data.voidp = cache->data;
                data->data_len = cache->data_len;
                /* the cache itself is automatically freed by the
                   data_list routines */
                break;

            case MODE_SET_COMMIT:
                cache = (data_set_cache *)
                    request_get_list_data(request, TABLE_DATA_SET_NAME);
                SNMP_FREE(cache->data);
                break;

            case MODE_SET_FREE:
                /* nothing to do */
                break;
        }
    }

    if (handler->next && handler->next->access_method)
        call_next_handler(handler, reginfo, reqinfo, requests);
    return SNMP_ERR_NOERROR;
}
    
void
config_parse_table_set(const char *token, char *line) 
{
    oid name[MAX_OID_LEN], table_name[MAX_OID_LEN];
    size_t name_length = MAX_OID_LEN, table_name_length = MAX_OID_LEN;
    struct tree *tp, *indexnode;
    table_data_set *table_set;
    struct index_list *index;
    unsigned int mincol = 0xffffff, maxcol = 0;
    data_set_tables *tables;
    int type;
    
    /* instatiate a fake table based on MIB information */
    if (!snmp_parse_oid(line, table_name, &table_name_length) ||
        (NULL == (tp = get_tree(table_name, table_name_length,
                                get_tree_head())))) {
        config_pwarn("can't instatiate table %s since I can't find mib information about it\n");
        return;
    }

    if (NULL == (tp = tp->child_list) ||
        NULL == tp->child_list) {
        config_pwarn("can't instatiate table since it doesn't appear to be a proper table\n");
        return;
    }

    table_set = create_table_data_set(line);

    /* loop through indexes and add types */
    for(index = tp->indexes; index; index = index->next) {
        if (!snmp_parse_oid(index->ilabel, name, &name_length) ||
            (NULL == (indexnode = get_tree(name, name_length, get_tree_head())))) {
            config_pwarn("can't instatiate table %s since I don't know anything about one index\n");
            return; /* xxx mem leak */
        }

        type = mib_to_asn_type(indexnode->type);
        if (type == -1) {
            config_pwarn("unknown index type");
            return; /* xxx mem leak */
        }
        if (index->isimplied) /* if implied, mark it as such */
            type |= ASN_PRIVATE;
            
        DEBUGMSGTL(("table_set_add_row","adding default index of type %d\n",
                    type));
        table_dataset_add_index(table_set, type);
    }

    /* loop through children and add each column info */
    for(tp = tp->child_list; tp; tp = tp->next_peer) {
        int canwrite = 0;
        type = mib_to_asn_type(tp->type);
        if (type == -1) {
            config_pwarn("unknown column type");
            return; /* xxx mem leak */
        }
        
        DEBUGMSGTL(("table_set_add_row","adding column %d of type %d\n",
                    tp->subid, type));

        switch (tp->access) {
            case MIB_ACCESS_CREATE:
            case MIB_ACCESS_READWRITE:
            case MIB_ACCESS_WRITEONLY:
                canwrite = 1;
            case MIB_ACCESS_READONLY:
                DEBUGMSGTL(("table_set_add_row","adding column %d of type %d\n",
                            tp->subid, type));
                table_set_add_default_row(table_set, tp->subid, type, canwrite);
                mincol = SNMP_MIN(mincol, tp->subid);
                maxcol = SNMP_MAX(maxcol, tp->subid);
                break;

            case MIB_ACCESS_NOACCESS:
            case MIB_ACCESS_NOTIFY:
                break;

            default:
                config_pwarn("unknown column access type");
                break;
        }
    }

    /* register the table */
    register_table_data_set(
        create_handler_registration(line, NULL, table_name, table_name_length,
                                    HANDLER_CAN_RWRITE),
        table_set, NULL);

    tables = SNMP_MALLOC_TYPEDEF(data_set_tables);
    tables->table_set = table_set;
    add_list_data(&auto_tables, create_data_list(line, tables, NULL));
}

void
config_parse_add_row(const char *token, char *line) 
{
    char buf[SNMP_MAXBUF_MEDIUM];
    char tname[SNMP_MAXBUF_MEDIUM];
    size_t buf_size;

    data_set_tables *tables;
    struct variable_list *vb; /* containing only types */
    table_row *row;
    table_data_set_storage *dr;
    
    line = copy_nword(line, tname, SNMP_MAXBUF_MEDIUM);

    tables = (data_set_tables *) get_list_data(auto_tables, tname);
    if (!tables) {
        config_pwarn("Unknown table trying to add a row");
        return;
    }

    /* do the indexes first */
    row = create_table_data_row();

    for(vb = tables->table_set->table->indexes_template; vb;
        vb = vb->next_variable) {
        if (!line) {
            config_pwarn("missing an index value");
            return;
        }
        
        DEBUGMSGTL(("table_set_add_row","adding index of type %d\n", vb->type));
        buf_size = SNMP_MAXBUF_MEDIUM;
        line = read_config_read_memory(vb->type, line, buf, &buf_size);
        table_row_add_index(row, vb->type, buf, buf_size);
    }

    /* then do the data */
    for(dr = tables->table_set->default_row; dr; dr = dr->next) {
        if (!line) {
            config_pwarn("missing an data value\n");
            return;
        }
        
        buf_size = SNMP_MAXBUF_MEDIUM;
        line = read_config_read_memory(dr->type, line, buf, &buf_size);
        DEBUGMSGTL(("table_set_add_row","adding data at column %d of type %d\n", dr->column, dr->type));
        set_row_column(row, dr->column, dr->type, buf, buf_size);
        if (dr->writable)
            mark_row_column_writable(row, dr->column, 1); /* make writable */
    }
    table_data_add_row(tables->table_set->table, row);
}

inline void table_dataset_add_index(table_data_set *table, int type) 
{
    table_data_add_index(table->table, type);
}

inline void table_dataset_add_row(table_data_set *table, table_row *row)
{
    table_data_add_row(table->table, row);
}

    
