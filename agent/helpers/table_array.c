/* 
 * table_array.c
 * $Id$
 */

#include <net-snmp/net-snmp-config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <assert.h>

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/table.h>
#include <net-snmp/agent/table_array.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

/* snmp.h:#define SNMP_MSG_INTERNAL_SET_BEGIN        -1 */
/* snmp.h:#define SNMP_MSG_INTERNAL_SET_RESERVE1     0 */
/* snmp.h:#define SNMP_MSG_INTERNAL_SET_RESERVE2     1 */
/* snmp.h:#define SNMP_MSG_INTERNAL_SET_ACTION       2 */
/* snmp.h:#define SNMP_MSG_INTERNAL_SET_COMMIT       3 */
/* snmp.h:#define SNMP_MSG_INTERNAL_SET_FREE         4 */
/* snmp.h:#define SNMP_MSG_INTERNAL_SET_UNDO         5 */

                            
static const char *mode_name[] = {
    "Reserve 1",
    "Reserve 2",
    "Action",
    "Commit",
    "Free",
    "Undo"
};

/*
 * structure for holding important info for each table.
 */
typedef struct table_array_data_s {
    netsnmp_table_registration_info * tblreg_info;
    oid_array                 array;

    /*    mutex_type                lock;*/
    oid_array                 changing;

    int                       group_rows;

    netsnmp_table_array_callbacks     *cb;

} table_array_data;

/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * PUBLIC Registration functions                                      *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
int
netsnmp_register_table_array(netsnmp_handler_registration *reginfo,
                     netsnmp_table_registration_info *tabreg,
                     netsnmp_table_array_callbacks   *cb,
                     int                     group_rows)
{
    table_array_data * tad = SNMP_MALLOC_TYPEDEF(table_array_data);
    tad->tblreg_info = tabreg; /* we need it too, but it really is not ours */
    tad->array = netsnmp_Initialise_oid_array( sizeof(void*) );
    /* netsnmp_mutex_init(&tad->lock); */
    tad->changing = netsnmp_Initialise_oid_array( sizeof(void*) );
    tad->cb = cb;

    reginfo->handler->myvoid = tad;

    return netsnmp_register_table(reginfo, tabreg);
}

netsnmp_mib_handler*
find_table_array_handler(netsnmp_handler_registration *reginfo)
{
    netsnmp_mib_handler *mh = reginfo->handler;
    while( mh ) {
        if(mh->access_method == netsnmp_table_array_helper_handler)
            break;
        mh = mh->next;
    }

    return mh;
}

oid_array *
netsnmp_extract_array_context(netsnmp_request_info *request) 
{
    return netsnmp_request_netsnmp_get_list_data(request, TABLE_ARRAY_NAME);
}

const netsnmp_oid_array_header*
netsnmp_table_array_get_by_index(netsnmp_handler_registration *reginfo,
                         netsnmp_oid_array_header * hdr)
{
    table_array_data* tad;
    netsnmp_oid_array_header *rtn = NULL;
    netsnmp_mib_handler *mh;
    
    if(reginfo == NULL)
        return NULL;

    mh = find_table_array_handler(reginfo);
    if( mh == NULL)
      return NULL;

    tad = (table_array_data*)mh->myvoid;
    if(tad == NULL || tad->array == NULL)
      return NULL;

    /* netsnmp_mutex_lock(&tad->lock);*/

    if(tad->changing && netsnmp_Get_oid_data_count(tad->changing)) {
        rtn = netsnmp_Get_oid_data( tad->changing, hdr, 1 );
        if(!rtn)
            rtn = netsnmp_Get_oid_data( tad->array, hdr, 1 );
    }
    else {
        rtn = netsnmp_Get_oid_data( tad->array, hdr, 1 );
    }

    /* netsnmp_mutex_unlock(&tad->lock);*/

    return rtn;
}

const netsnmp_oid_array_header**
netsnmp_table_array_get_subset(netsnmp_handler_registration *reginfo,
                       netsnmp_oid_array_header * hdr, int * len)
{
    table_array_data* tad;
    const netsnmp_oid_array_header **rtn = NULL;
    netsnmp_mib_handler *mh;
    
    if(reginfo == NULL)
        return NULL;

    mh = find_table_array_handler(reginfo);
    if( mh == NULL)
      return NULL;
    
    tad = (table_array_data*)mh->myvoid;
    if(!tad->array)
        return NULL;

    /* netsnmp_mutex_lock(&tad->lock);*/

    /* I really really don't want to merge two tables. so just freak
       out if this is called during a set. */
    assert( !tad->changing || netsnmp_Get_oid_data_count(tad->changing) == 0);

    rtn = (const netsnmp_oid_array_header**)netsnmp_Get_oid_data_subset( tad->array, hdr, len );

    /* netsnmp_mutex_unlock(&tad->lock);*/

    return rtn;
}

int
ta_check_row_status(netsnmp_table_array_callbacks *cb, netsnmp_oid_array_header* ctx_new,
                    netsnmp_oid_array_header* ctx_old, netsnmp_array_group* ag,
                    int* rs_new, int* rs_old)
{
    if (ctx_new) {
        /*
         * either a new row, or change to old row
         */
        int row_ready = cb->can_activate ? cb->can_activate(ctx_old, ctx_new, ag) : 1;

        /*
         * is it set to active?
         */
        if (RS_IS_GOING_ACTIVE(*rs_new)) {
            /*
             * is it ready to be active?
             */
            if (row_ready)
                *rs_new = RS_ACTIVE;
            else
                return SNMP_ERR_INCONSISTENTVALUE;
        }
        else {
            if (ctx_old) {
                /*
                 * change
                 */
                if (RS_IS_ACTIVE(*rs_old)) {
                    /*
                     * check preqs for deactivation
                     */
                    if (cb->can_deactivate && !cb->can_deactivate(ctx_old, ctx_new, ag)) {
                        return SNMP_ERR_INCONSISTENTVALUE;
                    }
                }
            }
            else {
                /*
                 * new row
                 */
            }

            *rs_new = row_ready ? RS_NOTINSERVICE : RS_NOTREADY;
        }
    } else {
        /*
         * check pre-reqs for delete row
         */
        if (cb->can_delete && !cb->can_delete(ctx_old, ctx_new, ag)) {
            return SNMP_ERR_INCONSISTENTVALUE;
        }
    }

    return SNMP_ERR_NOERROR;
}

/**********************************************************************
 **********************************************************************
 **********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 *                                                                    *
 *                                                                    *
 * EVERYTHING BELOW THIS IS PRIVATE IMPLEMENTATION DETAILS.           *
 *                                                                    *
 *                                                                    *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************
 **********************************************************************
 **********************************************************************/

/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * Structures, Utility/convenience functions                          *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
/*
 * context info for SET requests
 */
typedef struct set_context_s {
    netsnmp_agent_request_info *agtreq_info;
    table_array_data   *tad;
    int                status;
} set_context;

static void
release_netsnmp_array_group( netsnmp_oid_array_header * g, void *v )
{
    netsnmp_array_group_item *tmp;
    netsnmp_array_group * group = (netsnmp_array_group*)g;

    while(group->list) {
        tmp = group->list;
        group->list = tmp->next;
        free(tmp);
    }

    free( group );
}

static void
release_netsnmp_array_groups( void * vp )
{
    oid_array a = (oid_array)vp;
    netsnmp_For_each_oid_data( a, release_netsnmp_array_group, NULL, 0 );
}

inline netsnmp_oid_array_header *
find_next_row( netsnmp_table_request_info *tblreq_info, table_array_data *tad)
{
    netsnmp_oid_array_header *row = NULL;
    netsnmp_oid_array_header index;

    /*
     * below our minimum column?
     */
    if (tblreq_info->colnum < tad->tblreg_info->min_column) {
        tblreq_info->colnum = tad->tblreg_info->min_column;
        row = netsnmp_Get_oid_data( tad->array, NULL, 0 );
    }
    else {
        index.idx = tblreq_info->index_oid;
        index.idx_len = tblreq_info->index_oid_len;

        row = netsnmp_Get_oid_data( tad->array, &index, 0 );

        /*
         * we don't have a row, but we might be at the end of a
         * column, so try the next one.
         */
        if (!row) {
            ++tblreq_info->colnum;
            if(tad->tblreg_info->valid_columns) {
                tblreq_info->colnum = netsnmp_closest_column
                    (tblreq_info->colnum,
                     tad->tblreg_info->valid_columns);
            }
            else if(tblreq_info->colnum > tad->tblreg_info->max_column)
                tblreq_info->colnum = 0;
            
            if(tblreq_info->colnum != 0)
                row = netsnmp_Get_oid_data( tad->array, NULL, 0 );
        }
    }

    return row;
}

inline void
build_new_oid( netsnmp_handler_registration *reginfo,
               netsnmp_table_request_info   *tblreq_info,
               netsnmp_oid_array_header     *row,
               netsnmp_request_info         *current )
{
    oid coloid[MAX_OID_LEN];
    int coloid_len;        

    coloid_len = reginfo->rootoid_len+2;
    memcpy(coloid, reginfo->rootoid, reginfo->rootoid_len * sizeof(oid));

    /** table.entry */
    coloid[reginfo->rootoid_len] = 1;

    /** table.entry.column */
    coloid[reginfo->rootoid_len+1] = tblreq_info->colnum;

    /** table.entry.column.index */
    memcpy(&coloid[reginfo->rootoid_len+2], row->idx,
           row->idx_len * sizeof(oid));

    snmp_set_var_objid(current->requestvb, coloid,
                       reginfo->rootoid_len + 2 + row->idx_len);
}

/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * GET procession functions                                           *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
inline int
process_get_requests(netsnmp_handler_registration  *reginfo,
                     netsnmp_agent_request_info    *agtreq_info,
                     netsnmp_request_info          *requests,
                     table_array_data      *tad )
{
    int rc = SNMP_ERR_NOERROR;
    netsnmp_request_info * current;
    netsnmp_oid_array_header *row = NULL;
    netsnmp_table_request_info *tblreq_info;
    netsnmp_variable_list * var;

    /*
     * Loop through each of the requests, and
     * try to find the appropriate row from the oid_array.
     */
    for( current = requests; current; current = current->next) {

        var = current->requestvb;
        DEBUGMSGTL(("helper:table_array:get", "  process_get_request oid:"));
        DEBUGMSGOID(("helper:table_array:get", var->name, var->name_length));
        DEBUGMSG(("helper:table_array:get", "\n"));

        /*
         * skip anything that doesn't need processing.
         */
        if (current->processed != 0) {
            DEBUGMSGTL(("helper:table_array:get", "already processed\n"));
            continue;
        }

        /* 
         * Get pointer to the table information for this request. This
         * information was saved by table_helper_handler. When
         * debugging, we double check a few assumptions. For example,
         * the table_helper_handler should enforce column boundaries.
         */
        tblreq_info = netsnmp_extract_table_info(current);
        assert(tblreq_info->colnum <= tad->tblreg_info->max_column);
        
        if((agtreq_info->mode == MODE_GETNEXT) ||
           (agtreq_info->mode == MODE_GETBULK)) {
            /*
             * find the row
             */
            row = find_next_row(tblreq_info, tad);
            if (!row) {
                /*
                 * no results found.
                 *
                 * xxx-rks: how do we skip this entry for the next handler,
                 * but still allow it a chance to hit another handler?
                 */
                DEBUGMSGTL(("helper:table_array:get", "no row found\n"));
                continue;
            }
        
			/*
             * if data was found, make sure it has the column we want
             */
#ifndef WIN32
#pragma warning "xxx-rks: add suport for sparse tables"
#endif

            /*
             * build new oid
             */
            build_new_oid( reginfo, tblreq_info, row, current );

        } /** GETNEXT/GETBULK */
        else {
            netsnmp_oid_array_header index;
            index.idx = tblreq_info->index_oid;
            index.idx_len = tblreq_info->index_oid_len;

            row = netsnmp_Get_oid_data( tad->array, &index, 1 );
            if(!row) {
                DEBUGMSGTL(("helper:table_array:get", "no row found\n"));
                netsnmp_set_request_error(agtreq_info, current, SNMP_ERR_NOSUCHNAME);
                continue;
            }
        } /** GET */

        /*
         * get the data
         */
        rc = tad->cb->get_value( current, row, tblreq_info );

    } /** for ( ... requests ... ) */

    return rc;
}

/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * SET procession functions                                           *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
inline void
group_requests( netsnmp_agent_request_info *agtreq_info, netsnmp_request_info * requests,
                oid_array netsnmp_array_group_tbl, table_array_data *tad )
{
    netsnmp_table_request_info *tblreq_info;
    netsnmp_variable_list * var;
    netsnmp_oid_array_header *row, *tmp, index;
    netsnmp_request_info * current;
    netsnmp_array_group * g;
    netsnmp_array_group_item * i;

    for( current = requests; current; current = current->next) {
            
        var = current->requestvb;
        /* don't log OID, helper:table already did it */
#if 0
        DEBUGMSGTL(("helper:table_array:group", "  oid:"));
        DEBUGMSGOID(("helper:table_array:group", var->name, var->name_length));
        DEBUGMSG(("helper:table_array:group", "\n"));
#endif
        /*
         * skip anything that doesn't need processing.
         */
        if (current->processed != 0) {
            DEBUGMSGTL(("helper:table_array:group", "already processed\n"));
            continue;
        }

        /* 3.2.1 Setup and paranoia
         *
         * Get pointer to the table information for this request. This
         * information was saved by table_helper_handler. When
         * debugging, we double check a few assumptions. For example,
         * the table_helper_handler should enforce column boundaries.
         */
        row = NULL;
        tblreq_info = netsnmp_extract_table_info(current);
        assert(tblreq_info->colnum <= tad->tblreg_info->max_column);
        
        /*
         * search for index
         */
        index.idx = tblreq_info->index_oid;
        index.idx_len = tblreq_info->index_oid_len;
        tmp = netsnmp_Get_oid_data( netsnmp_array_group_tbl, &index, 1);
        if(tmp) {
            DEBUGMSGTL(("helper:table_array:group", "    existing group:"));
            DEBUGMSGOID(("helper:table_array:group", index.idx,index.idx_len));
            DEBUGMSG(("helper:table_array:group", "\n"));
            g = (netsnmp_array_group*)tmp;
            i = SNMP_MALLOC_TYPEDEF(netsnmp_array_group_item);
            i->ri = current;
            i->tri = tblreq_info;
            i->next = g->list;
            g->list = i;
            continue;
        }

        DEBUGMSGTL(("helper:table_array:group", "    new group"));
        DEBUGMSGOID(("helper:table_array:group", index.idx,index.idx_len));
        DEBUGMSG(("helper:table_array:group", "\n"));
        g = SNMP_MALLOC_TYPEDEF(netsnmp_array_group);
        i = SNMP_MALLOC_TYPEDEF(netsnmp_array_group_item);
        g->list = i;
        g->table = tad->array;
        i->ri = current;
        i->tri = tblreq_info;

        /*
         * search for row
         */
        row = g->old_row = netsnmp_Get_oid_data( tad->array, &index, 1 );
        if(!g->old_row){
            if(! tad->cb->create_row) {
                netsnmp_set_request_error(agtreq_info, current, SNMP_ERR_NOSUCHNAME);
                free(g);
                free(i);
                continue;
            }

            row = g->new_row = tad->cb->create_row( &index );
            if( !row ) {
                netsnmp_set_request_error(agtreq_info, current, SNMP_ERR_GENERR);
                free(g);
                free(i);
                continue;
            }
        }

        g->index.idx = row->idx;
        g->index.idx_len = row->idx_len;

        netsnmp_Add_oid_data( netsnmp_array_group_tbl, g );

    } /** for( current ... ) */
}

void
process_set_group( netsnmp_oid_array_header* o, void *c )
{
#ifndef WIN32
#pragma warning "should we continue processing after an error??"
#endif
    set_context * context = (set_context *)c;
    netsnmp_array_group * ag = (netsnmp_array_group *)o;

    switch(context->agtreq_info->mode) {

    case MODE_SET_RESERVE1: /** -> SET_RESERVE2 || SET_FREE */
        if(context->tad->cb->set_reserve1)
            context->tad->cb->set_reserve1( ag );

        /*
         * create storage for new row
         */
        if(!ag->new_row && context->tad->cb->duplicate_row &&
           ag->status == SNMP_ERR_NOERROR) {
            ag->new_row = context->tad->cb->duplicate_row( ag->old_row );
            if(!ag->new_row) {
                netsnmp_set_mode_request_error(MODE_SET_BEGIN, ag->list->ri,
                                       SNMP_ERR_RESOURCEUNAVAILABLE);
                return;
            }
        }
        break;
        
    case MODE_SET_RESERVE2: /** -> SET_ACTION || SET_FREE */
        if(context->tad->cb->set_reserve2)
            context->tad->cb->set_reserve2( ag );
        break;
        
    case MODE_SET_ACTION: /** -> SET_COMMIT || SET_UNDO */
        if(ag->old_row) {
            /** remove or replace */
            if(ag->new_row) {
                netsnmp_Replace_oid_data(ag->table,ag->new_row);
            }
            else {
                netsnmp_Remove_oid_data(ag->table,ag->old_row,NULL);
            }
        }
        else {
            /** insert new row */
            netsnmp_Add_oid_data(ag->table,ag->new_row);
        }
        
        netsnmp_Add_oid_data(context->tad->changing,ag->new_row);
        if(context->tad->cb->set_action)
            context->tad->cb->set_action( ag );
        break;
        
    case MODE_SET_COMMIT: /** FINAL CHANCE ON SUCCESS */
        if(context->tad->cb->set_commit)
            context->tad->cb->set_commit( ag );

        /** old row inserted in action, so delete old one */
        if(ag->old_row && context->tad->cb->delete_row) {
            context->tad->cb->delete_row(ag->old_row);
            ag->old_row = NULL;
        }
        netsnmp_Remove_oid_data(context->tad->changing,ag->new_row,NULL);
        break;
        
    case MODE_SET_FREE: /** FINAL CHANCE ON FAILURE */
        if(context->tad->cb->set_free)
            context->tad->cb->set_free( ag );

        if(ag->old_row && context->tad->cb->delete_row) {
            context->tad->cb->delete_row(ag->new_row);
            ag->new_row = NULL;
        }
        break;
        
    case MODE_SET_UNDO: /** FINAL CHANCE ON FAILURE */
        if(ag->new_row) {
            /** remove or replace */
            if(ag->old_row) {
                netsnmp_Replace_oid_data(ag->table,ag->old_row);
            }
            else {
                netsnmp_Remove_oid_data(ag->table,ag->new_row,NULL);
            }
        }
        else {
            /** there better be an old row! */
            assert(ag->old_row != NULL);
            /** insert old row */
            netsnmp_Add_oid_data(ag->table,ag->old_row);
        }
        /** status already set - don't change it now */
        if(context->tad->cb->set_undo)
            context->tad->cb->set_undo( ag );

        if(ag->new_row && context->tad->cb->delete_row) {
            context->tad->cb->delete_row(ag->new_row);
            ag->new_row = NULL;
        }
        break;
        
    default:
        snmp_log(LOG_ERR, "unknown mode processing SET for "
                 "netsnmp_table_array_helper_handler\n");
        /**context->status = SNMP_ERR_GENERR*/;
        break;
    }

}

inline int
process_set_requests( netsnmp_agent_request_info *agtreq_info,
                      netsnmp_request_info       *requests,
                      table_array_data   *tad,
                      char               *handler_name)
{
    set_context context;
    oid_array netsnmp_array_group_tbl;

    /*
     * create and save structure for set info
     */
    netsnmp_array_group_tbl = (oid_array)netsnmp_agent_netsnmp_get_list_data
        (agtreq_info, handler_name);
    if(netsnmp_array_group_tbl == NULL) {
        netsnmp_data_list *tmp;
        netsnmp_array_group_tbl = netsnmp_Initialise_oid_array( sizeof(void*) );

        DEBUGMSGTL(("helper:table_array", "Grouping requests by oid\n"));

        tmp = netsnmp_create_netsnmp_data_list(handler_name,
                               netsnmp_array_group_tbl,
                               release_netsnmp_array_groups);
        netsnmp_agent_netsnmp_add_list_data(agtreq_info, tmp);
        /*
         * group requests.
         */
        group_requests( agtreq_info, requests, netsnmp_array_group_tbl, tad );
    }

    /*
     * process each group one at a time
     */
    context.agtreq_info = agtreq_info;
    context.tad = tad;
    context.status = SNMP_ERR_NOERROR;
    netsnmp_For_each_oid_data( netsnmp_array_group_tbl, process_set_group, &context, 0 );

    return context.status;
}


/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * netsnmp_table_array_helper_handler()                                       *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
int
netsnmp_table_array_helper_handler(
    netsnmp_mib_handler               *handler,
    netsnmp_handler_registration      *reginfo,
    netsnmp_agent_request_info        *agtreq_info,
    netsnmp_request_info              *requests) {
  
    /*
     * First off, get our pointer from the handler. This
     * lets us get to the table registration information we
     * saved in get_table_array_handler(), as well as the
     * oid_array where the actual table data is stored.
     */
    int rc = SNMP_ERR_NOERROR;
    table_array_data * tad = (table_array_data*)handler->myvoid;

    if( agtreq_info->mode < 0 || agtreq_info->mode > 5 ) {
        DEBUGMSGTL(("helper:table_array", "Mode %d, Got request:\n",
                    agtreq_info->mode));
    }
    else {
        DEBUGMSGTL(("helper:table_array", "Mode %s, Got request:\n",
                    mode_name[agtreq_info->mode]));
    }

    /*
     * 3.1.1
     *
     * This handler will be called 1 time for any type of GET
     * request, but will be called multiple times for SET
     * requests. We don't need to find each row for every
     * pass of the SET processing, so we'll cache results.
     */
    if(MODE_IS_SET(agtreq_info->mode)) {
        /* netsnmp_mutex_lock(&tad->lock);*/
        rc = process_set_requests( agtreq_info, requests,
                                   tad, handler->handler_name );
        /* netsnmp_mutex_unlock(&tad->lock);*/
    }
    else
        rc = process_get_requests( reginfo, agtreq_info, requests, tad );

    /*
     * Now we should have row pointers for each request. Call the
     * next handler to process the row.
     *
     * rc = netsnmp_call_next_handler(handler, reginfo, agtreq_info, requests);
     */

    return rc;
}
