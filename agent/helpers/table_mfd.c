/*
 * $Id$
 */
/*
 * standard Net-SNMP includes 
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/table_mfd.h>

/**********************************************************************
 *
 * typedefs
 *
 */
#if 0 /* were these ever used?? */
typedef struct netsnmp_mfd_container_s {
   netsnmp_container *original_container; /* original */
} netsnmp_mfd_container;

typedef struct mfd_context_s {
   netsnmp_index    idx;
   oid              idx_oid[MAX_OID_LEN];
   netsnmp_ref_void tbl_ctx;
   netsnmp_ref_void data;
} mfd_ctx;
#endif



/**********************************************************************
 *
 * Prototypes
 *
 */
static int
netsnmp_mfd_helper_handler(netsnmp_mib_handler *handler,
                           netsnmp_handler_registration *reginfo,
                           netsnmp_agent_request_info *reqinfo,
                           netsnmp_request_info *requests);

/*
 * Modes
 */
static netsnmp_request_group *
_mfd_data_lookup(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_request_info *requests);

static netsnmp_request_group *
_mfd_data_find(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_request_info *requests);

/*
 * Utilities
 */
static netsnmp_request_group *
_mfd_group(netsnmp_handler_registration *reginfo, netsnmp_index *row,
           netsnmp_request_info *requests);


/**********************************************************************
 *
 * Registration
 *
 */
/** register specified callbacks for the specified table/oid. If the
    group_rows parameter is set, the row related callbacks will be
    called once for each unique row index. Otherwise, each callback
    will be called only once, for all objects.
*/
int
netsnmp_mfd_register_table(netsnmp_handler_registration *reginfo,
                           netsnmp_table_registration_info *tabreg,
                           netsnmp_container *container,
                           netsnmp_mfd_registration *mfdr)
{
    netsnmp_mib_handler *mfd_handler;
    u_long modes = 0;
        
    DEBUGMSGT(("mfd",">%s\n",__FUNCTION__));

    if (!mfdr) {
        snmp_log(LOG_ERR, "table_mfd registration with no callbacks\n" );
        return SNMPERR_GENERR;
    }
    
#if 0
    /*
     * check for required callbacks
     */
    if ((!mfdr->cbsm.data_lookup) ||(!mfdr->cbsm.get_values) ||
        ((reginfo->modes & HANDLER_CAN_RWRITE) &&
         ((!mfdr->cbsm.set_values) ||(!mfdr->cbsm.final_commit) ||
          (!mfdr->cbsm.object_syntax_checks)))) {
        snmp_log(LOG_ERR, "table_mfd registration with incomplete "
                 "callback structure.\n");
        return SNMPERR_GENERR;
    }
#endif
    if (NULL==container)
        container = netsnmp_container_find("table_mfd");
    if (NULL==container->compare)
        container->compare = netsnmp_compare_netsnmp_index;
    if (NULL==container->ncompare)
        container->ncompare = netsnmp_ncompare_netsnmp_index;

    mfdr->container = container;

    /*
     * create handler and inject if
     */
    mfd_handler = netsnmp_create_handler(TABLE_MFD_NAME,
                                         netsnmp_mfd_helper_handler);
    mfd_handler->myvoid = mfdr;
    mfdr->table_info = tabreg;
    netsnmp_inject_handler(reginfo, mfd_handler);

    /*
     * set up modes for baby steps handler, create it and inject it
     */
    if( mfdr->cbsm.data_lookup )
        modes |= BABY_STEP_DATA_LOOKUP;
    if( mfdr->cbsm.set_values )
        modes |= BABY_STEP_SET_VALUES;
    if( mfdr->cbsm.final_commit )
        modes |= BABY_STEP_FINAL_COMMIT;
    if( mfdr->cbsm.object_syntax_checks )
        modes |= BABY_STEP_CHECK_OBJECT;

    if( mfdr->cbse.pre_request )
        modes |= BABY_STEP_PRE_REQUEST;
    if( mfdr->cbse.post_request )
        modes |= BABY_STEP_POST_REQUEST;
    
    if( mfdr->cbse.undo_setup )
        modes |= BABY_STEP_UNDO_SETUP;
    if( mfdr->cbse.undo_cleanup )
        modes |= BABY_STEP_UNDO_CLEANUP;
    if( mfdr->cbse.undo_sets )
        modes |= BABY_STEP_UNDO_SETS;
    
    if( mfdr->cbse.row_creation )
        modes |= BABY_STEP_ROW_CREATE;
    if( mfdr->cbse.consistency_checks )
        modes |= BABY_STEP_CHECK_CONSISTENCY;
    if( mfdr->cbse.undoable_commit )
        modes |= BABY_STEP_UNDOABLE_COMMIT;
    if( mfdr->cbse.undo_commit )
        modes |= BABY_STEP_UNDO_COMMIT;
    
    netsnmp_inject_handler(reginfo,
                           netsnmp_get_baby_steps_handler(modes));

    /*
     * inject row_merge helper with prefix rootoid_len + 2 (entry.col)
     */
    netsnmp_inject_handler(reginfo,
                           netsnmp_get_row_merge_handler(reginfo->rootoid_len + 2));

    /*
     * register as a table
     */
    return netsnmp_register_table(reginfo, tabreg);
}

/**********************************************************************
 *
 * Helper
 *
 */
static int
netsnmp_mfd_helper_handler(netsnmp_mib_handler *handler,
                           netsnmp_handler_registration *reginfo,
                           netsnmp_agent_request_info *reqinfo,
                           netsnmp_request_info *requests)
{
    netsnmp_mfd_registration *mfdr;
    void *row  = NULL;
    
    /** call handlers should enforce these */
    netsnmp_assert((handler!=NULL) && (reginfo!=NULL) && (reqinfo!=NULL) &&
                   (requests!=NULL));

    DEBUGMSGT(("helper:mfd","netsnmp_mfd_handler; mode %d\n",
               reqinfo->mode));

    mfdr = (netsnmp_mfd_registration *)handler->myvoid;
    if(!mfdr) {
        snmp_log(LOG_ERR,"mfd handler called with null registration\n");
        return SNMPERR_GENERR;
    }

    /*
     * see if we've already got the row. 
     */
    if( MODE_IS_SET(reqinfo->mode))
        row = netsnmp_get_list_data(&requests->parent_data, "table_mfd_row");

    switch(reqinfo->mode) {
        
    case SNMP_MSG_GET:
        row = _mfd_data_lookup(handler, reginfo, requests);
        if( row && mfdr->cbsm.get_values )
            (*mfdr->cbsm.get_values)(mfdr, requests, row);
        break;
        
    case SNMP_MSG_GETNEXT:
        row = _mfd_data_find(handler, reginfo, requests);
        if( row && mfdr->cbsm.get_values )
            (*mfdr->cbsm.get_values)(mfdr, requests, row);
        break;
        
    case BABY_STEP_PRE_REQUEST:
        if( mfdr->cbse.pre_request )
            (*mfdr->cbse.pre_request)(mfdr, (u_long)reqinfo);
        break;
        
    case BABY_STEP_DATA_LOOKUP:
        /*
         * get the row and save it in the first request
         */
        row = _mfd_data_lookup(handler, reginfo, requests);
        netsnmp_data_list_add_data(&requests->parent_data, "table_mfd_row", row,
                                   (Netsnmp_Free_List_Data*)mfdr->container->release );
        
        break;

    case BABY_STEP_CHECK_OBJECT:
        if( mfdr->cbsm.object_syntax_checks ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbsm.object_syntax_checks)(mfdr, requests, row);
        }
        break;

    case BABY_STEP_ROW_CREATE:
        if( mfdr->cbse.row_creation ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbse.row_creation)(mfdr, requests, row);
        }
        break;

    case BABY_STEP_UNDO_SETUP:
        if( mfdr->cbse.undo_setup ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbse.undo_setup)(mfdr, requests, row);
        }
        break;

    case BABY_STEP_SET_VALUES:
        if( mfdr->cbsm.set_values ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbsm.set_values)(mfdr, requests, row);
        }
        break;

    case BABY_STEP_CHECK_CONSISTENCY:
        if( mfdr->cbse.consistency_checks ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbse.consistency_checks)(mfdr, requests, row);
        }
        break;

    case BABY_STEP_UNDO_SETS:
        if( mfdr->cbse.undo_sets ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbse.undo_sets)(mfdr, requests, row);
        }
        break;

    case BABY_STEP_UNDOABLE_COMMIT:
        if( mfdr->cbse.undoable_commit ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbse.undoable_commit)(mfdr, requests, row);
        }
        break;

    case BABY_STEP_UNDO_COMMIT:
        if( mfdr->cbse.undo_commit ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbse.undo_commit)(mfdr, requests, row);
        }
        break;

    case BABY_STEP_FINAL_COMMIT:
        if( mfdr->cbsm.final_commit ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbsm.final_commit)(mfdr, requests, row);
        }
        break;

    case BABY_STEP_UNDO_CLEANUP:
        if( mfdr->cbse.undo_cleanup ) {
            row = netsnmp_get_list_data(requests->parent_data,
                                        "table_mfd_row" );
            (*mfdr->cbse.undo_cleanup)(mfdr, requests, row);
        }            
        break;
        
    case BABY_STEP_POST_REQUEST:
        if( mfdr->cbse.post_request )
            (*mfdr->cbse.post_request)(mfdr, (u_long)reqinfo);
        break;

    default:
        snmp_log(LOG_ERR,"unknown mode %d\n", reqinfo->mode);
        return SNMP_ERR_GENERR;
    }

    /*
     * call any lower handlers
     */
    return netsnmp_call_next_handler(handler, reginfo, reqinfo, requests);
;
}

/**********************************************************************
 *
 * Implement modes
 *
 */
static netsnmp_request_group *
_mfd_data_lookup(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_request_info *requests)
{
    netsnmp_mfd_registration *mfdr;
    netsnmp_table_request_info *tblreq_info;
    netsnmp_index index;
    void *row;
    
    DEBUGMSGT(("mfd",">%s\n",__FUNCTION__));

    /** mull test in previous function */
    netsnmp_assert(handler && handler->myvoid);
    
    mfdr = (netsnmp_mfd_registration *)handler->myvoid;
    tblreq_info = netsnmp_extract_table_info(requests);
    if(NULL == tblreq_info)
        return NULL;
    
    index.oids = tblreq_info->index_oid;
    index.len = tblreq_info->index_oid_len;
    row = CONTAINER_FIND(mfdr->container, &index);
    if(NULL == row) 
        return NULL;

    return _mfd_group(reginfo, row, requests);
}

/*
 * xxx-rks: this needs updates to handle sparse tables
 */
static netsnmp_request_group *
_mfd_data_find(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_request_info *requests)
{
    netsnmp_mfd_registration *mfdr;
    netsnmp_table_request_info *tblreq_info;
    void *row;
    
    DEBUGMSGT(("mfd",">%s\n",__FUNCTION__));

    /** mull test in previous function */
    netsnmp_assert(handler && handler->myvoid);
    
    mfdr = (netsnmp_mfd_registration *)handler->myvoid;
    tblreq_info = netsnmp_extract_table_info(requests);
    if(NULL == tblreq_info)
        return NULL;

    row = netsnmp_table_index_find_next_row(mfdr->container, tblreq_info);

    return _mfd_group(reginfo, row, requests);
}

/**********************************************************************
 *
 * Internal helpers
 *
 */
static netsnmp_request_group *
_mfd_group(netsnmp_handler_registration *reginfo, netsnmp_index *row,
           netsnmp_request_info *requests)
{
    netsnmp_request_group_item *ritem;
    netsnmp_table_request_info *tblreq_info;
    netsnmp_request_group *rgroup;
    
    DEBUGMSGT(("mfd",">%s\n",__FUNCTION__));

    if(NULL == row)
        return NULL;

    /*
     * allocate a request group
     */
    rgroup = SNMP_MALLOC_TYPEDEF(netsnmp_request_group);
    if(NULL==rgroup) {
        snmp_log(LOG_ERR,"could not allocate request group\n");
        return NULL;
    }

    rgroup->existing_row = row;

    while(requests) {

        /*
         * check for table info, so we can update the index
         */
        tblreq_info = netsnmp_extract_table_info(requests);
        netsnmp_assert(NULL != tblreq_info); /* should never happen */

        /*
         * add a requiest item for this request to the request group
         */
        ritem = SNMP_MALLOC_TYPEDEF(netsnmp_request_group_item);
        if(NULL==ritem) {
            snmp_log(LOG_ERR,"could not allocate request item\n");
            /** xxx-rks: better cleanup */
            return NULL;
        }
        ritem->ri = requests;
        ritem->tri = tblreq_info;

        ritem->next = rgroup->list;
        rgroup->list = ritem;
        
        /*
         * copy index to agent request info
         */
        memcpy(tblreq_info->index_oid, row->oids,
               row->len * sizeof(oid));
        tblreq_info->index_oid_len = row->len;
        netsnmp_update_variable_list_from_index(tblreq_info);

        /*
         * build oid in varbind
         */
        netsnmp_table_build_oid_from_index(reginfo, requests, tblreq_info);
        
        requests = requests->next;
    }
    
    return rgroup;
}

