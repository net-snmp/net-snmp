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
static int
_mfd_data_lookup(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_request_info *requests,
                 mfd_pdu_context * pdu_ctx);

static int
_mfd_data_find(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_request_info *requests,
               mfd_pdu_context * pdu_ctx);

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
/**
 * register a MIBs For Dummies table.
 *
 * @param mfdr        : mfd registration
 * @param name        : table/handler name
 * @param handler     : user handler to be called after the
 *                      mfd handler (usually NULL)
 * @param reg_oid     : OID to register at
 * @param reg_oid_len : length of OID
 * @param modes       : modes for the handler
 */
int
netsnmp_mfd_register_table(netsnmp_mfd_registration *mfdr, const char *name,
                           Netsnmp_Node_Handler * handler,
                           oid * reg_oid, size_t reg_oid_len, int user_modes)
{
    netsnmp_mib_handler *mfd_handler;
    netsnmp_handler_registration *reginfo;
    u_long mfd_modes = 0;
        
    DEBUGMSGT(("mfd",">%s\n","register_table"));

    if (!mfdr) {
        snmp_log(LOG_ERR, "table_mfd registration with no callbacks\n" );
        return SNMPERR_GENERR;
    }

#if 0
    /*
     * check for required callbacks
     */
    if ((!mfdr->object_lookup) ||(!mfdr->get_values) ||
        ((reg_info->user_modes & HANDLER_CAN_RWRITE) &&
         ((!mfdr->set_values) ||(!mfdr->commit) ||
          (!mfdr->object_syntax_checks)))) {
        snmp_log(LOG_ERR, "table_mfd registration with incomplete "
                 "callback structure.\n");
        return SNMPERR_GENERR;
    }
#endif
    if (NULL==mfdr->container)
        mfdr->container = netsnmp_container_find("table_mfd");
    if (NULL==mfdr->container->compare)
        mfdr->container->compare = netsnmp_compare_netsnmp_index;
    if (NULL==mfdr->container->ncompare)
        mfdr->container->ncompare = netsnmp_ncompare_netsnmp_index;

    /*
     * create handler
     */
    reginfo = 
        netsnmp_create_handler_registration(name, handler,
                                            reg_oid, reg_oid_len, user_modes);
    

    mfd_handler = netsnmp_create_handler(TABLE_MFD_NAME,
                                         netsnmp_mfd_helper_handler);
    mfd_handler->myvoid = mfdr;
    netsnmp_inject_handler(reginfo, mfd_handler);

    /*
     * set up mfd_modes for baby steps handler, create it and inject it
     */
    if( mfdr->object_lookup )
        mfd_modes |= BABY_STEP_OBJECT_LOOKUP;
    if( mfdr->set_values )
        mfd_modes |= BABY_STEP_SET_VALUES;
    if( mfdr->irreversible_commit )
        mfd_modes |= BABY_STEP_IRREVERSIBLE_COMMIT;
    if( mfdr->object_syntax_checks )
        mfd_modes |= BABY_STEP_CHECK_OBJECT;

    if( mfdr->pre_request )
        mfd_modes |= BABY_STEP_PRE_REQUEST;
    if( mfdr->post_request )
        mfd_modes |= BABY_STEP_POST_REQUEST;
    
    if( mfdr->undo_setup )
        mfd_modes |= BABY_STEP_UNDO_SETUP;
    if( mfdr->undo_cleanup )
        mfd_modes |= BABY_STEP_UNDO_CLEANUP;
    if( mfdr->undo_sets )
        mfd_modes |= BABY_STEP_UNDO_SETS;
    
    if( mfdr->row_creation )
        mfd_modes |= BABY_STEP_ROW_CREATE;
    if( mfdr->consistency_checks )
        mfd_modes |= BABY_STEP_CHECK_CONSISTENCY;
    if( mfdr->commit )
        mfd_modes |= BABY_STEP_COMMIT;
    if( mfdr->undo_commit )
        mfd_modes |= BABY_STEP_UNDO_COMMIT;
    
    netsnmp_inject_handler(reginfo,
                           netsnmp_get_baby_steps_handler(mfd_modes));

    /*
     * inject row_merge helper with prefix rootoid_len + 2 (entry.col)
     */
    netsnmp_inject_handler(reginfo,
                           netsnmp_get_row_merge_handler(reginfo->rootoid_len + 2));

    /*
     * register as a table
     */
    return netsnmp_register_table(reginfo, mfdr->table_info);
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
    mfd_pdu_context           tmp_pdu_ctx, *pdu_ctx;
    
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
    if( (reqinfo->mode != MODE_BSTEP_OBJECT_LOOKUP) &&
        (reqinfo->mode != MODE_BSTEP_PRE_REQUEST) &&
        (reqinfo->mode != MODE_BSTEP_POST_REQUEST) ) {
        pdu_ctx = netsnmp_get_list_data(requests->parent_data, "mfd_pdu_ctx");
        if((NULL == pdu_ctx) && (reqinfo->mode != MODE_BSTEP_CHECK_VALUE) &&
           (reqinfo->mode != MODE_BSTEP_ROW_CREATE)) {
            snmp_log(LOG_ERR,"pdu context not found.\n");
            return SNMP_ERR_GENERR;
        }
        pdu_ctx->request_mode = reqinfo->mode;
        pdu_ctx->next_mode_ok = reqinfo->next_mode_ok;
    }

    switch(reqinfo->mode) {
        
    case MODE_BSTEP_PRE_REQUEST:
        if( mfdr->pre_request ) {
            tmp_pdu_ctx.mfd_user_ctx = mfdr->mfd_user_ctx;
            tmp_pdu_ctx.next_mode_ok = reqinfo->next_mode_ok;
            tmp_pdu_ctx.request_mode = reqinfo->mode;
            tmp_pdu_ctx.mfd_data_list = requests->parent_data;
            (*mfdr->pre_request)(&tmp_pdu_ctx,
                                 requests->parent_data, (u_long)reqinfo);
        }
        break;
        
    case MODE_BSTEP_OBJECT_LOOKUP: {
            int rc;
        /*
         * get the row and save it in the first request
         */
        if(MODE_GETNEXT == reqinfo->next_mode_ok)
            rc = _mfd_data_find(handler, reginfo, requests, &tmp_pdu_ctx);
        else
            rc = _mfd_data_lookup(handler, reginfo, requests, &tmp_pdu_ctx);
        /*
         * for row creation, the data lookup won't find the mfd_data, but
         * won't return an error. For this case, check that there is a
         * row_creation callback..
         */
        if((NULL == tmp_pdu_ctx.mfd_data) && (SNMP_ERR_NOERROR == rc)) {
            /*
             * no data only ok for a set
             */
            if(reqinfo->next_mode_ok != MODE_BSTEP_CHECK_VALUE)
                rc = SNMP_ERR_NOSUCHNAME; /* xxx-rks: scalars? */
            else if (NULL == mfdr->row_creation)
                rc = SNMP_ERR_NOCREATION;
        }
        if(rc) {
            netsnmp_request_set_error_all(requests, rc);
            break;
        }
        pdu_ctx = SNMP_MALLOC_TYPEDEF(mfd_pdu_context);
        if(NULL == pdu_ctx) {
            snmp_log(LOG_ERR,"could not allocate request group\n");
            netsnmp_request_set_error_all(requests, SNMP_ERR_GENERR);
            return SNMP_ERR_GENERR;
        }
        pdu_ctx->mfd_user_ctx = mfdr->mfd_user_ctx;
        pdu_ctx->request_mode = reqinfo->mode;
        pdu_ctx->next_mode_ok = reqinfo->next_mode_ok;
        pdu_ctx->mfd_data_list = requests->parent_data;
        pdu_ctx->mfd_data = tmp_pdu_ctx.mfd_data;
        netsnmp_data_list_add_data(&requests->parent_data, "mfd_pdu_ctx",
                                   pdu_ctx, NULL );
        if( mfdr->object_lookup ) {
            (*mfdr->object_lookup)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
    }
        break;

    case SNMP_MSG_GET:
    case SNMP_MSG_GETNEXT:
        if( pdu_ctx->mfd_data && mfdr->get_values )
            (*mfdr->get_values)(pdu_ctx, requests, pdu_ctx->mfd_data);
        break;
        
    case MODE_BSTEP_CHECK_VALUE:
        netsnmp_assert((NULL != pdu_ctx) && (NULL != pdu_ctx->mfd_data));
        if( mfdr->object_syntax_checks ) {
            (*mfdr->object_syntax_checks)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
        break;

    case MODE_BSTEP_ROW_CREATE:
        netsnmp_assert(NULL != pdu_ctx);
        if( (NULL == pdu_ctx->mfd_data) && mfdr->row_creation ) {
            (*mfdr->row_creation)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
        break;

    case MODE_BSTEP_UNDO_SETUP:
        netsnmp_assert((NULL != pdu_ctx) && (NULL != pdu_ctx->mfd_data));
        if( mfdr->undo_setup ) {
            (*mfdr->undo_setup)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
        break;

    case MODE_BSTEP_SET_VALUE:
        netsnmp_assert((NULL != pdu_ctx) && (NULL != pdu_ctx->mfd_data));
        if( mfdr->set_values ) {
            (*mfdr->set_values)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
        break;

    case MODE_BSTEP_CHECK_CONSISTENCY:
        netsnmp_assert((NULL != pdu_ctx) && (NULL != pdu_ctx->mfd_data));
        if( mfdr->consistency_checks ) {
            (*mfdr->consistency_checks)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
        break;

    case MODE_BSTEP_UNDO_SET:
        netsnmp_assert((NULL != pdu_ctx) && (NULL != pdu_ctx->mfd_data));
        if( mfdr->undo_sets ) {
            (*mfdr->undo_sets)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
        break;

    case MODE_BSTEP_COMMIT:
        netsnmp_assert((NULL != pdu_ctx) && (NULL != pdu_ctx->mfd_data));
        if( mfdr->commit ) {
            (*mfdr->commit)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
        break;

    case MODE_BSTEP_UNDO_COMMIT:
        netsnmp_assert((NULL != pdu_ctx) && (NULL != pdu_ctx->mfd_data));
        if( mfdr->undo_commit ) {
            (*mfdr->undo_commit)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
        break;

    case MODE_BSTEP_IRREVERSIBLE_COMMIT:
        netsnmp_assert((NULL != pdu_ctx) && (NULL != pdu_ctx->mfd_data));
        if( mfdr->irreversible_commit ) {
            (*mfdr->irreversible_commit)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }
        break;

    case MODE_BSTEP_UNDO_CLEANUP:
        netsnmp_assert((NULL != pdu_ctx) && (NULL != pdu_ctx->mfd_data));
        if( mfdr->undo_cleanup ) {
            (*mfdr->undo_cleanup)(pdu_ctx, requests, pdu_ctx->mfd_data);
        }            
        break;
        
    case MODE_BSTEP_POST_REQUEST:
        if( mfdr->post_request ) {
            tmp_pdu_ctx.mfd_user_ctx = mfdr->mfd_user_ctx;
            tmp_pdu_ctx.request_mode = reqinfo->mode;
            tmp_pdu_ctx.mfd_data_list = requests->parent_data;
            (*mfdr->post_request)(&tmp_pdu_ctx,
                                  requests->parent_data, (u_long)reqinfo);
        }
        break;

    default:
        snmp_log(LOG_ERR,"unknown mode %d\n", reqinfo->mode);
        return SNMP_ERR_GENERR;
    }

    /*
     * call any lower handlers
     */
    if((NULL != handler->next) &&
       (NULL != handler->next->access_method))
        return netsnmp_call_next_handler(handler, reginfo, reqinfo, requests);

    return SNMP_ERR_NOERROR;
}

/**********************************************************************
 *
 * Implement modes
 *
 */
static int
_mfd_data_lookup(netsnmp_mib_handler *handler,
                 netsnmp_handler_registration *reginfo,
                 netsnmp_request_info *requests,
                 mfd_pdu_context * pdu_ctx)
{
    netsnmp_mfd_registration *mfdr;
    netsnmp_table_request_info *tblreq_info;
    netsnmp_index index;
    
    DEBUGMSGT(("mfd",">%s\n","data_lookup"));

    /** mull test in previous function */
    netsnmp_assert(handler && handler->myvoid);
    
    mfdr = (netsnmp_mfd_registration *)handler->myvoid;
    tblreq_info = netsnmp_extract_table_info(requests);
    if(NULL == tblreq_info)
        return SNMP_ERR_GENERR;
    
    index.oids = tblreq_info->index_oid;
    index.len = tblreq_info->index_oid_len;
    pdu_ctx->mfd_data = CONTAINER_FIND(mfdr->container, &index);
    if(NULL == pdu_ctx->mfd_data) 
        return SNMP_ERR_NOSUCHNAME;

    return SNMP_ERR_NOERROR;
}

/*
 * xxx-rks: this needs updates to handle sparse tables
 */
static int
_mfd_data_find(netsnmp_mib_handler *handler,
               netsnmp_handler_registration *reginfo,
               netsnmp_request_info *requests,
               mfd_pdu_context * pdu_ctx)
{
    netsnmp_mfd_registration *mfdr;
    netsnmp_table_request_info *tblreq_info;
    
    DEBUGMSGT(("mfd",">%s\n","data_find"));

    /** mull test in previous function */
    netsnmp_assert(handler && handler->myvoid);
    
    mfdr = (netsnmp_mfd_registration *)handler->myvoid;
    tblreq_info = netsnmp_extract_table_info(requests);
    if(NULL == tblreq_info)
        return SNMP_ERR_GENERR;

    pdu_ctx->mfd_data = netsnmp_table_index_find_next_row(mfdr->container, tblreq_info);

    return SNMP_ERR_NOERROR;
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
    
    DEBUGMSGT(("mfd",">%s\n","_mfd_group"));

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

