/*
 * baby_steps.c
 * $Id$
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include <net-snmp/agent/baby_steps.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#define BABY_STEPS_PER_MODE_MAX     4
#define BSTEP_USE_ORIGINAL          0xffff

static u_short get_mode_map[BABY_STEPS_PER_MODE_MAX] = {
    MODE_BSTEP_PRE_REQUEST, MODE_BSTEP_OBJECT_LOOKUP, BSTEP_USE_ORIGINAL, MODE_BSTEP_POST_REQUEST };

static u_short set_mode_map[SNMP_MSG_INTERNAL_SET_MAX][BABY_STEPS_PER_MODE_MAX] = {
    /*R1*/
    { MODE_BSTEP_PRE_REQUEST, MODE_BSTEP_OBJECT_LOOKUP, MODE_BSTEP_CHECK_VALUE,
      MODE_BSTEP_ROW_CREATE},
    /*R2*/
    { MODE_BSTEP_UNDO_SETUP, BABY_STEP_NONE, BABY_STEP_NONE, BABY_STEP_NONE },
    /*A */
    { MODE_BSTEP_SET_VALUE,MODE_BSTEP_CHECK_CONSISTENCY,
      MODE_BSTEP_COMMIT, BABY_STEP_NONE },
    /*C */
    { MODE_BSTEP_IRREVERSIBLE_COMMIT, MODE_BSTEP_UNDO_CLEANUP, MODE_BSTEP_POST_REQUEST,
      BABY_STEP_NONE},
    /*F */
    { MODE_BSTEP_UNDO_CLEANUP, MODE_BSTEP_POST_REQUEST, BABY_STEP_NONE,
      BABY_STEP_NONE },
    /*U */
    { MODE_BSTEP_UNDO_COMMIT, MODE_BSTEP_UNDO_SET, MODE_BSTEP_UNDO_CLEANUP,
      MODE_BSTEP_POST_REQUEST}
};

static int
_baby_steps_helper(netsnmp_mib_handler *handler,
                   netsnmp_handler_registration *reginfo,
                   netsnmp_agent_request_info *reqinfo,
                   netsnmp_request_info *requests);
static int
_baby_steps_access_multiplexer(netsnmp_mib_handler *handler,
                               netsnmp_handler_registration *reginfo,
                               netsnmp_agent_request_info *reqinfo,
                               netsnmp_request_info *requests);
    
/** @defgroup baby_steps baby_steps: calls your handler in baby_steps for set processing.
 *  @ingroup handler
 *  @{
 */

/** returns a baby_steps handler that can be injected into a given
 *  handler chain.
 */
netsnmp_mib_handler *
netsnmp_baby_steps_handler_get(u_long modes)
{
    netsnmp_mib_handler *mh;

    mh = netsnmp_create_handler("baby_steps", _baby_steps_helper);
    if(!mh)
        return NULL;

    mh->myvoid = (void*)modes;

    /*
     * don't set MIB_HANDLER_AUTO_NEXT, since we need to call lower
     * handlers with a munged mode.
     */
    
    return mh;
}

/** @internal Implements the baby_steps handler */
static int
_baby_steps_helper(netsnmp_mib_handler *handler,
                         netsnmp_handler_registration *reginfo,
                         netsnmp_agent_request_info *reqinfo,
                         netsnmp_request_info *requests)
{
    int save_mode, i, rc = SNMP_ERR_NOERROR;
    u_short *mode_map_ptr;
    
    DEBUGMSGTL(("helper:baby_steps", "Got request, mode %d\n", reqinfo->mode));

    switch (reqinfo->mode) {

    case MODE_SET_RESERVE1:
    case MODE_SET_RESERVE2:
    case MODE_SET_ACTION:
    case MODE_SET_COMMIT:
    case MODE_SET_FREE:
    case MODE_SET_UNDO:
        mode_map_ptr = set_mode_map[reqinfo->mode];
        break;
            
    default:
        mode_map_ptr = get_mode_map;
    }

    /* Legend: (test) [optional] <required>
     *
     * OLD              NEW
     * ========  ============================================
     * +++           [pre_request]
     *                    |
     *               (row exists?) N ->(row_creation) N >-->+
     *                    |                   | Y           |
     *                    |<------------------+             |
     *                   \|/                                |
     * RESERVE1  <object_syntax_checks>                     |
     *                    |                                \|/
     *                  (err?)  Y >------------------------>+
     *                    |                                 |
     *                   \|/                               \|/
     * +++          (row existed?) N ->[row_creation] ERR ->+
     *                    |                   | OK          |
     *                    |<------------------+             |
     *                   \|/                                |
     * RESERVER2     [undo_setup]                           |
     *                    |                                 |
     *                  (err?)  Y --->------------------>+  |
     *                    |                              |  |
     * ACTION        <set_values>                        |  |
     *                    |                              |  |
     *                  (err?)  Y >---------+            |  |
     *                    |                 |            |  |
     * +++        [consistency_checks]      |            |  |
     *                    |                \|/           |  |
     * UNDO             (err?)  Y >-------[undo]-------->+  |
     *                    |                              |  |
     *            [reversible_commit]                    |  |
     * +++                |                              | \|/
     *                  (err?)  Y >--[reverse_commit]    |  |
     *                    |              |               |  |
     * COMMIT        <final_commit>      |               |  |
     *                    |              |               |  |
     *                  (err?)  Y >--[log msg]           |  |
     *                    |              |               |  |
     *                    |             \|/             \|/ |
     *                    | <-----------<+---<-----------+  |
     *                   \|/                                |
     * FREE          [undo_cleanup]                         |
     *                    |                                \|/
     *                    |<--------------<-----------------+
     *                   \|/
     *               [post_request]
     */
    /*
     * save original mode
     */
    save_mode = reqinfo->mode;
    for(i = 0; i < BABY_STEPS_PER_MODE_MAX; ++i ) {
        /*
         * break if we run out of baby steps for this mode
         */
        if(mode_map_ptr[i] == BABY_STEP_NONE)
            break;

        /*
         * skip modes the handler didn't register for
        if(!(mode_map_ptr[i] & (u_long)handler->myvoid))
            continue;
         */
        
        /*
         * call handlers for baby step
         */
        if(BSTEP_USE_ORIGINAL == mode_map_ptr[i])
            reqinfo->mode = save_mode;
        else
            reqinfo->mode = mode_map_ptr[i];
        if((BABY_STEPS_PER_MODE_MAX - 1) == i)
            reqinfo->next_mode_ok = BABY_STEP_NONE;
        else {
            if(BSTEP_USE_ORIGINAL == mode_map_ptr[i+1])
                reqinfo->next_mode_ok = save_mode;
            else
                reqinfo->next_mode_ok = mode_map_ptr[i+1];
        }
        rc = netsnmp_call_next_handler(handler, reginfo, reqinfo,
                                       requests);

        /*
         * check for error calling handler (unlikely, but...)
         */
        if(rc)
            break;

        /*
         * check for errors in any of the requests
         */
        rc = netsnmp_check_requests_error(requests);
        if(rc)
            break;
    }

    /*
     * restore original mode
     */
    reqinfo->mode = save_mode;

    
    return rc;
}

/** initializes the baby_steps helper which then registers a baby_steps
 *  handler as a run-time injectable handler for configuration file
 *  use.
 */
void
netsnmp_baby_steps_handler_init(void)
{
    netsnmp_register_handler_by_name("baby_steps",
                                     netsnmp_baby_steps_handler_get(BABY_STEP_ALL));
}

/** @} */

/** @defgroup baby_steps baby_steps_access_multiplexer: calls individual access methods based on baby_step mode.
 *  @ingroup handler
 *  @{
 */

/** returns a baby_steps handler that can be injected into a given
 *  handler chain.
 */
netsnmp_mib_handler *
netsnmp_baby_steps_access_multiplexer_get(netsnmp_baby_steps_access_methods *am)
{
    netsnmp_mib_handler *mh;

    mh = netsnmp_create_handler("baby_steps_access_multiplexer",
                                _baby_steps_access_multiplexer);
    if(!mh)
        return NULL;

    mh->myvoid = am;
    mh->flags |= MIB_HANDLER_AUTO_NEXT;
    
    return mh;
}

/** @internal Implements the baby_steps handler */
static int
_baby_steps_access_multiplexer(netsnmp_mib_handler *handler,
                               netsnmp_handler_registration *reginfo,
                               netsnmp_agent_request_info *reqinfo,
                               netsnmp_request_info *requests)
{
    void *temp_void;
    Netsnmp_Node_Handler *method = NULL;
    netsnmp_baby_steps_access_methods *access_methods;
    int rc = SNMP_ERR_NOERROR;

    /** call handlers should enforce these */
    netsnmp_assert((handler!=NULL) && (reginfo!=NULL) && (reqinfo!=NULL) &&
                   (requests!=NULL));

    DEBUGMSGT(("helper:baby_steps_access_multiplexer",
               "baby_steps_access_multiplexer; mode %d\n", reqinfo->mode));

    access_methods = (netsnmp_baby_steps_access_methods *)handler->myvoid;
    if(!access_methods) {
        snmp_log(LOG_ERR,"baby_steps_access_multiplexer has no methods\n");
        return SNMPERR_GENERR;
    }

    switch(reqinfo->mode) {
        
    case MODE_BSTEP_PRE_REQUEST:
        if( access_methods->pre_request )
            method = access_methods->pre_request;
        break;
        
    case MODE_BSTEP_OBJECT_LOOKUP:
        if( access_methods->object_lookup )
            method = access_methods->object_lookup;
        break;

    case SNMP_MSG_GET:
    case SNMP_MSG_GETNEXT:
        if( access_methods->get_values )
            method = access_methods->get_values;
        break;
        
    case MODE_BSTEP_CHECK_VALUE:
        if( access_methods->object_syntax_checks )
            method = access_methods->object_syntax_checks;
        break;

    case MODE_BSTEP_ROW_CREATE:
        if( access_methods->row_creation )
            method = access_methods->row_creation;
        break;

    case MODE_BSTEP_UNDO_SETUP:
        if( access_methods->undo_setup )
            method = access_methods->undo_setup;
        break;

    case MODE_BSTEP_SET_VALUE:
        if( access_methods->set_values )
            method = access_methods->set_values;
        break;

    case MODE_BSTEP_CHECK_CONSISTENCY:
        if( access_methods->consistency_checks )
            method = access_methods->consistency_checks;
        break;

    case MODE_BSTEP_UNDO_SET:
        if( access_methods->undo_sets )
            method = access_methods->undo_sets;
        break;

    case MODE_BSTEP_COMMIT:
        if( access_methods->commit )
            method = access_methods->commit;
        break;

    case MODE_BSTEP_UNDO_COMMIT:
        if( access_methods->undo_commit )
            method = access_methods->undo_commit;
        break;

    case MODE_BSTEP_IRREVERSIBLE_COMMIT:
        if( access_methods->irreversible_commit )
            method = access_methods->irreversible_commit;
        break;

    case MODE_BSTEP_UNDO_CLEANUP:
        if( access_methods->undo_cleanup )
            method = access_methods->undo_cleanup;
        break;
        
    case MODE_BSTEP_POST_REQUEST:
        if( access_methods->post_request )
            method = access_methods->post_request;
        break;

    default:
        snmp_log(LOG_ERR,"unknown mode %d\n", reqinfo->mode);
        return SNMP_ERR_GENERR;
    }

    /*
     * if method exists, set up handler void and call method.
     */
    if(NULL != method) {
        temp_void = handler->myvoid;
        handler->myvoid = access_methods->my_access_void;
        rc = (*method)(handler, reginfo, reqinfo, requests);
        handler->myvoid = temp_void;
    }

    /*
     * don't call any lower handlers, it will be done for us 
     * since we set MIB_HANDLER_AUTO_NEXT
     */

    return rc;
}
