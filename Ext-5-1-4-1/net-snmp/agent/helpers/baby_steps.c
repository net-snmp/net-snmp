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

static u_short get_mode_map[BABY_STEPS_PER_MODE_MAX] = {
    MODE_BSTEP_PRE_REQUEST, MODE_BSTEP_OBJECT_LOOKUP, 0xffff, MODE_BSTEP_POST_REQUEST };

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
    
/** @defgroup baby_steps baby_steps
 *  Calls your handler in baby_steps for set processing.
 *  @ingroup handler
 *  @{
 */

/** returns a baby_steps handler that can be injected into a given
 *  handler chain.
 */
netsnmp_mib_handler *
netsnmp_get_baby_steps_handler(u_long modes)
{
    netsnmp_mib_handler *mh;

    mh = netsnmp_create_handler("baby_steps", netsnmp_baby_steps_helper);
    if(!mh)
        return NULL;

    mh->myvoid = (void*)modes;
    
    return mh;
}

/** @internal Implements the baby_steps handler */
int
netsnmp_baby_steps_helper(netsnmp_mib_handler *handler,
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
        if(0xffff == mode_map_ptr[i]) /** use original mode */
            reqinfo->mode = save_mode;
        else
            reqinfo->mode = mode_map_ptr[i];
        if((BABY_STEPS_PER_MODE_MAX - 1) == i)
            reqinfo->next_mode_ok = BABY_STEP_NONE;
        else {
            if(0xffff == mode_map_ptr[i+1])
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
netsnmp_init_baby_steps_helper(void)
{
    netsnmp_register_handler_by_name("baby_steps",
                                     netsnmp_get_baby_steps_handler(BABY_STEP_ALL));
}
