#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

/*
 *
 *  Convenience routines to make various requests
 *  over the specified SNMP session.
 *
 */
static netsnmp_session *_def_query_session = NULL;
void
netsnmp_query_set_default_session( netsnmp_session *sess) {
    _def_query_session = sess;
}

netsnmp_session *
netsnmp_query_get_default_session( void ) {
    return _def_query_session;
}


/*
 * Internal utility routine to actually send the query
 */
static int _query(netsnmp_variable_list *list,
                  int                    request,
                  netsnmp_session       *session) {

    netsnmp_pdu *pdu      = snmp_pdu_create( request );
    netsnmp_pdu *response = NULL;
    netsnmp_variable_list *vb1, *vb2, *vtmp;
    int ret;

    /*
     * Clone the varbind list into the request PDU...
     */
    pdu->variables = snmp_clone_varbind( list );
    if ( session )
        ret = snmp_synch_response(            session, pdu, &response );
    else if (_def_query_session)
        ret = snmp_synch_response( _def_query_session, pdu, &response );
    else {
        /* No session specified */
        return SNMP_ERR_GENERR;
    }

    /*
     * ....then copy the results back into the
     * list (assuming the request succeeded!).
     * This avoids having to worry about how this
     * list was originally allocated.
     */
    if ( ret == SNMP_ERR_NOERROR ) {
        if ( response->errstat != SNMP_ERR_NOERROR ) {
            ret = response->errstat;
        } else {
            for (vb1 = response->variables, vb2 = list;
                 vb1;
                 vb1 = vb1->next_variable,  vb2 = vb2->next_variable) {
                if ( !vb2 ) {
                    ret = SNMP_ERR_GENERR;
                    break;
                }
                vtmp = vb2->next_variable;
                snmp_clone_var( vb1, vb2 );
                vb2->next_variable = vtmp;
            }
        }
    } else {
        /* Distinguish snmp_send errors from SNMP errStat errors */
        ret = -ret;
    }
    snmp_free_pdu( response );
    return ret;
}

/*
 * These are simple wrappers round the internal utility routine
 */
int netsnmp_query_get(netsnmp_variable_list *list,
                      netsnmp_session       *session){
    return _query( list, SNMP_MSG_GET, session );
}


int netsnmp_query_getnext(netsnmp_variable_list *list,
                          netsnmp_session       *session){
    return _query( list, SNMP_MSG_GETNEXT, session );
}


int netsnmp_query_set(netsnmp_variable_list *list,
                      netsnmp_session       *session){
    return _query( list, SNMP_MSG_SET, session );
}

/*
 * A walk needs a bit more work.
 */
int netsnmp_query_walk(netsnmp_variable_list *list,
                       netsnmp_session       *session) {
    /*
     * Create a working copy of the original (single)
     * varbind, so we can use this varbind parameter
     * to check when we've finished walking this subtree.
     */
    netsnmp_variable_list *vb = snmp_clone_varbind( list );
    netsnmp_variable_list *res_list = NULL;
    netsnmp_variable_list *res_last = NULL;
    int ret;

    /*
     * Now walk the tree as usual
     */
    ret = _query( vb, SNMP_MSG_GETNEXT, session );
    while ( ret == SNMP_ERR_NOERROR &&
        snmp_oidtree_compare( list->name, list->name_length,
                                vb->name,   vb->name_length ) == 0) {

        /*
         * Copy each response varbind to the end of the result list
         * and then re-use this to ask for the next entry.
         */
        if ( res_last ) {
            res_last->next_variable = snmp_clone_varbind( vb );
            res_last = res_last->next_variable;
        } else {
            res_list = snmp_clone_varbind( vb );
            res_last = res_list;
        }
        ret = _query( vb, SNMP_MSG_GETNEXT, session );
    }
    /*
     * Copy the first result back into the original varbind parameter,
     * add the rest of the results (if any), and clean up.
     */
    if ( res_list ) {
        snmp_clone_var( res_list, list );
        list->next_variable = res_list->next_variable;
        res_list->next_variable = NULL;
        snmp_free_varbind( res_list );
    }
    snmp_free_varbind( vb );
    return ret;
}
