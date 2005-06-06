#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "utilities/iquery.h"

netsnmp_session *iquery_default_session = NULL;

void init_iquery(void){
}

    /**************************
     *
     *  APIs to construct an "internal query" session
     *
     **************************/

netsnmp_session *iquery_pdu_session(netsnmp_pdu* pdu){
    if (!pdu)
       return NULL;
    if (pdu->version == SNMP_VERSION_3)
        return iquery_session( pdu->securityName, 
                           pdu->version,
                           pdu->securityModel,
                           pdu->securityLevel,
                           pdu->securityEngineID,
                           pdu->securityEngineIDLen);
    else
        return iquery_session( pdu->community, 
                           pdu->version,
                           pdu->version+1,
                           SNMP_SEC_LEVEL_NOAUTH,
                           pdu->securityEngineID,
                           pdu->securityEngineIDLen);
}

netsnmp_session *iquery_user_session(char* secName){
    u_char eID[SNMP_MAXBUF_SMALL];
    size_t elen = snmpv3_get_engineID(eID, sizeof(eID));

    return iquery_session( secName, 
                           SNMP_MP_MODEL_SNMPv3,
                           SNMP_SEC_MODEL_USM,
                           SNMP_SEC_LEVEL_AUTHNOPRIV, eID, elen);
}

netsnmp_session *iquery_community_session( char* community, int version ){
    u_char eID[SNMP_MAXBUF_SMALL];
    size_t elen = snmpv3_get_engineID(eID, sizeof(eID));

    return iquery_session( community, version, version+1,
                           SNMP_SEC_LEVEL_NOAUTH, eID, elen);
}

netsnmp_session *iquery_session( char* secName,   int   mpModel,
                                 int   secModel,  int   secLevel,
                               u_char* engineID, size_t engIDLen) {

    /*
     * This routine creates a completely new session every time.
     * It might be worth keeping track of which 'secNames' already
     * have iquery sessions created, and re-using the appropriate one.  
     */
    extern int callback_master_num;
    netsnmp_session *ss = netsnmp_callback_open( callback_master_num,
                                                 NULL, NULL, NULL);
    if (ss) {
        ss->version       = mpModel;
        ss->securityModel = secModel;
        ss->securityLevel = secLevel;
        memdup( &(ss->securityEngineID), engineID, engIDLen );
        ss->securityEngineIDLen = engIDLen;
        if ( mpModel == SNMP_MP_MODEL_SNMPv3 ) {
            memdup(&(ss->securityName), secName, strlen(secName));
            ss->securityNameLen = strlen(secName);
        } else {
            memdup( &(ss->community), secName, strlen(secName));
            ss->community_len = strlen(secName);
        }
    }
    return ss;
}

    /**************************
     *
     *  APIs to issue an "internal query"
     *
     **************************/

/*
 * Internal utility routine to actually make the internal query
 */
static int _iquery(netsnmp_variable_list *list,
                   int                    request,
                   netsnmp_session       *session){

    netsnmp_pdu *pdu      = snmp_pdu_create( request );
    netsnmp_pdu *response = NULL;
    netsnmp_variable_list *vb1, *vb2;
    int ret;

    /*
     * Clone the varbind list into the request PDU...
     */
    pdu->variables = snmp_clone_varbind( list );
    ret = snmp_synch_response( session, pdu, &response );

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
                snmp_clone_var( vb1, vb2 );
            }
        }
    }
    snmp_free_pdu( response );
    return ret;
}

/*
 * Most of these are simple wrappers round the internal utility routine
 */
int iquery_get_session(netsnmp_variable_list *list,
                       netsnmp_session       *session){
    return _iquery( list, SNMP_MSG_GET, session );
}
int iquery_get(        netsnmp_variable_list *list){
    return iquery_get_session(list, iquery_default_session);
}


int iquery_getnext_session(netsnmp_variable_list *list,
                           netsnmp_session       *session){
    return _iquery( list, SNMP_MSG_GETNEXT, session );
}
int iquery_getnext(        netsnmp_variable_list *list){
    return iquery_getnext_session(list, iquery_default_session);
}


int iquery_set_session(netsnmp_variable_list *list,
                       netsnmp_session       *session){
    return _iquery( list, SNMP_MSG_SET, session );
}
int iquery_set(        netsnmp_variable_list *list){
    return iquery_set_session(list, iquery_default_session);
}

/*
 * An internal walk needs a bit more work.
 */
int iquery_walk_session(netsnmp_variable_list *list,
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
    ret = _iquery( vb, SNMP_MSG_GETNEXT, session );
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
        ret = _iquery( vb, SNMP_MSG_GETNEXT, session );
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
int iquery_walk(        netsnmp_variable_list *list){
    return iquery_walk_session(list, iquery_default_session);
}
