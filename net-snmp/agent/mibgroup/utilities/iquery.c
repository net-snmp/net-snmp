#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "utilities/iquery.h"

static netsnmp_session *iquery_default_session = NULL;

void init_iquery(void){
}

    /**************************
     *
     *  APIs to construct an "internal query" session
     *
     **************************/

netsnmp_session *netsnmp_iquery_pdu_session(netsnmp_pdu* pdu){
    if (!pdu)
       return NULL;
    if (pdu->version == SNMP_VERSION_3)
        return netsnmp_iquery_session( pdu->securityName, 
                           pdu->version,
                           pdu->securityModel,
                           pdu->securityLevel,
                           pdu->securityEngineID,
                           pdu->securityEngineIDLen);
    else
        return netsnmp_iquery_session( pdu->community, 
                           pdu->version,
                           pdu->version+1,
                           SNMP_SEC_LEVEL_NOAUTH,
                           pdu->securityEngineID,
                           pdu->securityEngineIDLen);
}

netsnmp_session *netsnmp_iquery_user_session(char* secName){
    u_char eID[SNMP_MAXBUF_SMALL];
    size_t elen = snmpv3_get_engineID(eID, sizeof(eID));

    return netsnmp_iquery_session( secName, 
                           SNMP_MP_MODEL_SNMPv3,
                           SNMP_SEC_MODEL_USM,
                           SNMP_SEC_LEVEL_AUTHNOPRIV, eID, elen);
}

netsnmp_session *netsnmp_iquery_community_session( char* community, int version ){
    u_char eID[SNMP_MAXBUF_SMALL];
    size_t elen = snmpv3_get_engineID(eID, sizeof(eID));

    return netsnmp_iquery_session( community, version, version+1,
                           SNMP_SEC_LEVEL_NOAUTH, eID, elen);
}

netsnmp_session *netsnmp_iquery_session( char* secName,   int   mpModel,
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
 * These are simple wrappers round the equivalent library routines
 */
int netsnmp_iquery_get(netsnmp_variable_list *list){
    return netsnmp_query_get(list, iquery_default_session);
}


int netsnmp_iquery_getnext(netsnmp_variable_list *list){
    return netsnmp_query_getnext(list, iquery_default_session);
}


int netsnmp_iquery_set(netsnmp_variable_list *list){
    return netsnmp_query_set(list, iquery_default_session);
}

int netsnmp_iquery_walk(netsnmp_variable_list *list){
    return netsnmp_query_walk(list, iquery_default_session);
}
