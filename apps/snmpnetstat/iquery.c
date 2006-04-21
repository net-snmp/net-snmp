#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#if HAVE_WINSOCK_H
#include <winsock.h>
#include "winstub.h"
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp_debug.h"
#include "main.h"

/*
 *
 *  Convenience routines to make various requests
 *  over the specified SNMP session.
 *
 */
static struct snmp_session *_def_query_session = NULL;
void
netsnmp_query_set_default_session( struct snmp_session *sess) {
    _def_query_session = sess;
}

struct snmp_session *
netsnmp_query_get_default_session( void ) {
    return _def_query_session;
}


/*
 * Internal utility routine to actually send the query
 */
static int _query(struct variable_list *list,
                  int                    request,
                  struct snmp_session       *session) {

    struct snmp_pdu *pdu      = snmp_pdu_create( request );
    struct snmp_pdu *response = NULL;
    struct variable_list *vb1, *vb2, *vtmp;
    int ret;

    /*
     * Clone the varbind list into the request PDU...
     */
    pdu->variables = snmp_clone_varbind( list );
retry:
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
            /*
             * If the request failed, then remove the
             *  offending varbind and try again.
             *  (all except SET requests)
             *
             * XXX - implement a library version of
              *       NETSNMP_DS_APP_DONT_FIX_PDUS ??
             */
            ret = response->errstat;
            if (request != SNMP_MSG_SET &&
                 response->errindex != 0) {
                pdu = snmp_fix_pdu( response, request );
                snmp_free_pdu( response );
                response = NULL;
                if ( pdu != NULL )
                    goto retry;
            }
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
int netsnmp_query_get(struct variable_list *list,
                      struct snmp_session       *session){
    return _query( list, SNMP_MSG_GET, session );
}


int netsnmp_query_getnext(struct variable_list *list,
                          struct snmp_session       *session){
    return _query( list, SNMP_MSG_GETNEXT, session );
}


int netsnmp_query_set(struct variable_list *list,
                      struct snmp_session       *session){
    return _query( list, SNMP_MSG_SET, session );
}

/*
 * A walk needs a bit more work.
 */
int netsnmp_query_walk(struct variable_list *list,
                       struct snmp_session       *session) {
    /*
     * Create a working copy of the original (single)
     * varbind, so we can use this varbind parameter
     * to check when we've finished walking this subtree.
     */
    struct variable_list *vb = snmp_clone_varbind( list );
    struct variable_list *res_list = NULL;
    struct variable_list *res_last = NULL;
    int ret;
    int len;

    /*
     * Now walk the tree as usual
     */
    ret = _query( vb, SNMP_MSG_GETNEXT, session );
    while ( ret == SNMP_ERR_NOERROR ) {
        len = (( list->name_length < vb->name_length ) ?
                 list->name_length : vb->name_length );
        if ( snmp_oid_compare( list->name, len, vb->name, len ) != 0)
            break;

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
