/*
 *  master_request.c
 *
 *  Handle passing SNMP requests to and from AgentX clients
 */

#include "config.h"

#include <stdio.h>
#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#define SNMP_NEED_REQUEST_LIST
#include "asn1.h"
#include "mib.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "snmp_debug.h"
#include "snmp.h"

#include "agentx/protocol.h"
#include "agentx/client.h"
#include "agentx/master.h"
#include "snmp_agent.h"
#include "snmp_vars.h"
#include "var_struct.h"
#include "mibII/sysORTable.h"

#define MAX_VARS	16

struct ax_variable_list {
    struct agent_snmp_session	*asp;
    int				num_vars;
#ifdef ONE_IDEA
    {
	struct variable_list    *entry;
	int		        index;
    }				variables[MAX_VARS];
#else
    struct variable_list*        variables[MAX_VARS];
#endif
};

extern int verbose;

	/*
	 * Handle the response from an AgentX subagent,
	 *   merging the answers back into the original query
	 */
int
handle_agentx_response( int operation,
		    struct snmp_session *session,
		    int reqid,
		    struct snmp_pdu *pdu,
		    void *magic)
{
    struct ax_variable_list *ax_vlist = (struct ax_variable_list *)magic;
    struct variable_list *vbp;
    struct agent_snmp_session *asp  =  ax_vlist->asp;
    int i;
    char buf[SPRINT_MAX_LEN];

    asp->outstanding_requests = NULL;

    for ( i = 0, vbp = pdu->variables ;
		i < ax_vlist->num_vars ; i++, vbp = vbp->next_variable ) {

	if ( verbose ) {
	    sprint_variable (buf, vbp->name, vbp->name_length, vbp);
	    DEBUGMSGTL(("snmp_agent", "    >> %s\n", buf));
	}
#ifdef STILL_TO_CODE
	if ( !asp->exact && (vbp->type == ENDOFMIB || !in_view())) {
	    /* Add to "oustanding query" list */
	}
	else
#endif
	if ( pdu->errstat != AGENTX_ERR_NOERROR ) {
	    asp->status = pdu->errstat;
	}
	else
	    snmp_clone_var( vbp, ax_vlist->variables[i] );
	
    }


#ifdef STILL_TO_CODE
    if ( asp->outstanding_requests )
		/*
		 * unfulfilled GETNEXT requests
		 *
		 * Need a new 'handle_getnext_request' routine
		 *   (parameters to be determined)
		 */
	return handle_getnext_request(operation, session, reqid,
					asp->pdu, (void*)asp);
    else
#endif
	return handle_snmp_packet(operation, session, reqid,
					asp->pdu, (void*)asp);
}




	/*
	 * Return the request for this subagent transaction
	 *   (creating a new one if necessary)
	 */
struct request_list *
get_agentx_request(struct agent_snmp_session *asp,
                   struct snmp_session *ax_session, int transID )
{
    struct request_list     *req;
    struct snmp_pdu         *pdu;
    struct ax_variable_list *vlist;

    for (req = asp->outstanding_requests ; req != NULL ; req = req->next_request ) {
	if ( req->request_id == transID)		/* ??? */
	    return req;
    }

		/*
		 * No existing request found, so create a new one
		 */
    req   = (struct request_list     *)malloc(sizeof(struct request_list));
    vlist = (struct ax_variable_list *)malloc(sizeof(struct ax_variable_list));
    pdu   = snmp_pdu_create( 0 );
    if ( req == NULL || pdu == NULL || vlist == NULL ) {
	free( pdu );
	free( vlist );
	free( req );
	return NULL;
    }
    memset( req,   0, sizeof( struct request_list ));
    memset( vlist, 0, sizeof( struct ax_variable_list ));

		/*
		 * Initialise the structures:
		 *	pdu,
		 */
    pdu->version     = AGENTX_VERSION_1;
    pdu->reqid       = transID;		/* ??? */
    pdu->msgid       = transID;		/* ??? */
    pdu->sessid      = ax_session->sessid;
    switch (asp->pdu->command ) {
	case SNMP_MSG_GET:
		pdu->command = AGENTX_MSG_GET;
		break;
	case SNMP_MSG_GETNEXT:
	case SNMP_MSG_GETBULK:
		pdu->command = AGENTX_MSG_GETNEXT;
		break;
	case SNMP_MSG_SET:
		switch ( asp->mode ) {
				/*
				 * This is a provisional mapping of
				 *   UCD SET handling into the AgentX
				 *   protocol.
				 * It is by no means definitive.
				 */
		    case RESERVE1:
		    case RESERVE2:
				pdu->command = AGENTX_MSG_TESTSET;
				break;
		    case ACTION:
				pdu->command = AGENTX_MSG_COMMITSET;
				break;
		    case UNDO:
				pdu->command = AGENTX_MSG_UNDOSET;
				break;
		    case FREE:
		    case COMMIT:
				pdu->command = AGENTX_MSG_CLEANUPSET;
				break;
		}
		break;
	default:
		free( req );
		free( pdu );
		free( vlist );
		return NULL;
    }
   
		/*	callback data,		*/
    vlist->asp      = asp;
    vlist->num_vars = 0;

		/*	and request		*/
    req->request_id  = pdu->reqid;
    req->message_id  = pdu->msgid;
    req->callback    = handle_agentx_response;
    req->cb_data     = vlist;
    req->pdu         = pdu;
    req->session     = ax_session;
		 
    req->next_request         = asp->outstanding_requests;
    asp->outstanding_requests = req;

    return req;
}




	/*
	 * Delegate a request to an AgentX subagent
	 *   adding it to the list for that particular agent
	 */
int
agentx_add_request( struct agent_snmp_session *asp,
		    struct variable_list *vbp)
{
    struct snmp_pdu     *pdu = asp->pdu;
    int                  transID;
    struct snmp_session *ax_session;
    struct request_list *request;
    struct ax_variable_list *ax_vlist;
    struct subtree      *sub;

				/* Or msgid ? */
    transID    = get_agentx_transID( pdu->reqid, &(pdu->address));
    ax_session = get_session_for_oid( vbp->name, vbp->name_length );
    if ( ax_session->flags & SNMP_FLAGS_SUBSESSION )
	ax_session = ax_session->subsession;
    request    = get_agentx_request( asp, ax_session, transID );
    ax_vlist   = (struct ax_variable_list *)request->cb_data;

    ax_vlist->variables[ ax_vlist->num_vars ] = vbp;
    ax_vlist->num_vars++;
    
    if ( asp->exact )
        snmp_pdu_add_variable( request->pdu,
			   vbp->name, vbp->name_length, vbp->type,
			   (u_char*)&(vbp->val), vbp->val_len);
    else {
	sub = find_subtree_next( vbp->name, vbp->name_length, NULL );
        snmp_pdu_add_variable( request->pdu,
			   vbp->name, vbp->name_length, ASN_PRIV_INCL_RANGE,
			   (u_char*)sub->name, sub->namelen);
    }

    return AGENTX_ERR_NOERROR;
}
