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
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
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
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#define SNMP_NEED_REQUEST_LIST
#include "asn1.h"
#include "mib.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "snmp_debug.h"
#include "snmp.h"
#include "ds_agent.h"
#include "default_store.h"

#include "protocol.h"
#include "client.h"
#include "master.h"
#include "master_admin.h"
#include "snmp_agent.h"
#include "snmp_vars.h"
#include "var_struct.h"
#include "mibII/sysORTable.h"

#define VARLIST_ITERATION	10

struct ax_variable_list {
    struct agent_snmp_session	*asp;
    int				num_vars;
    int				max_vars;
		/* Placeholder for dynamically-resized list of variables */
    struct variable_list*       variables[1];
};

void
free_agentx_request(struct request_list *req, int free_cback)
{
    if ( !req )
	return;

    /*
     *	Only free this call-back data when request processing has
     *	completed.  Multi-pass requests (i.e. SET and GETBULK handling)
     *	use this to store information that needs to be persistent
     *	from one pass to the next.
     */

    if ( req->cb_data && free_cback )
	free ( req->cb_data );

    free ( req );
}

void
free_agentx_varlist(struct ax_variable_list *vlist)
{
    if ( !vlist )
	return;
    if ( vlist->variables )
	free ( vlist->variables );
    free ( vlist );
}

	/*
	 * Remove the specified request from
	 *  the list of outstanding requests
	 *  and return it, for later disposal
	 */
struct request_list *
remove_outstanding_request( struct agent_snmp_session *asp, int reqid )
{
    struct request_list     *req, *prev;

    for (req = asp->outstanding_requests, prev=NULL ;
			req != NULL ;
			prev = req , req = req->next_request ) {
	if ( req->request_id == reqid) {
	    if ( prev )
		prev->next_request = req->next_request;
	    else
		asp->outstanding_requests = req->next_request;

	    return req;
	}
    }
    return NULL;
}

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
    struct variable_list *vbp, *next;
    struct agent_snmp_session *asp  =  ax_vlist->asp;
    struct snmp_session *ax_session;
    struct request_list *req, *oldreq;
    int  free_cback = 1;
    int i, type, index;
    int oldstatus;
    struct subtree          *retry_sub;
    char buf[SPRINT_MAX_LEN];

    oldreq = remove_outstanding_request( asp, pdu->reqid );

    switch(operation) {
	case TIMED_OUT:
			/*
			 * Multiple timed out requests probably
			 *  indicate that the subagent has died.
			 */
		if ( SET_SNMP_STRIKE_FLAGS( session->flags )) {
		    ax_session = session->subsession;
				/*
				 * XXX - Need to send a 'close' message
				 *       to the subagent (even though
				 *	 we don't think it's listening)
				 */
		    (void) close_agentx_session(ax_session, session->sessid);
		    if ( ax_session->subsession == NULL ) {
			snmp_close( ax_session );
		    }
		}
		pdu->errstat  = SNMP_ERR_GENERR;
		pdu->errindex = 0;
		if (asp->pdu->command != SNMP_MSG_SET)
		    asp->mode = RESERVE2;
		break;

	case SEND_FAILED:
		if ( SET_SNMP_STRIKE_FLAGS( session->flags )) {
		    (void) close_agentx_session(session, -1 );
		}
		pdu->errstat  = SNMP_ERR_GENERR;
		pdu->errindex = 0;
		if (asp->pdu->command != SNMP_MSG_SET)
		    asp->mode = RESERVE2;
		return 0;


	case RECEIVED_MESSAGE:
		/* This session is alive */
		CLEAR_SNMP_STRIKE_FLAGS( session->flags );
		break;
	default:
		return 0;
    }


    oldstatus = asp->status;
    asp->status = pdu->errstat;
    if ( pdu->errstat != AGENTX_ERR_NOERROR ) {
		/*
		 *  If the request failed, locate the
		 *    original index of the variable resonsible
		 */
	if ( pdu->errindex != 0 && pdu->errindex < ax_vlist->num_vars )
	    asp->index = ax_vlist->variables[pdu->errindex-1]->index;
        else
	    asp->index = 0;

    }
    else {
		/*
		 * Otherwise, process successful requests
		 */
	DEBUGMSGTL(("agentx/master","handle_agentx_response() beginning...\n"));
	for ( i = 0, vbp = pdu->variables ;
              vbp && i < ax_vlist->num_vars ;
              i++, vbp = vbp->next_variable ) {

            if (vbp) {
		DEBUGMSGTL(("agentx/master","  handle_agentx_response: processing: "));
		DEBUGMSGOID(("agentx/master",vbp->name, vbp->name_length));
		DEBUGMSG(("agentx/master","\n"));
		if ( ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE) ) {
		    sprint_variable (buf, vbp->name, vbp->name_length, vbp);
		    DEBUGMSGTL(("snmp_agent", "    >> %s\n", buf));
		}
	    }

	    if ( !asp->exact && (vbp->type == SNMP_ENDOFMIBVIEW ||
			     in_a_view( vbp->name, &vbp->name_length,
                                        asp->pdu,  vbp->type ))) {
	        /*
	         *   Retry unfulfilled requests
	         */
	        retry_sub = find_subtree_next( vbp->name, vbp->name_length, NULL );
	        if ( retry_sub ) {
		    (void)snmp_set_var_objid(ax_vlist->variables[i], retry_sub->name, retry_sub->namelen);
		    asp->index = ax_vlist->variables[i]->index;
		    asp->status = handle_one_var(asp, ax_vlist->variables[i]);
	        }
	        else
		    ax_vlist->variables[i]->type = SNMP_ENDOFMIBVIEW;
	    }
	    else {
		next  = ax_vlist->variables[i]->next_variable;
		index = ax_vlist->variables[i]->index;
        	snmp_clone_var( vbp, ax_vlist->variables[i] );
		ax_vlist->variables[i]->next_variable = next;
		ax_vlist->variables[i]->index         = index;
	    }

	    type = ax_vlist->variables[i]->type;
	    if ((asp->pdu->version == SNMP_VERSION_1) &&
	        ((type == SNMP_ENDOFMIBVIEW) || (type == SNMP_NOSUCHOBJECT) || (type == SNMP_NOSUCHINSTANCE))) {
		    asp->index = ax_vlist->variables[i]->index;
		    asp->status = SNMP_ERR_NOSUCHNAME;
		    goto finish;
	    }
	}
    }

	/*
	 *  If we're in the middle of a SET,
	 *	the state machine will have been updated on the
	 *	(mistaken) assumption that the request succeeded.
	 *  In fact the lack of an error from the 'agentx_var()'
	 *	routine  simply meant that the delegation succeeded. 
	 *
	 *  If the subagent reports that the request failed,
	 *	we need to tweak the mode to reflect this.
	 */
    if (asp->pdu->command == SNMP_MSG_SET) {
	switch( asp->mode ) {

	    case ACTION:	/* I.e. a 'successful' RESERVE2 pass */
		if ( asp->status != SNMP_ERR_NOERROR )
			asp->mode = FREE;
		break;

	    case COMMIT:	/* I.e. a 'successful' ACTION pass */
		if ( asp->status != SNMP_ERR_NOERROR )
			asp->mode = UNDO;
		break;

	    case FREE:
		asp->mode   = FINISHED_FAILURE;
		asp->status = oldstatus;
		break;

	    case FINISHED_SUCCESS:	/* I.e. a 'successful' COMMIT pass */
		if ( asp->status != SNMP_ERR_NOERROR ) {
			asp->mode   = FINISHED_FAILURE;
			asp->status = SNMP_ERR_COMMITFAILED;
		}
		break;

	    case FINISHED_FAILURE:	/* I.e. a 'successful' UNDO pass */
		if ( asp->status != SNMP_ERR_NOERROR ) {
			asp->mode   = FINISHED_FAILURE;
			asp->status = SNMP_ERR_UNDOFAILED;
		}
		else {
			asp->status = oldstatus;
		}
		break;
	}
    }


    if ( asp->outstanding_requests ) {
		/*
		 * Send out any newly delegated requests
		 * 	See 'handle_one_var' above
		 */
	for ( req=asp->outstanding_requests ; req ; req=req->next_request ) {
	    if ( req->pdu ) {
		snmp_async_send(req->session, req->pdu,
				req->callback, req->cb_data);
		req->pdu = NULL;
	    }
	}
    }

finish:
			 /*
			  * Free the old request, but if we
			  * haven't completed a multi-pass request,
			  * then don't free the callback data
			  */
    if ( oldreq ) {
	if ( oldreq->pdu && oldreq->pdu->command == SNMP_MSG_SET &&
		(( asp->mode == ACTION ) ||
		 ( asp->mode == COMMIT )))
	    free_cback = 0;
	free_agentx_request( oldreq, free_cback );
    }

    DEBUGMSGTL(("agentx/master","handle_agentx_response() finishing...\n"));
    return handle_snmp_packet(operation, session, reqid, asp->pdu, (void*)asp);
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
    int			    new_size;

    DEBUGMSGTL(("agentx/master","processing request...\n"));

    for (req = asp->outstanding_requests ; req != NULL ; req = req->next_request ) {
	if ( req->message_id == transID && req->session == ax_session) {
		/*
		 * Check if there's room in this request for another variable.
		 * If not, then expand it by 'VARLIST_ITERATION' variables.
		 */
	    vlist = (struct ax_variable_list *)req->cb_data;
	    if ( vlist->num_vars > vlist->max_vars ) {		/* i.e. full */
		DEBUGMSGTL(("agentx/master", "increasing ax_variable list...\n"));
		new_size = sizeof(struct ax_variable_list) +
		    (vlist->max_vars + VARLIST_ITERATION) * sizeof(struct variable_list);
		vlist = (struct ax_variable_list *)realloc(vlist, new_size);
		if ( !vlist )
		    break; 
		vlist->max_vars += VARLIST_ITERATION;
		req->cb_data = (void *)vlist;
	    }
	    return req;
	}
    }

		/*
		 * No existing request found, so create a new one
		 */
    req   = (struct request_list     *)calloc( 1, sizeof(struct request_list));
    new_size = sizeof(struct ax_variable_list) +
		VARLIST_ITERATION * sizeof(struct variable_list);
    vlist = (struct ax_variable_list *)calloc( 1, new_size);
    pdu   = snmp_pdu_create( 0 );
    if ( req == NULL || pdu == NULL || vlist == NULL ) {
	free_agentx_request( req, 1 );
	snmp_free_pdu(       pdu );
	free_agentx_varlist( vlist );
	return NULL;
    }

		/*
		 * Initialise the structures:
		 *	pdu,
		 */
    pdu->version     = AGENTX_VERSION_1;
    pdu->reqid       = snmp_get_next_transid();
    pdu->transid     = asp->pdu->transid;
    pdu->sessid      = ax_session->sessid;
    switch (asp->pdu->command ) {
	case SNMP_MSG_GET:
                DEBUGMSGTL(("agentx/master","-> get\n"));
		pdu->command = AGENTX_MSG_GET;
		break;
	case SNMP_MSG_GETNEXT:
	case SNMP_MSG_GETBULK:
                DEBUGMSGTL(("agentx/master","-> getnext/bulk\n"));
		pdu->command = AGENTX_MSG_GETNEXT;
		break;
	case SNMP_MSG_SET:
                DEBUGMSGTL(("agentx/master","-> set\n"));
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
                DEBUGMSGTL(("agentx/master","-> unknown\n"));
		free_agentx_request( req, 1 );
		snmp_free_pdu(       pdu );
		free_agentx_varlist( vlist );
		return NULL;
    }
   
		/*	callback data,		*/
    vlist->asp      = asp;
    vlist->num_vars = 0;

		/*	and request		*/
    req->request_id  = pdu->reqid;
    req->message_id  = pdu->transid;
    req->callback    = handle_agentx_response;
    req->cb_data     = vlist;
    req->pdu         = pdu;
    req->session     = ax_session;
		 
    req->next_request         = asp->outstanding_requests;
    asp->outstanding_requests = req;

    DEBUGMSGTL(("agentx/master","processing request...  DONE\n"));
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
    struct snmp_session *ax_session;
    struct request_list *request;
    struct ax_variable_list *ax_vlist;
    struct subtree      *sub;
    int			 sessid;

    if (asp->pdu->command == SNMP_MSG_SET && asp->mode == RESERVE1 )
	return AGENTX_ERR_NOERROR;

    ax_session = get_session_for_oid( vbp->name, vbp->name_length );
    if ( !ax_session )
	return SNMP_ERR_GENERR;
    sessid = ax_session->sessid;
    if ( ax_session->flags & SNMP_FLAGS_SUBSESSION )
	ax_session = ax_session->subsession;
    request    = get_agentx_request( asp, ax_session, pdu->transid );
    if ( !request )
	return SNMP_ERR_GENERR;
    request->pdu->sessid = sessid;	/* Use the registered (sub)session's ID,
					   not the main listening session ID */
    ax_vlist   = (struct ax_variable_list *)request->cb_data;

    ax_vlist->variables[ ax_vlist->num_vars ] = vbp;
    vbp->index = asp->index;	/* Remember the variable index */
    ax_vlist->num_vars++;
    
    sub = find_subtree_previous( vbp->name, vbp->name_length, NULL );
    if ( asp->exact )
        snmp_pdu_add_variable( request->pdu,
			   vbp->name, vbp->name_length, vbp->type,
			   (u_char*)(vbp->val.string), vbp->val_len);
    else {
        snmp_pdu_add_variable( request->pdu,
			   vbp->name, vbp->name_length, ASN_PRIV_EXCL_RANGE,
			   (u_char*)sub->end, sub->end_len*sizeof(oid));
    }
    if ( sub->timeout > (int)request->pdu->time ) {
	request->pdu->time = sub->timeout;
	request->pdu->flags |= UCD_MSG_FLAG_PDU_TIMEOUT;
    }

    return AGENTX_ERR_NOERROR;
}
