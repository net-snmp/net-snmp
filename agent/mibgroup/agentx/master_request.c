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
#include "ds_agent.h"
#include "default_store.h"

#include "agentx/protocol.h"
#include "agentx/client.h"
#include "agentx/master.h"
#include "snmp_agent.h"
#include "snmp_vars.h"
#include "var_struct.h"
#include "mibII/sysORTable.h"

#define VARLIST_ITERATION	10

struct ax_variable_list {
    struct agent_snmp_session	*asp;
    int				num_vars;
    int				max_vars;
#ifdef ONE_IDEA
    {
	struct variable_list    *entry;
	int		        index;
    }				variables[MAX_VARS];
#else
		/* Placeholder for dynamically-resized list of variables */
    struct variable_list*        variables[1];
#endif
};

	/*
	 * Remove the specified request from
	 *  the list of outstanding requests
	 */
int
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
	    free( req );
	    return 0;
	}
    }
    return 1;
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
    int i;
    struct ax_variable_list *retry_vlist;
    struct variable_list    *vb_retry, *vbp2;
    struct subtree          *retry_sub;
    int j;
    char buf[SPRINT_MAX_LEN];

    remove_outstanding_request( asp, pdu->reqid );

    retry_vlist = NULL;
    vb_retry    = NULL;
    vbp2        = NULL;

    DEBUGMSGTL(("agentx/master","handle_agentx_response() beginning...\n"));
    for ( i = 0, vbp = pdu->variables ;
          vbp && i < ax_vlist->num_vars ;
          i++, vbp = vbp->next_variable ) {

      if (vbp) {
        DEBUGMSGTL(("agentx/master","  handle_agentx_response: processing: "));
        DEBUGMSGOID(("agentx/master",vbp->name, vbp->name_length));
        DEBUGMSG(("agentx/master","\n"));
      }
	if ( ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE) ) {
	    sprint_variable (buf, vbp->name, vbp->name_length, vbp);
	    DEBUGMSGTL(("snmp_agent", "    >> %s\n", buf));
	}

	if ( !asp->exact && (vbp->type == SNMP_ENDOFMIBVIEW ||
			     in_a_view( vbp->name, &vbp->name_length,
                                        asp->pdu,  vbp->type ))) {
	    /*
	     *   Add unfulfilled requests to "retry" list
	     */
	    retry_sub = find_subtree_next( vbp->name, vbp->name_length, NULL );
	    if ( retry_sub == NULL ) {
		next = ax_vlist->variables[i]->next_variable;
	        snmp_clone_var( vbp, ax_vlist->variables[i] );
		ax_vlist->variables[i]->next_variable = next;
			/* XXX - handle SNMPv1 */
		ax_vlist->variables[i]->type = SNMP_ENDOFMIBVIEW;
		continue;
	    }
	    if (retry_vlist == NULL ) {
		retry_vlist = (struct ax_variable_list *)
				calloc( 1, sizeof( struct ax_variable_list));
		if (retry_vlist == NULL)
		    break;

		vb_retry = (struct variable_list *)
				calloc( 1, sizeof( struct variable_list));
		if (vb_retry == NULL) {
		    free(retry_vlist);
		    break;
		}

		vbp2 = vb_retry;
	    }
	    else {
		vbp2->next_variable = (struct variable_list *)
				calloc( 1, sizeof( struct variable_list));
		if (vbp2->next_variable == NULL)
		    break;
		vbp2 = vbp2->next_variable;
	    }
	    j = retry_vlist->num_vars;
	    retry_vlist->variables[ j ] = ax_vlist->variables[i];
	    retry_vlist->num_vars++;
	    memcpy(vbp->name, retry_sub->name, retry_sub->namelen * sizeof(oid));
	    vbp->name_length = retry_sub->namelen;
	    next = vbp2->next_variable;
	    snmp_clone_var( vbp, vbp2 );
	    vbp2->next_variable = next;
	}
	else
		/* Got an answer, so use it */
	if ( pdu->errstat != AGENTX_ERR_NOERROR ) {
	    asp->status = pdu->errstat;
	}
	else {
	    next = ax_vlist->variables[i]->next_variable;
	    snmp_clone_var( vbp, ax_vlist->variables[i] );
	    ax_vlist->variables[i]->next_variable = next;
	}	
    }


    if ( retry_vlist ) {
		/*
		 * unfulfilled GETNEXT requests
		 *
		 * Need a new 'handle_getnext_request' routine
		 *   (parameters to be determined)
		 */
	asp->start = vb_retry;
	asp->end   = vbp2;
	j = handle_var_list( asp );
	if ( j != SNMP_ERR_NOERROR )
	    asp->status = j;
	else for ( i = 0, vbp2 = vb_retry ;
	           i < retry_vlist->num_vars ;
	           i++ , vbp2=vbp2->next_variable ) {
			/*
			 * XXX - assumes success second time around
			 *	Needs to handle deferrals / failures
			 */
	    		next = retry_vlist->variables[i]->next_variable;
	 		snmp_clone_var( vbp2, retry_vlist->variables[i] );
	    		retry_vlist->variables[i]->next_variable = next;
	}
	return j;
    }
    else
      DEBUGMSGTL(("agentx/master","handle_agentx_response() finishing...\n"));
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
	free( pdu );
	free( vlist );
	free( req );
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
    sessid = ax_session->sessid;
		/* WHat if this returns NULL ? */
    if ( ax_session->flags & SNMP_FLAGS_SUBSESSION )
	ax_session = ax_session->subsession;
    request    = get_agentx_request( asp, ax_session, pdu->transid );
    request->pdu->sessid = sessid;	/* Use the registered (sub)session's ID,
					   not the main listening session ID */
    ax_vlist   = (struct ax_variable_list *)request->cb_data;

    ax_vlist->variables[ ax_vlist->num_vars ] = vbp;
    ax_vlist->num_vars++;
    
    if ( asp->exact )
        snmp_pdu_add_variable( request->pdu,
			   vbp->name, vbp->name_length, vbp->type,
			   (u_char*)(vbp->val.string), vbp->val_len);
    else {
	sub = find_subtree_previous( vbp->name, vbp->name_length, NULL );
        snmp_pdu_add_variable( request->pdu,
			   vbp->name, vbp->name_length, ASN_PRIV_EXCL_RANGE,
			   (u_char*)sub->end, sub->end_len);
    }

    return AGENTX_ERR_NOERROR;
}
