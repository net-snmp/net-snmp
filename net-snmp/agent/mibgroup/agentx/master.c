/*
 *  AgentX master agent
 */

#include <net-snmp/net-snmp-config.h>

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
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <errno.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "snmpd.h"
#include "agentx/protocol.h"
#include "agentx/master_admin.h"

void real_init_master(void)
{
    netsnmp_session sess, *session;

    if ( ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE) != MASTER_AGENT )
	return;

    DEBUGMSGTL(("agentx/master","initializing...\n"));
    snmp_sess_init( &sess );
    sess.version  = AGENTX_VERSION_1;
    sess.flags  |= SNMP_FLAGS_STREAM_SOCKET;
    if ( ds_get_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET) )
	sess.peername = ds_get_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET);
    else
	sess.peername = AGENTX_SOCKET;

    if ( sess.peername[0] == '/' ) {
			/*
			 *  If this is a Unix pathname,
			 *  try and create the directory first.
			 */
	if (mkdirhier(sess.peername, AGENT_DIRECTORY_MODE, 1)) {
            snmp_log(LOG_ERR,
		"Failed to create the directory for the agentX socket: %s\n",
                 sess.peername);
	}
    }

			/*
			 *  Otherwise, let 'snmp_open' interpret the string.
			 */
    sess.local_port = AGENTX_PORT;         /* Indicate server & set default port */
    sess.remote_port = 0;
    sess.callback = handle_master_agentx_packet;
    session = snmp_open_ex(&sess, NULL, agentx_parse, NULL, NULL,
			   agentx_realloc_build, agentx_check_packet);

    if ( session == NULL && sess.s_errno == EADDRINUSE ) {
		/*
		 * Could be a left-over socket (now deleted)
		 * Try again
		 */
        session = snmp_open_ex(&sess, NULL, agentx_parse, NULL, NULL,
			       agentx_realloc_build, agentx_check_packet);
    }

    if ( session == NULL ) {
      /* diagnose snmp_open errors with the input netsnmp_session pointer */
	snmp_sess_perror("real_init_master", &sess);
	if (!ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS))
	    exit(1);
    }

    DEBUGMSGTL(("agentx/master","initializing...   DONE\n"));
}

	/*
	 * Handle the response from an AgentX subagent,
	 *   merging the answers back into the original query
	 */
int
agentx_got_response(int operation,
		    netsnmp_session *session,
		    int reqid,
		    netsnmp_pdu *pdu,
		    void *magic)
{
    netsnmp_delegated_cache *cache = (netsnmp_delegated_cache *) magic;
    int i, ret;
    netsnmp_request_info *requests, *request;
    netsnmp_variable_list *var;
    netsnmp_session *ax_session;

    cache = netsnmp_handler_check_cache(cache);
    if (!cache) {
        DEBUGMSGTL(("agentx/master", "response too late on session %08p\n",
		    session));
        return 0;
    }
    requests = cache->requests;

    switch (operation) {
    case NETSNMP_CALLBACK_OP_TIMED_OUT: {
	void *s = snmp_sess_pointer(session);
	DEBUGMSGTL(("agentx/master", "timeout on session %08p\n", session));

	/*  This is a bit sledgehammer because the other sessions on this
	    transport may be okay (e.g. some thread in the subagent has
	    wedged, but the others are alright).  OTOH the overwhelming
	    probability is that the whole agent has died somehow.  */

	if (s != NULL) {
	    netsnmp_transport *t = snmp_sess_transport(s);
	    close_agentx_session(session, -1);

	    if (t != NULL) {
		DEBUGMSGTL(("agentx/master", "close transport\n"));
		t->f_close(t);
	    } else {
		DEBUGMSGTL(("agentx/master", "NULL transport??\n"));
	    }
	} else {
	    DEBUGMSGTL(("agentx/master", "NULL sess_pointer??\n"));
	}
	netsnmp_handler_mark_requests_as_delegated(requests, REQUEST_IS_NOT_DELEGATED);
	netsnmp_set_request_error(cache->reqinfo, requests, /* XXXWWW: should be index=0 */
			  SNMP_ERR_GENERR);
	ax_session = (netsnmp_session *) cache->localinfo;
	netsnmp_free_agent_snmp_session_by_session(ax_session, NULL);
	netsnmp_free_delegated_cache(cache);
	return 0;
    }

    case NETSNMP_CALLBACK_OP_DISCONNECT:
    case NETSNMP_CALLBACK_OP_SEND_FAILED:
	if (operation == NETSNMP_CALLBACK_OP_DISCONNECT) {
	    DEBUGMSGTL(("agentx/master", "disconnect on session %08p\n",
			session));
	} else {
	    DEBUGMSGTL(("agentx/master", "send failed on session %08p\n",
			session));
	}
	close_agentx_session(session, -1);
	netsnmp_handler_mark_requests_as_delegated(requests, REQUEST_IS_NOT_DELEGATED);
	netsnmp_set_request_error(cache->reqinfo, requests, /* XXXWWW: should be index=0 */
			  SNMP_ERR_GENERR);
	netsnmp_free_delegated_cache(cache);
	return 0;

    case NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE:
	/* This session is alive */
	CLEAR_SNMP_STRIKE_FLAGS( session->flags );
	break;
    default:
	netsnmp_free_delegated_cache(cache);
	return 0;
    }


    if (pdu->errstat != AGENTX_ERR_NOERROR) {
        /*
         *  If the request failed, locate the
         *    original index of the variable resonsible
         */
	DEBUGMSGTL(("agentx/master","agentx_got_response() error branch\n"));
        ret = 0;
        for(request = requests, i = 1; request; request = request->next, i++) {
            if (request->index == pdu->errindex) {
                /* mark this one as the one generating the error */
                netsnmp_set_request_error(cache->reqinfo, request,
                                  pdu->errstat);
                ret = 1;
            }
            request->delegated = REQUEST_IS_NOT_DELEGATED;
        }
        if (!ret) {
            /* ack, unknown, mark the first one */
            netsnmp_set_request_error(cache->reqinfo, request, SNMP_ERR_GENERR);
	}
        netsnmp_free_delegated_cache(cache);
	DEBUGMSGTL(("agentx/master","end error branch\n"));
        return 1;
    } else if (cache->reqinfo->mode == MODE_GET     ||
               cache->reqinfo->mode == MODE_GETNEXT ||
               cache->reqinfo->mode == MODE_GETBULK) {
        /*  Replace varbinds for data request types, but not SETs.  */
	DEBUGMSGTL(("agentx/master", "agentx_got_response() beginning...\n"));
        for (var = pdu->variables, request = requests;
	     request && var;
	     request = request->next, var = var->next_variable) {
            /*
	     * Otherwise, process successful requests
	     */
            DEBUGMSGTL(("agentx/master", "  handle_agentx_response: processing: "));
            DEBUGMSGOID(("agentx/master", var->name, var->name_length));
            DEBUGMSG(("agentx/master", "\n"));
            if (ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE)) {
		DEBUGMSGTL(("snmp_agent", "    >> "));
		DEBUGMSGVAR(("snmp_agent", var));
		DEBUGMSG(("snmp_agent", "\n"));
            }

            /* update the oid in the original request */
            if (var->type != SNMP_ENDOFMIBVIEW) {
                snmp_set_var_typed_value(request->requestvb, var->type,
                                         var->val.string, var->val_len);
                snmp_set_var_objid(request->requestvb, var->name,
                                   var->name_length);
            }
            request->delegated = REQUEST_IS_NOT_DELEGATED;
	}

        if (request || var) {
            /* ack, this is bad.  The # of varbinds don't match and
               there is no way to fix the problem */
            snmp_log(LOG_ERR,
                     "response to agentx request illegal.  We're screwed.\n");
            netsnmp_set_request_error(cache->reqinfo, requests, SNMP_ERR_GENERR);
        }

        if (cache->reqinfo->mode == MODE_GETBULK)
            bulk_to_next_fix_requests(requests);
    } else {
        /* mark set requests as handled */
        for(request = requests; request; request = request->next) {
            request->delegated = REQUEST_IS_NOT_DELEGATED;
        }
    }
    DEBUGMSGTL(("agentx/master","handle_agentx_response() finishing...\n"));
    netsnmp_free_delegated_cache(cache);
    return 1;
}

/*
 *
 * AgentX State diagram.  [mode] = internal mode it's mapped from:
 *
 * TESTSET -success-> COMMIT -success-> CLEANUP
 * [RESERVE1]         [ACTION]          [COMMIT]
 *    |                 |
 *    |                 \--failure-> UNDO
 *    |                              [UNDO]
 *    |
 *     --failure-> CLEANUP
 *                 [FREE]
 */
int
agentx_master_handler(
    netsnmp_mib_handler               *handler,
    netsnmp_handler_registration      *reginfo,
    netsnmp_agent_request_info        *reqinfo,
    netsnmp_request_info              *requests)
{
    netsnmp_session *ax_session = (netsnmp_session *)handler->myvoid;
    netsnmp_request_info        *request = requests;
    netsnmp_pdu     *pdu;

    DEBUGMSGTL(("agentx/master", "agentx master handler starting, mode = 0x%02x\n",
                reqinfo->mode));
    
    /* build a new pdu based on the pdu type coming in */
    switch(reqinfo->mode) {
        case MODE_GET:
            pdu = snmp_pdu_create(AGENTX_MSG_GET);
            break;
            
        case MODE_GETNEXT:
            pdu = snmp_pdu_create(AGENTX_MSG_GETNEXT);
            break;

        case MODE_GETBULK: /* WWWXXX */
            pdu = snmp_pdu_create(AGENTX_MSG_GETNEXT);
            break;
            
        case MODE_SET_RESERVE1:
            pdu = snmp_pdu_create(AGENTX_MSG_TESTSET);
            break;

        case MODE_SET_RESERVE2:
            /* don't do anything here for AgentX.  Assume all is fine
               and go on since AgentX only has one test phase. */
            return SNMP_ERR_NOERROR;
            
        case MODE_SET_ACTION:
            pdu = snmp_pdu_create(AGENTX_MSG_COMMITSET);
            break;

        case MODE_SET_UNDO:
            pdu = snmp_pdu_create(AGENTX_MSG_UNDOSET);
            break;

        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
            pdu = snmp_pdu_create(AGENTX_MSG_CLEANUPSET);
            break;

        default:
            snmp_log(LOG_WARNING, "unsupported mode for agentx/master called\n");
            return SNMP_ERR_NOERROR;
    }

    if (!pdu || !ax_session) {
        netsnmp_set_request_error(reqinfo, requests, SNMP_ERR_GENERR);
        return SNMP_ERR_NOERROR;
    }

    pdu->version     = AGENTX_VERSION_1;
    pdu->reqid       = snmp_get_next_transid();
    pdu->transid     = reqinfo->asp->pdu->transid;
    pdu->sessid      = ax_session->sessid;

    while (request) {

        /* loop through all the requests and create agentx ones out of them */

        if (reqinfo->mode == MODE_GETNEXT || reqinfo->mode == MODE_GETBULK) {
	    size_t nlen = request->requestvb->name_length;
	    oid *nptr   = request->requestvb->name;
	    
	    if (snmp_oid_compare(nptr, nlen, request->subtree->start,
				 request->subtree->start_len) < 0) {
		DEBUGMSGTL(("agentx/master","inexact request for variable ("));
		DEBUGMSGOID(("agent/master", nptr, nlen));
		DEBUGMSG(("agentx/master", ") preceeding region ("));
		DEBUGMSGOID(("agent/master", request->subtree->start,
			     request->subtree->start_len));
		DEBUGMSG(("agentx/master", ")\n"));
		nptr = request->subtree->start;
		nlen = request->subtree->start_len;
	    }

	    if (request->inclusive) {
		DEBUGMSGTL(("agentx/master", "INCLUSIVE varbind "));
		DEBUGMSGOID(("agentx/master", nptr, nlen));
		DEBUGMSG(("agentx/master", " scoped to "));
		DEBUGMSGOID(("agentx/master", request->range_end,
			     request->range_end_len));
		DEBUGMSG(("agentx/master", "\n"));
		snmp_pdu_add_variable(pdu, nptr, nlen, ASN_PRIV_INCL_RANGE,
				      (u_char *)request->range_end,
				      request->range_end_len * sizeof(oid));
	    } else {
		DEBUGMSGTL(("agentx/master", "EXCLUSIVE varbind "));
		DEBUGMSGOID(("agentx/master", nptr, nlen));
		DEBUGMSG(("agentx/master", " scoped to "));
		DEBUGMSGOID(("agentx/master", request->range_end,
			     request->range_end_len));
		DEBUGMSG(("agentx/master", "\n"));
		snmp_pdu_add_variable(pdu, nptr, nlen, ASN_PRIV_EXCL_RANGE,
				      (u_char *)request->range_end,
				      request->range_end_len * sizeof(oid));
	    }
        } else {
            snmp_pdu_add_variable(pdu, request->requestvb->name,
                                  request->requestvb->name_length,
                                  request->requestvb->type,
                                  request->requestvb->val.string,
                                  request->requestvb->val_len);
        }
        
        /* mark the request as delayed */
        if (pdu->command != AGENTX_MSG_CLEANUPSET)
            request->delegated = 1;
        else
            request->delegated = 0;

        /* next... */
        request = request->next;
    }

    /* send the requests out */
    DEBUGMSGTL(("agentx", "sending pdu\n"));
    snmp_async_send(ax_session, pdu, agentx_got_response,
                    netsnmp_create_delegated_cache(handler, reginfo, reqinfo, requests,
                                           (void *) ax_session));
    return SNMP_ERR_NOERROR;
}

