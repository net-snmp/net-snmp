/*
 *   AgentX utility routines
 */

#include <config.h>

#include <stdio.h>
#include <errno.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
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

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "asn1.h"
#include "system.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "snmp.h"
#include "snmp_debug.h"
#include "snmp_vars.h"
#include "agent_registry.h"
#include "agent_index.h"

#include "agentx/protocol.h"
#include "agentx/client.h"

extern struct timeval starttime;

	/*
	 * AgentX handling utility routines
	 *
	 * Mostly wrappers round, or re-writes of
	 *   the SNMP equivalents
	 */

int
agentx_synch_input(int op,
			struct snmp_session *session,
			int reqid,
			struct snmp_pdu *pdu,
			void *magic)
{
    struct synch_state *state = (struct synch_state *)magic;
    struct timeval now, diff;

    if ( reqid != state->reqid )
	return 0;

    DEBUGMSGTL(("agentx/subagent","synching input\n"));
    state->waiting = 0;
    if (op == RECEIVED_MESSAGE) {
	if (pdu->command == AGENTX_MSG_RESPONSE) {
	    state->pdu		= snmp_clone_pdu(pdu);
	    state->status	= STAT_SUCCESS;
	    session->s_snmp_errno = SNMPERR_SUCCESS;

		/*
		 * Synchronise sysUpTime with the master agent
		 */
          gettimeofday( &now, NULL );
          now.tv_sec--;
          now.tv_usec += 1000000L;
          diff.tv_sec  = pdu->time/100;
          diff.tv_usec = (pdu->time - (diff.tv_sec * 100)) * 10000;
          starttime.tv_sec  = now.tv_sec  - diff.tv_sec;
          starttime.tv_usec = now.tv_usec - diff.tv_usec;
          if ( starttime.tv_usec > 1000000L ) {
              starttime.tv_usec -= 1000000L;
              starttime.tv_sec++;
          }
	}
    }
    else if (op == TIMED_OUT){
	state->pdu		= NULL;
	state->status		= STAT_TIMEOUT;
	session->s_snmp_errno	= SNMPERR_TIMEOUT;
    }

    return 1;
}



int
agentx_synch_response( struct snmp_session *ss, struct snmp_pdu *pdu, struct snmp_pdu **response )
{
    return snmp_synch_response_cb(ss, pdu, response, agentx_synch_input);
}


	/*
	 * AgentX PofE convenience functions
	 */

int
agentx_open_session( struct snmp_session *ss )
{
    struct snmp_pdu *pdu, *response;
    extern oid version_id[];
    extern oid version_id_len;

    DEBUGMSGTL(("agentx/subagent","opening session \n"));
    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_OPEN);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    snmp_add_var( pdu, version_id, version_id_len, 's', "UCD AgentX sub-agent");

    if ( agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS )
	return 0;

    if ( response->errstat != SNMP_ERR_NOERROR ) {
	snmp_free_pdu(response);
	return 0;
    }

    ss->sessid = response->sessid;
    snmp_free_pdu(response);
    DEBUGMSGTL(("agentx/subagent","open \n"));
    return 1;
}

int
agentx_close_session( struct snmp_session *ss, int why )
{
    struct snmp_pdu *pdu, *response;
    DEBUGMSGTL(("agentx/subagent","closing session\n"));

    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_CLOSE);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    pdu->errstat = why;
    pdu->sessid  = ss->sessid;

    (void) agentx_synch_response(ss, pdu, &response);
    snmp_free_pdu(response);
    DEBUGMSGTL(("agentx/subagent","closed\n"));
    return 1;
}

int
agentx_register( struct snmp_session *ss, oid start[], size_t startlen,
		 int priority, int range_subid, oid range_ubound, int timeout)
{
    struct snmp_pdu *pdu, *response;

    DEBUGMSGTL(("agentx/subagent","registering: "));
    DEBUGMSGOID(("agentx/subagent", start, startlen));
    DEBUGMSG(("agentx/subagent","\n"));
    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_REGISTER);
    if ( pdu == NULL )
	return 0;
    pdu->time = timeout;
    pdu->priority = priority;
    pdu->sessid = ss->sessid;
    pdu->range_subid = range_subid;
    if ( range_subid ) {
	snmp_pdu_add_variable( pdu, start, startlen,
				ASN_OBJECT_ID, (u_char *)start, startlen*sizeof(oid));
	pdu->variables->val.objid[ range_subid-1 ] = range_ubound;
    }
    else
	snmp_add_null_var( pdu, start, startlen);

    if ( agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS ) {
        DEBUGMSGTL(("agentx/subagent","registering failed!\n"));
        return 0;
    }

    if ( response->errstat != SNMP_ERR_NOERROR ) {
        DEBUGMSGTL(("agentx/subagent","registering pdu failed: %d!\n",
                    response->errstat));
	snmp_free_pdu(response);
	return 0;
    }

    snmp_free_pdu(response);
    DEBUGMSGTL(("agentx/subagent","registered\n"));
    return 1;
}

int
agentx_unregister( struct snmp_session *ss, oid start[], size_t startlen,
		   int priority, int range_subid, oid range_ubound)
{
    struct snmp_pdu *pdu, *response;

    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    DEBUGMSGTL(("agentx/subagent","unregistering: "));
    DEBUGMSGOID(("agentx/subagent", start, startlen));
    DEBUGMSG(("agentx/subagent","\n"));
    pdu = snmp_pdu_create(AGENTX_MSG_UNREGISTER);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    pdu->priority = priority;
    pdu->sessid = ss->sessid;
    pdu->range_subid = range_subid;
    if ( range_subid ) {
	snmp_pdu_add_variable( pdu, start, startlen,
				ASN_OBJECT_ID, (u_char *)start, startlen*sizeof(oid));
	pdu->variables->val.objid[ range_subid-1 ] = range_ubound;
    }
    else
	snmp_add_null_var( pdu, start, startlen);

    if ( agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS )
	return 0;

    if ( response->errstat != SNMP_ERR_NOERROR ) {
	snmp_free_pdu(response);
	return 0;
    }

    snmp_free_pdu(response);
    DEBUGMSGTL(("agentx/subagent","unregistered\n"));
    return 1;
}

struct variable_list *
agentx_register_index( struct snmp_session *ss,
		      struct variable_list* varbind, int flags)
{
    struct snmp_pdu *pdu, *response;
    struct variable_list *varbind2;

    if (! IS_AGENTX_VERSION( ss->version ))
	return NULL;

		/*
		 * Make a copy of the index request varbind
		 *    for the AgentX request PDU
		 *    (since the pdu structure will be freed)
		 */
    varbind2 = (struct variable_list *)malloc(sizeof(struct variable_list));
    if ( varbind2 == NULL )
	return NULL;
    if ( snmp_clone_var( varbind, varbind2 )) {
	snmp_free_varbind( varbind2 );
	return NULL;
    }
    if ( varbind2->val.string == NULL )
	varbind2->val.string = varbind2->buf;	/* ensure it points somewhere */

    pdu = snmp_pdu_create(AGENTX_MSG_INDEX_ALLOCATE);
    if ( pdu == NULL ) {
	snmp_free_varbind( varbind2 );
	return NULL;
    }
    pdu->time = 0;
    pdu->sessid = ss->sessid;
    if ( flags == ALLOCATE_ANY_INDEX )
	pdu->flags |= AGENTX_MSG_FLAG_ANY_INSTANCE;
    if ( flags == ALLOCATE_NEW_INDEX )
	pdu->flags |= AGENTX_MSG_FLAG_NEW_INSTANCE;

		/*
		 *  Just send a single index request varbind.
		 *  Although the AgentX protocol supports
		 *    multiple index allocations in a single
		 *    request, the model used in the UCD agent
		 *    doesn't currently take advantage of this.
		 *  I believe this is our prerogative - just as
		 *    long as the master side Index request handler
		 *    can cope with multiple index requests.
		 */
    pdu->variables = varbind2;

    if ( agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS )
	return NULL;

    if ( response->errstat != SNMP_ERR_NOERROR ) {
	snmp_free_pdu(response);
	return NULL;
    }

		/*
		 * Unlink the (single) response varbind to return
		 *  to the main driving index request routine.
		 *
		 * This is a memory leak, as nothing will ever
		 *  release this varbind.  If this becomes a problem,
		 *  we'll need to keep a list of these here, and
		 *  free the memory in the "index release" routine.
		 * But the master side never frees these either (by
		 *  design, since it still needs them), so expecting
		 *  the subagent to is discrimination, pure & simple :-)
		 */ 
    varbind2 = response->variables;
    response->variables = NULL;
    snmp_free_pdu(response);
    return varbind2;
}

int
agentx_unregister_index( struct snmp_session *ss,
		      struct variable_list* varbind)
{
    struct snmp_pdu *pdu, *response;
    struct variable_list *varbind2;

    if (! IS_AGENTX_VERSION( ss->version ))
	return -1;

		/*
		 * Make a copy of the index request varbind
		 *    for the AgentX request PDU
		 *    (since the pdu structure will be freed)
		 */
    varbind2 = (struct variable_list *)malloc(sizeof(struct variable_list));
    if ( varbind2 == NULL )
	return -1;
    if ( snmp_clone_var( varbind, varbind2 )) {
	snmp_free_varbind( varbind2 );
	return -1;
    }

    pdu = snmp_pdu_create(AGENTX_MSG_INDEX_DEALLOCATE);
    if ( pdu == NULL ) {
	snmp_free_varbind( varbind2 );
	return -1;
    }
    pdu->time = 0;
    pdu->sessid = ss->sessid;

		/*
		 *  Just send a single index release varbind.
		 *	(as above)
		 */
    pdu->variables = varbind2;

    if ( agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS )
	return -1;

    if ( response->errstat != SNMP_ERR_NOERROR ) {
	snmp_free_pdu(response);
	return -1;	/* XXX - say why */
    }

    snmp_free_pdu(response);
    return SNMP_ERR_NOERROR;
}

int
agentx_add_agentcaps( struct snmp_session *ss,
		      oid* agent_cap, size_t agent_caplen, const char* descr)
{
    struct snmp_pdu *pdu, *response;

    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_ADD_AGENT_CAPS);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    pdu->sessid = ss->sessid;
    snmp_add_var( pdu, agent_cap, agent_caplen, 's', descr);

    if ( agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS )
	return 0;

    if ( response->errstat != SNMP_ERR_NOERROR ) {
	snmp_free_pdu(response);
	return 0;
    }

    snmp_free_pdu(response);
    return 1;
}

int
agentx_remove_agentcaps( struct snmp_session *ss,
		      oid* agent_cap, size_t agent_caplen)
{
    struct snmp_pdu *pdu, *response;

    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_REMOVE_AGENT_CAPS);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    pdu->sessid = ss->sessid;
    snmp_add_null_var( pdu, agent_cap, agent_caplen);

    if ( agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS )
	return 0;

    if ( response->errstat != SNMP_ERR_NOERROR ) {
	snmp_free_pdu(response);
	return 0;
    }

    snmp_free_pdu(response);
    return 1;
}

int
agentx_send_ping( struct snmp_session *ss )
{
    struct snmp_pdu *pdu, *response;

    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_PING);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    pdu->sessid = ss->sessid;

    if ( agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS )
	return 0;

    if ( response->errstat != SNMP_ERR_NOERROR ) {
	snmp_free_pdu(response);
	return 0;
    }

    snmp_free_pdu(response);
    return 1;
}
