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

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "snmp.h"
#include "agentx.h"

static oid null_oid[] = {0, 0};

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

    if ( reqid != state->reqid )
	return 0;

    state->waiting = 0;
    if (op == RECEIVED_MESSAGE) {
	if (pdu->command == AGENTX_MSG_RESPONSE) {
	    state->pdu		= snmp_clone_pdu(pdu);
	    state->status	= STAT_SUCCESS;
	    snmp_errno		= SNMPERR_SUCCESS;
	    session->s_snmp_errno = SNMPERR_SUCCESS;
	}
    }
    else if (op == TIMED_OUT){
	state->pdu		= NULL;
	state->status		= STAT_TIMEOUT;
	snmp_errno		= SNMPERR_TIMEOUT;
	session->s_snmp_errno	= SNMPERR_TIMEOUT;
    }

    return 1;
}



int
agentx_synch_response( struct snmp_session *ss, struct snmp_pdu *pdu, struct snmp_pdu **response )
{
    int result;
    void *saved_state;
    int (*saved_cback)(int, struct snmp_session *, int, struct snmp_pdu *, void *);

    saved_state = ss->callback_magic;
    saved_cback = ss->callback;
    snmp_synch_setup( ss );
    ss->callback = agentx_synch_input;

    result = snmp_synch_response(ss, pdu, response);

    snmp_synch_reset( ss );
    ss->callback       = saved_cback;
    ss->callback_magic = saved_state;

    return result;
}


	/*
	 * AgentX PofE convenience functions
	 */

int
agentx_open_session( struct snmp_session *ss )
{
    struct snmp_pdu *pdu, *response;

    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_OPEN);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    snmp_add_var( pdu, null_oid, 2, 's', "UCD AgentX sub-agent");

    if ( agentx_synch_response(ss, pdu, &response) != STAT_SUCCESS )
	return 0;

    if ( response->errstat != SNMP_ERR_NOERROR ) {
	snmp_free_pdu(response);
	return 0;
    }

    ss->sessid = response->sessid;
    snmp_free_pdu(response);
    return 1;
}

int
agentx_close_session( struct snmp_session *ss )
{
    struct snmp_pdu *pdu, *response;

    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_CLOSE);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    snmp_add_var( pdu, null_oid, 2, 's', "UCD AgentX sub-agent");

    (void) agentx_synch_response(ss, pdu, &response);
    snmp_free_pdu(response);
    return 1;
}

int
agentx_register( struct snmp_session *ss, oid start[], size_t startlen)
{
    struct snmp_pdu *pdu, *response;

    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_REGISTER);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    pdu->sessid = ss->sessid;
    snmp_add_null_var( pdu, start, startlen);

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
agentx_unregister( struct snmp_session *ss, oid start[], size_t startlen)
{
    struct snmp_pdu *pdu, *response;

    if (! IS_AGENTX_VERSION( ss->version ))
	return 0;

    pdu = snmp_pdu_create(AGENTX_MSG_UNREGISTER);
    if ( pdu == NULL )
	return 0;
    pdu->time = 0;
    pdu->sessid = ss->sessid;
    snmp_add_null_var( pdu, start, startlen);

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
agentx_add_agentcaps( struct snmp_session *ss,
		      oid* agent_cap, size_t agent_caplen, char* descr)
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
