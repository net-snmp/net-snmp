/*
 *  AgentX Administrative request handling
 */
#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STRING
#include <string.h>
#else
#include <strings.h>
#endif
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

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_impl.h"
#include "snmp.h"
#include "system.h"

#include "agentx/protocol.h"
#include "agentx/client.h"

#include "snmp_agent.h"
#include "snmp_vars.h"
#include "var_struct.h"
#include "agent_registry.h"
#include "mibII/sysORTable.h"

extern struct variable2 agentx_varlist[];
extern struct timeval   starttime;

struct snmp_session *
find_agentx_session( struct snmp_session *session, int sessid)
{
    struct snmp_session *sp;
    
    for ( sp = session->subsession ; sp != NULL ; sp = sp->next ) {
        if ( sp->sessid == sessid )
	    return sp;
    }
    return NULL;
}


int
open_agentx_session(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;
    struct timeval now;

    sp = malloc( sizeof( struct snmp_session ));
    if ( sp == NULL ) {
        session->s_snmp_errno = AGENTX_ERR_OPEN_FAILED;
	return -1;
    }

    memcpy( sp, session, sizeof(struct snmp_session));    
    sp->sessid     = snmp_get_next_sessid();
    sp->version    = pdu->version;
    sp->timeout    = pdu->time;

	/*
	 * This next bit utilises unused SNMPv3 fields
	 *   to store the subagent OID and description.
	 * This really ought to use AgentX-specific fields,
	 *   but it hardly seems worth it for a one-off use.
	 *
	 * But I'm willing to be persuaded otherwise....
	 */
    sp->securityAuthProto =
	snmp_duplicate_objid(pdu->variables->name, pdu->variables->name_length);
    sp->securityAuthProtoLen = pdu->variables->name_length;
    sp->securityName = strdup( pdu->variables->val.string );
    gettimeofday(&now, NULL);
    sp->engineTime = calculate_time_diff( &now, &starttime );

    sp->subsession = session;			/* link back to head */
    sp->flags     |= SNMP_FLAGS_SUBSESSION;
    sp->next       = session->subsession;
    session->subsession = sp;

    return sp->sessid;
}

int
close_agentx_session(struct snmp_session *session, int sessid)
{
    struct snmp_session *sp, *prev = NULL;
    
    for ( sp = session->subsession ; sp != NULL ; prev = sp, sp = sp->next ) {
        if ( sp->sessid == sessid ) {

	    unregister_mibs_by_session( sp );
	    unregister_sysORTable_by_session( sp );
	    if ( prev )
	        prev->next = sp->next;
	    else
	    	session->subsession = sp->next;
	    free( sp );
	    
	    return AGENTX_ERR_NOERROR;
	}
    }
    
    return AGENTX_ERR_NOT_OPEN;
}

int
register_agentx_list(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;
    struct subtree *sub;
    char buf[32];
    oid ubound = 0;
    
    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    sprintf(buf, "AgentX subagent %ld", sp->sessid );
    		 /*
		* TODO: registration timeout
		*	registration context
		*/ 
    if ( pdu->range_subid )
	ubound = pdu->variables->val.objid[ pdu->range_subid-1 ];
    switch (register_mib_range(buf, (struct variable *)agentx_varlist,
			 sizeof(agentx_varlist[0]), 1,
			 pdu->variables->name, pdu->variables->name_length,
			 pdu->priority, pdu->range_subid, ubound, sp)) {

	case MIB_REGISTERED_OK:
				return AGENTX_ERR_NOERROR;
	case MIB_DUPLICATE_REGISTRATION:
				return AGENTX_ERR_DUPLICATE_REGISTRATION;
	case MIB_REGISTRATION_FAILED:
	default:
				return AGENTX_ERR_REQUEST_DENIED;
    }
}

int
unregister_agentx_list(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;
    oid ubound = 0;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    switch (unregister_mib_range(pdu->variables->name,
    		       pdu->variables->name_length,
		       pdu->priority, pdu->range_subid, ubound, sp)) {
	case MIB_UNREGISTERED_OK:
				return AGENTX_ERR_NOERROR;
	case MIB_NO_SUCH_REGISTRATION:
				return AGENTX_ERR_UNKNOWN_REGISTRATION;
	case MIB_UNREGISTRATION_FAILED:
	default:
				return AGENTX_ERR_REQUEST_DENIED;
    }
}

int
add_agent_caps_list(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    register_sysORTable_sess(pdu->variables->name,
    			pdu->variables->name_length,
			(char *)pdu->variables->val.string, sp);
    return AGENTX_ERR_NOERROR;
}

int
remove_agent_caps_list(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    if ( unregister_sysORTable_sess(pdu->variables->name,
    			       pdu->variables->name_length, sp) < 0 )
        return AGENTX_ERR_UNKNOWN_AGENTCAPS;
    else
        return AGENTX_ERR_NOERROR;
}

int
handle_master_agentx_packet(int operation,
			    struct snmp_session *session,
			    int reqid,
			    struct snmp_pdu *pdu,
			    void *magic)
{
    struct agent_snmp_session  *asp;
    struct timeval now;
    
    if ( magic )
        asp = (struct agent_snmp_session *)magic;
    else
    	asp = init_agent_snmp_session(session, snmp_clone_pdu(pdu) );

    switch (pdu->command) {
        case AGENTX_MSG_OPEN:
		asp->pdu->sessid = open_agentx_session( session, pdu );
		if ( asp->pdu->sessid == -1 )
		    asp->status = session->s_snmp_errno;
		break;

        case AGENTX_MSG_CLOSE:
		asp->status = close_agentx_session( session, pdu->sessid );
		break;

	case AGENTX_MSG_REGISTER:
		asp->status = register_agentx_list( session, pdu );
		break;

	case AGENTX_MSG_UNREGISTER:
		asp->status = unregister_agentx_list( session, pdu );
		break;

	case AGENTX_MSG_ADD_AGENT_CAPS:
		asp->status = add_agent_caps_list( session, pdu );
		break;

	case AGENTX_MSG_REMOVE_AGENT_CAPS:
		asp->status = remove_agent_caps_list( session, pdu );
		break;

	/* TODO: Other admin packets */
	
	case AGENTX_MSG_GET:
	case AGENTX_MSG_GETNEXT:
	case AGENTX_MSG_GETBULK:
	case AGENTX_MSG_TESTSET:
	case AGENTX_MSG_COMMITSET:
	case AGENTX_MSG_UNDOSET:
	case AGENTX_MSG_CLEANUPSET:
	case AGENTX_MSG_RESPONSE:
		/* Shouldn't be handled here */
		break;
		
	default:
		asp->status = AGENTX_ERR_PARSE_FAILED;
		break;
    }
    
    if ( asp->outstanding_requests == NULL ) {
        gettimeofday(&now, NULL);
	asp->pdu->time    = calculate_time_diff( &now, &starttime );
        asp->pdu->command = AGENTX_MSG_RESPONSE;
	asp->pdu->errstat = asp->status;
	snmp_send( asp->session, asp->pdu );
	free(asp);
    }

    return 1;
}
