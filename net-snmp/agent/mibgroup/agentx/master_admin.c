/*
 *  AgentX Administrative request handling
 */
#include "config.h"

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

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp.h"

#include "agentx/protocol.h"
#include "agentx/client.h"

#include "snmp_agent.h"
#include "snmp_vars.h"
#include "var_struct.h"
#include "mibII/sysORTable.h"

extern struct variable2 agentx_varlist[];

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

    sp = malloc( sizeof( struct snmp_session ));
    if ( sp == NULL ) {
        session->s_snmp_errno = AGENTX_ERR_OPEN_FAILED;
	return -1;
    }

    memcpy( sp, session, sizeof(struct snmp_session));    
    sp->sessid     = getNextSessID();
    sp->subsession = session;			/* link back to head */
    sp->flags     |= SNMP_FLAGS_SUBSESSION;
    sp->next       = session->subsession;
    session->subsession = sp;

    return sp->sessid;
}

int
close_agentx_session(struct snmp_session *session, int sessid)
{
    struct snmp_session *sp, *prev;
    
    for ( sp = session->subsession ; sp != NULL ; prev = sp, sp = sp->next ) {
        if ( sp->sessid == sessid ) {
	    /* 
	    * TODO:	Unregister any MIB regions,
	    *		indexes or sysOR entries from this session
	    */
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
    
    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    sprintf(buf, "AgentX subagent %ld", sp->sessid );
    		 /*
		* TODO: registration priority, timeout, etc
		*	Range registration
		*/ 
    switch (register_mib(buf, (struct variable *)agentx_varlist,
			 sizeof(agentx_varlist[0]), 1,
			 pdu->variables->name, pdu->variables->name_length)) {
       case -1:		return AGENTX_ERR_REQUEST_DENIED;
       case -2:		return AGENTX_ERR_DUPLICATE_REGISTRATION;
    }
    sub = find_subtree_previous( pdu->variables->name,
				 pdu->variables->name_length, NULL );

    if ( sub != NULL )
        sub->session = sp;
    return AGENTX_ERR_NOERROR;
}

int
unregister_agentx_list(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    		 /*
		* TODO: registration priority, timeout, etc
		*	Range registration
		*/ 
    if (unregister_mib(pdu->variables->name,
    		       pdu->variables->name_length) < 0 )
	return AGENTX_ERR_UNKNOWN_REGISTRATION;
    else
        return AGENTX_ERR_NOERROR;
}

int
add_agent_caps_list(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    register_sysORTable(pdu->variables->name,
    			pdu->variables->name_length,
			pdu->variables->val.string);
    return AGENTX_ERR_NOERROR;
}

int
remove_agent_caps_list(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    if ( unregister_sysORTable(pdu->variables->name,
    			       pdu->variables->name_length) < 0 )
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
    
    if ( magic )
        asp = (struct agent_snmp_session *)magic;
    else
    	asp = init_agent_snmp_session(session, pdu );

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
        asp->pdu->command = AGENTX_MSG_RESPONSE;
	asp->pdu->errstat = asp->status;
	snmp_send( asp->session, asp->pdu );
	free(asp);
    }

    return 1;
}
