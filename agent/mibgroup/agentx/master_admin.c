/*
 *  AgentX Administrative request handling
 */
#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#include "agent_index.h"
#include "agent_trap.h"
#include "mibII/sysORTable.h"
#include "snmp_debug.h"

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

    DEBUGMSGTL(("agentx:open_agentx_session","open %p\n", session));
    sp = (struct snmp_session *)malloc( sizeof( struct snmp_session ));
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
    sp->securityName = strdup((char *) pdu->variables->val.string );
    gettimeofday(&now, NULL);
    sp->engineTime = calculate_time_diff( &now, &starttime );

    sp->subsession = session;			/* link back to head */
    sp->flags     |= SNMP_FLAGS_SUBSESSION;
    sp->next       = session->subsession;
    session->subsession = sp;
    DEBUGMSGTL(("agentx:open_agentx_session","opened %p = %d\n", sp, sp->sessid));

    return sp->sessid;
}

int
close_agentx_session(struct snmp_session *session, int sessid)
{
    struct snmp_session *sp, *prev = NULL;
    
    DEBUGMSGTL(("agentx:close_agentx_session","close %p, %d\n", session, sessid));
    if ( sessid == -1 ) {
	unregister_mibs_by_session( session );
	unregister_index_by_session( session );
	unregister_sysORTable_by_session( session );

	return AGENTX_ERR_NOERROR;
    }

    for ( sp = session->subsession ; sp != NULL ; prev = sp, sp = sp->next ) {
        if ( sp->sessid == sessid ) {

	    unregister_mibs_by_session( sp );
	    unregister_index_by_session( sp );
	    unregister_sysORTable_by_session( sp );
	    if ( prev )
	        prev->next = sp->next;
	    else
	    	session->subsession = sp->next;
	    if (sp->securityAuthProto)
		free(sp->securityAuthProto);
	    if (sp->securityName)
		free(sp->securityName);
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
    char buf[32];
    oid ubound = 0;

    DEBUGMSGTL(("agentx:register","in register_agentx_list\n"));
    
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
    switch (register_mib_context(buf, (struct variable *)agentx_varlist,
			 sizeof(agentx_varlist[0]), 1,
			 pdu->variables->name, pdu->variables->name_length,
			 pdu->priority, pdu->range_subid, ubound, sp,
			 (char *)pdu->community, pdu->time,
			 pdu->flags&AGENTX_MSG_FLAG_INSTANCE_REGISTER)) {

	case MIB_REGISTERED_OK:
				DEBUGMSGTL(("agentx:register",
                                            "registered ok\n"));
				return AGENTX_ERR_NOERROR;
	case MIB_DUPLICATE_REGISTRATION:
				DEBUGMSGTL(("agentx:register",
                                            "duplicate registration\n"));
				return AGENTX_ERR_DUPLICATE_REGISTRATION;
	case MIB_REGISTRATION_FAILED:
	default:
				DEBUGMSGTL(("agentx:register",
                                            "failed registration\n"));
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

    switch (unregister_mib_context(pdu->variables->name,
    		       pdu->variables->name_length,
		       pdu->priority, pdu->range_subid, ubound,
		       (char *)pdu->community)) {
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
allocate_idx_list(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;
    struct variable_list *vp, *vp2, *next, *res;
    int flags = 0;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    if ( pdu->flags & AGENTX_MSG_FLAG_ANY_INSTANCE )
	flags |= ALLOCATE_ANY_INDEX;
    if ( pdu->flags & AGENTX_MSG_FLAG_NEW_INSTANCE )
	flags |= ALLOCATE_NEW_INDEX;

		/*
		 * XXX - what about errors?
		 *
		 *  If any allocations fail, then we need to
		 *    *fully* release the earlier ones.
		 *  (i.e. remove them completely from the index registry,
		 *    not simply mark them as available for re-use)
		 *
		 * For now - assume they all succeed.
		 */
    for ( vp = pdu->variables ; vp != NULL; vp = next ) {
	next = vp->next_variable;
	res = register_index( vp, flags, session );
	if ( res == NULL ) {
		/*
		 *  If any allocations fail, we need to *fully* release
		 *	all previous ones (i.e. remove them completely
		 *	from the index registry)
		 */
	    for ( vp2 = pdu->variables ; vp2 != vp ; vp2=vp2->next_variable )
		remove_index( vp2, session );
	    return AGENTX_ERR_INDEX_NONE_AVAILABLE;	/* XXX */
	}
	(void)snmp_clone_var( res, vp );
	vp->next_variable = next;
    }
    return AGENTX_ERR_NOERROR;
}

int
release_idx_list(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;
    struct variable_list *vp, *vp2;
    int res;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    for ( vp = pdu->variables ; vp != NULL; vp = vp->next_variable ) {
	res = unregister_index( vp, TRUE, session );
		/*
		 *  If any releases fail,
		 *	we need to reinstate all previous ones.
		 */
	if ( res != SNMP_ERR_NOERROR ) {
	    for ( vp2 = pdu->variables ; vp2 != vp; vp2 = vp2->next_variable )
		(void) register_index( vp2, ALLOCATE_THIS_INDEX, session );
	    return AGENTX_ERR_INDEX_NOT_ALLOCATED;	/* Probably */
	}
    }
    return AGENTX_ERR_NOERROR;
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
agentx_notify(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;
    struct variable_list *var;
    int got_sysuptime = 0;
    extern oid sysuptime_oid[], snmptrap_oid[];
    extern size_t sysuptime_oid_len, snmptrap_oid_len;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;

    var = pdu->variables;
    if (!var)
	return AGENTX_ERR_PROCESSING_ERROR;

    if ( snmp_oid_compare( var->name, var->name_length, 
		sysuptime_oid, sysuptime_oid_len) == 0 ) {
	got_sysuptime = 1;
	var = var->next_variable;
    }

    if (!var || snmp_oid_compare( var->name, var->name_length, 
			snmptrap_oid, snmptrap_oid_len) != 0 )
	return AGENTX_ERR_PROCESSING_ERROR;

		/*
		 *  If sysUptime isn't the first varbind, don't worry.  
		 *     send_trap_vars() will add it if necessary.
		 *
		 *  Note that if this behaviour is altered, it will
		 *     be necessary to add sysUptime here,
		 *     as this is valid AgentX syntax.
		 */

    send_trap_vars( -1, -1, pdu->variables );
    return AGENTX_ERR_NOERROR;
}


int
agentx_ping_response(struct snmp_session *session, struct snmp_pdu *pdu)
{
    struct snmp_session *sp;

    sp = find_agentx_session( session, pdu->sessid );
    if ( sp == NULL )
        return AGENTX_ERR_NOT_OPEN;
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
    	asp = init_agent_snmp_session(session, pdu);

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

	case AGENTX_MSG_INDEX_ALLOCATE:
		asp->status = allocate_idx_list( session, asp->pdu );
		if ( asp->status != AGENTX_ERR_NOERROR) {
		    snmp_free_pdu( asp->pdu );
    		    asp->pdu = snmp_clone_pdu(pdu);
		}
		break;

	case AGENTX_MSG_INDEX_DEALLOCATE:
		asp->status = release_idx_list( session, pdu );
		break;

	case AGENTX_MSG_ADD_AGENT_CAPS:
		asp->status = add_agent_caps_list( session, pdu );
		break;

	case AGENTX_MSG_REMOVE_AGENT_CAPS:
		asp->status = remove_agent_caps_list( session, pdu );
		break;

	case AGENTX_MSG_NOTIFY:
		asp->status = agentx_notify( session, pdu );
		break;

	case AGENTX_MSG_PING:
		asp->status = agentx_ping_response( session, pdu );
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
	if (! snmp_send( asp->session, asp->pdu ))
	    snmp_free_pdu(asp->pdu);
	asp->pdu = NULL;
	free_agent_snmp_session(asp);
    }

    return 1;
}
