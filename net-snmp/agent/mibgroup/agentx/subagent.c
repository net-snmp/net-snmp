/*
 *  AgentX sub-agent
 */
#include "config.h"

#include <sys/types.h>
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
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "snmp.h"

#include "snmp_vars.h"
#include "snmp_agent.h"
#include "var_struct.h"
#include "snmpd.h"
#include "agentx/protocol.h"
#include "agentx/client.h"
#include "default_store.h"
#include "ds_agent.h"
#include "callback.h"
#include "agent_registry.h"
#include "agent_callbacks.h"
#include "agent_trap.h"
#include "snmp_debug.h"
#include "mib_module_config.h"
#ifdef USING_MIBII_SYSORTABLE_MODULE
#include "mibII/sysORTable.h"
#endif
#include "system.h"


struct agent_set_info {
    int			  transID;
    int			  mode;
    time_t		  uptime;
    struct snmp_session  *sess;
    struct variable_list *var_list;
    struct agent_set_info *next;
};

static struct agent_set_info *Sets = NULL;

struct agent_set_info *
save_set_vars( struct snmp_session *ss, struct snmp_pdu *pdu )
{
    struct agent_set_info *ptr;
    struct timeval now;
    extern struct timeval starttime;

    ptr = (struct agent_set_info *)malloc(sizeof(struct agent_set_info));
    if (ptr == NULL )
	return NULL;

	/*
	 * Save the important information
	 */
    ptr->transID = pdu->transid;
    ptr->sess    = ss;
    ptr->mode    = RESERVE1;
    gettimeofday(&now, NULL);
    ptr->uptime = calculate_time_diff(&now, &starttime);

    ptr->var_list = snmp_clone_varbind(pdu->variables);
    if ( ptr->var_list == NULL ) {
	free( ptr );
	return NULL;
    }

    ptr->next = Sets;
    Sets = ptr;

    return ptr;
}

struct agent_set_info *
restore_set_vars( struct agent_snmp_session *asp )
{
    struct agent_set_info *ptr;

    for ( ptr=Sets ; ptr != NULL ; ptr=ptr->next )
	if ( ptr->sess == asp->session && ptr->transID == asp->pdu->transid )
	    break;

    if ( ptr == NULL || ptr->var_list == NULL )
	return NULL;

    asp->rw      	= WRITE;
    asp->pdu->variables = ptr->var_list;
    asp->start		= ptr->var_list;
    asp->end		= ptr->var_list;
    while ( asp->end->next_variable )
	asp->end = asp->end->next_variable;
    asp->mode		= ptr->mode;
    return ptr;
}


void
free_set_vars( struct snmp_session *ss, struct snmp_pdu *pdu )
{
    struct agent_set_info *ptr, *prev=NULL;

    for ( ptr=Sets ; ptr != NULL ; ptr=ptr->next ) {
	if ( ptr->sess == ss && ptr->transID == pdu->transid ) {
	    if ( prev )
		prev->next = ptr->next;
	    else
		Sets = ptr->next;
	    snmp_free_varbind(ptr->var_list);
	    free(ptr);
	    return;
	}
	prev = ptr;
    }
}


int
handle_agentx_packet(int operation, struct snmp_session *session, int reqid,
                   struct snmp_pdu *pdu, void *magic)
{
    struct agent_snmp_session  *asp;
    struct agent_set_info      *asi;
    int status, allDone, i;
    struct variable_list *var_ptr, *var_ptr2;

    asp = init_agent_snmp_session( session, pdu );

    DEBUGMSGTL(("agentx/subagent","handling agentx request....\n"));
    switch (pdu->command) {
    case AGENTX_MSG_GET:
        DEBUGMSGTL(("agentx/subagent","  -> get\n"));
	status = handle_next_pass( asp );
	break;

    case AGENTX_MSG_GETBULK:
        DEBUGMSGTL(("agentx/subagent","  -> getbulk\n"));
	    /*
	     * GETBULKS require multiple passes. The first pass handles the
	     * explicitly requested varbinds, and subsequent passes append
	     * to the existing var_op_list.  Each pass (after the first)
	     * uses the results of the preceeding pass as the input list
	     * (delimited by the start & end pointers.
	     * Processing is terminated if all entries in a pass are
	     * EndOfMib, or the maximum number of repetitions are made.
	     */
	asp->exact   = FALSE;
		/*
		 * Limit max repetitions to something reasonable
		 *	XXX: We should figure out what will fit somehow...
		 */
	if ( asp->pdu->errindex > 100 )
	    asp->pdu->errindex = 100;

	status = handle_next_pass( asp );	/* First pass */
	if ( status != SNMP_ERR_NOERROR )
	    break;

	while ( asp->pdu->errstat-- > 0 )	/* Skip non-repeaters */
	    asp->start = asp->start->next_variable;
	asp->pdu->errindex--;           /* First repetition was handled above */

	while ( asp->pdu->errindex-- > 0 ) {	/* Process repeaters */
		/*
		 * Add new variable structures for the
		 * repeating elements, ready for the next pass.
		 * Also check that these are not all EndOfMib
		 */
	    allDone = TRUE;		/* Check for some content */
	    for ( var_ptr = asp->start;
		  var_ptr != asp->end->next_variable;
		  var_ptr = var_ptr->next_variable ) {
				/* XXX: we don't know the size of the next
					OID, so assume the maximum length */
		var_ptr2 = snmp_add_null_var(asp->pdu, var_ptr->name, MAX_OID_LEN);
		for ( i=var_ptr->name_length ; i<MAX_OID_LEN ; i++)
		    var_ptr2->name[i] = '\0';
		var_ptr2->name_length = var_ptr->name_length;

		if ( var_ptr->type != SNMP_ENDOFMIBVIEW )
		    allDone = FALSE;
	    }
	    if ( allDone )
		break;

	    asp->start = asp->end->next_variable;
	    while ( asp->end->next_variable != NULL )
		asp->end = asp->end->next_variable;
	    
	    status = handle_next_pass( asp );
	    if ( status != SNMP_ERR_NOERROR )
		break;
	}
	break;

    case AGENTX_MSG_GETNEXT:
        DEBUGMSGTL(("agentx/subagent","  -> getnext\n"));
	asp->exact   = FALSE;
	status = handle_next_pass( asp );
	break;

    case AGENTX_MSG_TESTSET:
        DEBUGMSGTL(("agentx/subagent","  -> testset\n"));
    	    /*
	     * In the UCD architecture the first two passes through var_op_list
	     * verify that all types, lengths, and values are valid
	     * and may reserve resources.
	     * These correspond to the first AgentX pass - TESTSET
	     */
	asp->rw      = WRITE;
        asp->mode = RESERVE1;
	asi = save_set_vars( session, pdu );
	if ( asi ) {
	    status = handle_next_pass( asp );
	}
	else
	    status = AGENTX_ERR_PROCESSING_ERROR;

	if ( status == SNMP_ERR_NOERROR ) {
	    asp->mode = RESERVE2;
	    status = handle_next_pass( asp );
	}

	if ( status == SNMP_ERR_NOERROR )
	    asi->mode = ACTION;
	else
	    asi->mode = FREE;
	
	break;


	    /*
	     * The third and fourth passes in the UCD architecture
	     *   correspond to distinct AgentX passes,
	     *   as does the "undo" pass, in case of errors elsewhere
	     */
    case AGENTX_MSG_COMMITSET:
        DEBUGMSGTL(("agentx/subagent","  -> commitset\n"));
        asp->mode = ACTION;
        asi = restore_set_vars( asp );
	if ( asi ) {
	    status = handle_next_pass( asp );
	}
	else
	    status = AGENTX_ERR_PROCESSING_ERROR;

	if ( status == SNMP_ERR_NOERROR )
	    asi->mode = COMMIT;
	else
	    asi->mode = UNDO;
	
        asp->pdu->variables = NULL;
	break;

    case AGENTX_MSG_CLEANUPSET:
        DEBUGMSGTL(("agentx/subagent","  -> cleanupset\n"));
        asi = restore_set_vars( asp );
	if ( asi ) {
	    asp->mode = asi->mode;
	    status = handle_next_pass( asp );
	}
	else
	    status = AGENTX_ERR_PROCESSING_ERROR;

	free_set_vars( session, pdu );
        asp->pdu->variables = NULL;
	break;

    case AGENTX_MSG_UNDOSET:
        DEBUGMSGTL(("agentx/subagent","  -> undoset\n"));
        asp->mode = UNDO;
        asi = restore_set_vars( asp );
	if ( asi ) {
	    status = handle_next_pass( asp );
	}
	else
	    status = AGENTX_ERR_PROCESSING_ERROR;

	free_set_vars( session, pdu );
        asp->pdu->variables = NULL;
	break;

    case AGENTX_MSG_RESPONSE:
        DEBUGMSGTL(("agentx/subagent","  -> response\n"));
	free_agent_snmp_session( asp );
	return 1;

    default:
        DEBUGMSGTL(("agentx/subagent","  -> unknown (%d)\n", pdu->command ));
	free_agent_snmp_session( asp );
	return 0;
    }
	
    
	
    if ( asp->outstanding_requests == NULL ) {
	if ( status != SNMP_ERR_NOERROR ) {
	    snmp_free_pdu( asp->pdu );
	    asp->pdu = asp->orig_pdu;
	    asp->orig_pdu = NULL;
	}
	asp->pdu->command = AGENTX_MSG_RESPONSE;
	asp->pdu->errstat  = status;
	asp->pdu->errindex = asp->index;
	if (! snmp_send( asp->session, asp->pdu ))
	    snmp_free_pdu(asp->pdu);
	asp->pdu = NULL;
	free_agent_snmp_session( asp );
    }
    DEBUGMSGTL(("agentx/subagent","  FINISHED\n"));

    return 1;
}


extern struct snmp_session *main_session;	/* from snmp_agent.c */

int
agentx_registration_callback(int majorID, int minorID, void *serverarg,
                         void *clientarg) {
  struct register_parameters *reg_parms =
    (struct register_parameters *) serverarg;
  struct snmp_session *agentx_ss =
    (struct snmp_session *) clientarg;

  if (minorID == SNMPD_CALLBACK_REGISTER_OID)
    return agentx_register(agentx_ss,
		    reg_parms->name, reg_parms->namelen,
		    reg_parms->priority,
		    reg_parms->range_subid, reg_parms->range_ubound,
		    reg_parms->timeout);
  else
    return agentx_unregister(agentx_ss,
		    reg_parms->name, reg_parms->namelen,
		    reg_parms->priority,
		    reg_parms->range_subid, reg_parms->range_ubound);
}


#ifdef USING_MIBII_SYSORTABLE_MODULE
int
agentx_sysOR_callback(int majorID, int minorID, void *serverarg,
                         void *clientarg) {
  struct register_sysOR_parameters *reg_parms =
    (struct register_sysOR_parameters *) serverarg;
  struct snmp_session *agentx_ss =
    (struct snmp_session *) clientarg;

  if (minorID == SNMPD_CALLBACK_REG_SYSOR)
    return agentx_add_agentcaps(agentx_ss,
		    reg_parms->name, reg_parms->namelen,
		    reg_parms->descr);
  else
    return agentx_remove_agentcaps(agentx_ss,
		    reg_parms->name, reg_parms->namelen);
}
#endif


static int
subagent_shutdown(int majorID, int minorID, void *serverarg, void *clientarg) {
  struct snmp_session *thesession = (struct snmp_session *) clientarg;
  DEBUGMSGTL(("agentx/subagent","shutting down session....\n"));
  if (thesession == NULL) {
    DEBUGMSGTL(("agentx/subagent","Empty session to shutdown\n"));
    return 0;
  }
  agentx_close_session(thesession, AGENTX_CLOSE_SHUTDOWN);
  snmp_close(thesession);
  DEBUGMSGTL(("agentx/subagent","shut down finished.\n"));
  return 1;
}

static int
subagent_register_for_traps(int majorID, int minorID, void *serverarg, void *clientarg) {
  struct snmp_session *thesession = (struct snmp_session *) clientarg;
  DEBUGMSGTL(("agentx/subagent","registering trap session....\n"));
  if (thesession == NULL) {
    DEBUGMSGTL(("agentx/subagent","No session to register\n"));
    return 0;
  }
  if (add_trap_session( thesession, AGENTX_MSG_NOTIFY, 1, AGENTX_VERSION_1) == 0){
    DEBUGMSGTL(("agentx/subagent","Trap session registration failed\n"));
    return 0;
  }
  DEBUGMSGTL(("agentx/subagent","Trap session registered OK\n"));
  return 1;
}

/* returns non-zero on error */
int
subagent_pre_init( void )
{
    struct snmp_session sess;

    DEBUGMSGTL(("agentx/subagent","initializing....\n"));
    if ( ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE) != SUB_AGENT )
	return 0;

    snmp_sess_init( &sess );
    sess.version = AGENTX_VERSION_1;
    sess.retries = SNMP_DEFAULT_RETRIES;
    sess.timeout = SNMP_DEFAULT_TIMEOUT;
    sess.flags  |= SNMP_FLAGS_STREAM_SOCKET;
    if ( ds_get_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET) )
	sess.peername = strdup(ds_get_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET));
    else
	sess.peername = strdup(AGENTX_SOCKET);
 
    sess.local_port  = 0;		/* client */
    sess.remote_port = AGENTX_PORT;	/* default port */
    sess.callback = handle_agentx_packet;
    sess.authenticator = NULL;
    main_session = snmp_open_ex( &sess, 0, agentx_parse, 0, agentx_build,
                                   agentx_check_packet );

    if ( main_session == NULL ) {
      /* diagnose snmp_open errors with the input struct snmp_session pointer */
	snmp_sess_perror("subagent_pre_init", &sess);
	return -1;
    }

    if ( agentx_open_session( main_session ) < 0 ) {
	snmp_close( main_session );
	return -1;
    }


    snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_POST_PREMIB_READ_CONFIG,
                           subagent_register_for_traps, main_session);
    snmp_register_callback(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_SHUTDOWN,
                           subagent_shutdown, main_session);
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_REGISTER_OID,
                           agentx_registration_callback, main_session);
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_UNREGISTER_OID,
                           agentx_registration_callback, main_session);
#ifdef USING_MIBII_SYSORTABLE_MODULE
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_REG_SYSOR,
                           agentx_sysOR_callback, main_session);
    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_UNREG_SYSOR,
                           agentx_sysOR_callback, main_session);
#endif
    DEBUGMSGTL(("agentx/subagent","initializing....  DONE\n"));
    
    return 0;
}



