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
#include "snmp_alarm.h"
#include "snmp_logging.h"
#include "default_store.h"
#include "snmp.h"

#include "snmp_vars.h"
#include "snmp_agent.h"
#include "agent_handler.h"
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
#include "snmpCallbackDomain.h"

#include "subagent.h"

static SNMPCallback subagent_register_ping_alarm;
static SNMPAlarmCallback agentx_reopen_session;
void agentx_register_callbacks(struct snmp_session *s);
void agentx_unregister_callbacks(struct snmp_session *ss);
int handle_subagent_response(int op, struct snmp_session *session, int reqid,
                             struct snmp_pdu *pdu, void *magic);
int handle_subagent_set_response(int op, struct snmp_session *session,
                                 int reqid, struct snmp_pdu *pdu, void *magic);

struct agent_set_info {
    int			  transID;
    int			  mode;
    int                   errstat;
    time_t		  uptime;
    struct snmp_session  *sess;
    struct variable_list *var_list;
    
    struct agent_set_info *next;
};

static struct agent_set_info *Sets = NULL;

struct snmp_session *agentx_callback_sess = NULL;
extern int callback_master_num;

void
init_subagent(void) {
    agentx_callback_sess =
        snmp_callback_open(callback_master_num,
                           handle_subagent_response,
                           NULL, NULL);
}


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
    ptr->mode    = SNMP_MSG_INTERNAL_SET_RESERVE1;
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
restore_set_vars( struct snmp_session *sess, struct snmp_pdu *pdu )
{
    struct agent_set_info *ptr;

    for ( ptr=Sets ; ptr != NULL ; ptr=ptr->next )
	if ( ptr->sess == sess && ptr->transID == pdu->transid )
	    break;

    if ( ptr == NULL || ptr->var_list == NULL )
	return NULL;

    pdu->variables = snmp_clone_varbind(ptr->var_list);
    if (pdu->variables == NULL)
        return NULL;
    
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

extern struct snmp_session *main_session;	/* from snmp_agent.c */

int
handle_agentx_packet(int operation, struct snmp_session *session, int reqid,
                   struct snmp_pdu *pdu, void *magic)
{
    struct agent_snmp_session  *asp;
    struct agent_set_info      *asi;
    int status, allDone, i;
    struct variable_list *var_ptr, *var_ptr2;
    int (*mycallback)(int operation, struct snmp_session *session, int reqid,
                      struct snmp_pdu *pdu, void *magic);
    void *retmagic;

    if (operation == SNMP_CALLBACK_OP_DISCONNECT) {
      int period = ds_get_int(DS_APPLICATION_ID,DS_AGENT_AGENTX_PING_INTERVAL);
      DEBUGMSGTL(("agentx/subagent", "transport disconnect indication\n"));
      /*  Deregister the ping alarm, if any, and invalidate all other
	  references to this session.  */
      if (session->securityModel != SNMP_DEFAULT_SECMODEL) {
	snmp_alarm_unregister(session->securityModel);
      }
      agentx_unregister_callbacks(session);
      main_session = NULL;
      if (period != 0) {
	/*  Pings are enabled, so periodically attempt to re-establish contact 
	    with the master agent.  Don't worry about the handle,
	    agentx_reopen_session unregisters itself if it succeeds in talking 
	    to the master agent.  */
	snmp_alarm_register(period, SA_REPEAT, agentx_reopen_session, NULL);
      }
      return 0;
    } else if (operation != SNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
      DEBUGMSGTL(("agentx/subagent", "unexpected callback op %d\n",operation));
      return 1;
    }

    /* ok, we have a pdu from the net. Modify as needed */

    pdu->version = agentx_callback_sess->version;
    pdu->flags |= UCD_MSG_FLAG_ALWAYS_IN_VIEW;

    switch(pdu->command) {
        case AGENTX_MSG_GET:
            DEBUGMSGTL(("agentx/subagent","  -> get\n"));
            pdu->command = SNMP_MSG_GET;
            mycallback = handle_subagent_response;
            retmagic = session;
            break;

        case AGENTX_MSG_GETNEXT:
            DEBUGMSGTL(("agentx/subagent","  -> getnext\n"));
            pdu->command = SNMP_MSG_GETNEXT;
            mycallback = handle_subagent_response;
            retmagic = session;
            break;

        case AGENTX_MSG_GETBULK:
            /* WWWXXX */
            DEBUGMSGTL(("agentx/subagent","  -> getbulk\n"));
            pdu->command = SNMP_MSG_GETBULK;
            mycallback = handle_subagent_response;
            retmagic = session;
            break;
            
        case AGENTX_MSG_RESPONSE:
            DEBUGMSGTL(("agentx/subagent","  -> response\n"));
            return 1;

        case AGENTX_MSG_TESTSET:
            /* XXXWWW we have to map this twice to both RESERVE1 and RESERVE2 */
            DEBUGMSGTL(("agentx/subagent","  -> testset\n"));
            asi = save_set_vars( session, pdu );
            asi->mode = pdu->command = SNMP_MSG_INTERNAL_SET_RESERVE1;
            mycallback = handle_subagent_set_response;
            retmagic = asi;
            break;
            
        case AGENTX_MSG_COMMITSET:
            DEBUGMSGTL(("agentx/subagent","  -> commitset\n"));
            asi = restore_set_vars( session, pdu );
            asi->mode = pdu->command = SNMP_MSG_INTERNAL_SET_ACTION;
            mycallback = handle_subagent_set_response;
            retmagic = asi;
            break;

        case AGENTX_MSG_CLEANUPSET:
            DEBUGMSGTL(("agentx/subagent","  -> cleanupset\n"));
            asi = restore_set_vars( session, pdu );
            if (asi->mode == AGENTX_MSG_TESTSET) {
                asi->mode = pdu->command = SNMP_MSG_INTERNAL_SET_FREE;
            } else {
                asi->mode = pdu->command = SNMP_MSG_INTERNAL_SET_COMMIT;
            }
            mycallback = handle_subagent_set_response;
            retmagic = asi;
            break;

        case AGENTX_MSG_UNDOSET:
            DEBUGMSGTL(("agentx/subagent","  -> undoset\n"));
            asi = restore_set_vars( session, pdu );
            asi->mode = pdu->command = SNMP_MSG_INTERNAL_SET_UNDO;
            mycallback = handle_subagent_set_response;
            retmagic = asi;
            break;

        default:
            DEBUGMSGTL(("agentx/subagent","  -> unknown (%d)\n",
                        pdu->command ));
            return 0;
    }

    /* submit the pdu to the internal handler */
    snmp_async_send(agentx_callback_sess, pdu, mycallback, retmagic);
    return 1;
}

int
handle_subagent_response(int op, struct snmp_session *session, int reqid,
                         struct snmp_pdu *pdu, void *magic) 
{
    struct snmp_session *retsess;
    
    if (op != SNMP_CALLBACK_OP_RECEIVED_MESSAGE || magic == NULL) {
      return 1;
    }

    retsess = (struct snmp_session *) magic;
    
    pdu = snmp_clone_pdu(pdu);
    DEBUGMSGTL(("agentx/subagent","handling agentx subagent response....\n"));

    if (pdu->command == SNMP_MSG_INTERNAL_SET_FREE ||
        pdu->command == SNMP_MSG_INTERNAL_SET_UNDO ||
        pdu->command == SNMP_MSG_INTERNAL_SET_COMMIT)
        free_set_vars(retsess, pdu);
    
    pdu->command = AGENTX_MSG_RESPONSE;
    pdu->version = retsess->version;
    
    if (!snmp_send(retsess, pdu)) {
        snmp_free_pdu(pdu);
    }
    DEBUGMSGTL(("agentx/subagent","  FINISHED\n"));
    return 1;
}

int
handle_subagent_set_response(int op, struct snmp_session *session, int reqid,
                             struct snmp_pdu *pdu, void *magic) 
{
    struct snmp_session *retsess;
    struct agent_set_info *asi;
    
    if (op != SNMP_CALLBACK_OP_RECEIVED_MESSAGE || magic == NULL) {
        return 1;
    }

    DEBUGMSGTL(("agentx/subagent",
                "handling agentx subagent set response....\n"));

    asi = (struct snmp_session *) magic;
    retsess = asi->sess;
    asi->errstat = pdu->errstat;
    
    if (pdu->command == SNMP_MSG_INTERNAL_SET_FREE ||
        pdu->command == SNMP_MSG_INTERNAL_SET_UNDO ||
        pdu->command == SNMP_MSG_INTERNAL_SET_COMMIT)
        free_set_vars(retsess, pdu);
    
    pdu->command = AGENTX_MSG_RESPONSE;
    pdu->version = retsess->version;
    
    if (!snmp_send(retsess, pdu)) {
        snmp_free_pdu(pdu);
    }
    DEBUGMSGTL(("agentx/subagent","  FINISHED\n"));
    return 1;
}



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
			   reg_parms->timeout,
			   reg_parms->flags);
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


/*  Register all the "standard" AgentX callbacks for the given session.  */

void
agentx_register_callbacks(struct snmp_session *s)
{
  DEBUGMSGTL(("agentx/subagent", "registering callbacks for session %p\n"));
  snmp_register_callback(SNMP_CALLBACK_LIBRARY,
			 SNMP_CALLBACK_POST_READ_CONFIG,
			 subagent_register_ping_alarm, s);
  snmp_register_callback(SNMP_CALLBACK_LIBRARY,
			 SNMP_CALLBACK_POST_PREMIB_READ_CONFIG,
			 subagent_register_for_traps, s);
  snmp_register_callback(SNMP_CALLBACK_LIBRARY,
			 SNMP_CALLBACK_SHUTDOWN,
			 subagent_shutdown, s);
  snmp_register_callback(SNMP_CALLBACK_APPLICATION,
			 SNMPD_CALLBACK_REGISTER_OID,
			 agentx_registration_callback, s);
  snmp_register_callback(SNMP_CALLBACK_APPLICATION,
			 SNMPD_CALLBACK_UNREGISTER_OID,
			 agentx_registration_callback, s);
#ifdef USING_MIBII_SYSORTABLE_MODULE
  snmp_register_callback(SNMP_CALLBACK_APPLICATION,
			 SNMPD_CALLBACK_REG_SYSOR,
			 agentx_sysOR_callback, s);
  snmp_register_callback(SNMP_CALLBACK_APPLICATION,
			 SNMPD_CALLBACK_UNREG_SYSOR,
			 agentx_sysOR_callback, s);
#endif
}

/*  Unregister all the callbacks associated with this session.  */

void
agentx_unregister_callbacks(struct snmp_session *ss)
{
  DEBUGMSGTL(("agentx/subagent", "unregistering callbacks for session %p\n"));
  snmp_unregister_callback(SNMP_CALLBACK_LIBRARY,
			   SNMP_CALLBACK_POST_READ_CONFIG,
			   subagent_register_ping_alarm, ss, 1);
  snmp_unregister_callback(SNMP_CALLBACK_LIBRARY,
			   SNMP_CALLBACK_POST_PREMIB_READ_CONFIG,
			   subagent_register_for_traps, ss, 1);
  snmp_unregister_callback(SNMP_CALLBACK_LIBRARY,
			   SNMP_CALLBACK_SHUTDOWN,
                           subagent_shutdown, ss, 1);
  snmp_unregister_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_REGISTER_OID,
                           agentx_registration_callback, ss, 1);
  snmp_unregister_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_UNREGISTER_OID,
                           agentx_registration_callback, ss, 1);
#ifdef USING_MIBII_SYSORTABLE_MODULE
  snmp_unregister_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_REG_SYSOR,
                           agentx_sysOR_callback, ss, 1);
  snmp_unregister_callback(SNMP_CALLBACK_APPLICATION,
                           SNMPD_CALLBACK_UNREG_SYSOR,
                           agentx_sysOR_callback, ss, 1);
#endif
    
}

/*  Open a session to the master agent.  */
int
subagent_open_master_session(void) {
    struct snmp_session sess;

    DEBUGMSGTL(("agentx/subagent","opening session....\n"));

    if (main_session) {
        snmp_log(LOG_WARNING,
                 "AgentX session to master agent attempted to be re-opened.");
        return -1;
    }
    
    snmp_sess_init( &sess );
    sess.version = AGENTX_VERSION_1;
    sess.retries = SNMP_DEFAULT_RETRIES;
    sess.timeout = SNMP_DEFAULT_TIMEOUT;
    sess.flags  |= SNMP_FLAGS_STREAM_SOCKET;
    if ( ds_get_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET) )
	sess.peername = ds_get_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET);
    else
	sess.peername = AGENTX_SOCKET;
 
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
        main_session = NULL;
	return -1;
    }

    agentx_register_callbacks(main_session);

    DEBUGMSGTL(("agentx/subagent","opening session...  DONE (%p)\n",
                main_session));

    return 0;
}

/* returns non-zero on error */
int
subagent_pre_init( void )
{
    DEBUGMSGTL(("agentx/subagent","initializing....\n"));

    /* set up callbacks to initiate master agent pings for this session */
    ds_register_config(ASN_INTEGER,
                       ds_get_string(DS_LIBRARY_ID, DS_LIB_APPTYPE),
                       "agentxPingInterval",
                       DS_APPLICATION_ID, DS_AGENT_AGENTX_PING_INTERVAL);


    if ( ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE) != SUB_AGENT )
	return 0;

    if (subagent_open_master_session() != 0) {
	if (ds_get_int(DS_APPLICATION_ID, DS_AGENT_AGENTX_PING_INTERVAL) > 0) {
	    agentx_reopen_session(0, NULL);
	}
        return -1;
    }


    DEBUGMSGTL(("agentx/subagent","initializing....  DONE\n"));
    
    return 0;
}


/*  Alarm callback function to open a session to the master agent.  If a
    transport disconnection callback occurs, indicating that the master agent
    has died (or there has been some strange communication problem), this
    alarm is called repeatedly to try to re-open the connection.  */

void
agentx_reopen_session(unsigned int clientreg, void *clientarg) {
  DEBUGMSGTL(("agentx/subagent", "agentx_reopen_session(%d) called\n",
	      clientreg));

  if (subagent_open_master_session() == 0) {
    /*  Successful.  Delete the alarm handle if one exists.  */
    if (clientreg != 0) {
      snmp_alarm_unregister(clientreg);
    }

    /*  Reregister all our nodes.  */
    register_mib_reattach();

    /*  Register a ping alarm (if need be).  */
    subagent_register_ping_alarm(0, 0, 0, main_session);
  } else {
    if (clientreg == 0) {
      /*  Register a reattach alarm for later */
      subagent_register_ping_alarm(0, 0, 0, main_session);
    }
  }
}

/* If a valid session is passed in (through clientarg), register a
   ping handler to ping it frequently, else register an attempt to try
   and open it again later. */

static int
subagent_register_ping_alarm(int majorID, int minorID,
                             void *serverarg, void *clientarg) {

    struct snmp_session *ss = (struct snmp_session *) clientarg;
    int ping_interval = 
        ds_get_int(DS_APPLICATION_ID, DS_AGENT_AGENTX_PING_INTERVAL);

    if (!ping_interval) /* don't do anything if not setup properly */
        return 0;

    /* register a ping alarm, if desired */
    if (ss) {
      if (ss->securityModel != SNMP_DEFAULT_SECMODEL) {
	DEBUGMSGTL(("agentx/subagent", "unregister existing alarm %d\n",
		    ss->securityModel));
	snmp_alarm_unregister(ss->securityModel);
      }

      DEBUGMSGTL(("agentx/subagent", "register ping alarm every %d seconds\n",
		  ping_interval));
      /* we re-use the securityModel parameter for an alarm stash,
	 since agentx doesn't need it */
      ss->securityModel = snmp_alarm_register(ping_interval, SA_REPEAT,
					      agentx_check_session, ss);
    } else {
        /* attempt to open it later instead */
        DEBUGMSGTL(("agentx/subagent",
                    "subagent not properly attached, postponing registration till later....\n"));
        snmp_alarm_register(ping_interval, SA_REPEAT,
                            agentx_reopen_session, NULL);
    }
    return 0;
}

/* check a session validity for connectivity to the master agent.  If
   not functioning, close and start attempts to reopen the session */
void
agentx_check_session(unsigned int clientreg, void *clientarg) {
    struct snmp_session *ss = (struct snmp_session *) clientarg;
    if (!ss) {
        if (clientreg)
            snmp_alarm_unregister (clientreg);
        return;
    }
    DEBUGMSGTL(("agentx/subagent","checking status of our session (%x)\n",
                ss));
    
    if (!agentx_send_ping(ss)) {
        snmp_log(LOG_WARNING, "AgentX master agent failed to respond to ping.  Attempting to re-register.\n");
        /* master agent disappeared?  Try and re-register */
        /* close first, just to be sure */
        agentx_unregister_callbacks(ss);
        agentx_close_session(ss, AGENTX_CLOSE_TIMEOUT);
        snmp_alarm_unregister(clientreg); /* delete ping alarm timer */
	snmp_close( main_session );
        
        main_session = NULL;
        agentx_reopen_session(0, NULL);
    } else {
        DEBUGMSGTL(("agentx/subagent","status ok, master responded to ping\n"));
    }
}

