/*
 * snmp_agent.c
 *
 * Simple Network Management Protocol (RFC 1067).
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

#include <config.h>

#include <sys/types.h>
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
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
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <errno.h>
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#ifdef USE_LIBWRAP
#include <tcpd.h>
#endif

#define SNMP_NEED_REQUEST_LIST
#include "mibincl.h"
#include "snmp_client.h"
#include "snmp_alarm.h"

#include "snmpd.h"
#include "mibgroup/struct.h"
#include "mibgroup/util_funcs.h"
#include "mib_module_config.h"

#include "default_store.h"
#include "system.h"
#include "ds_agent.h"
#include "snmp_agent.h"
#include "snmp_alarm.h"

#include "snmp_transport.h"
#include "snmpUDPDomain.h"
#ifdef SNMP_TRANSPORT_UNIX_DOMAIN
#include "snmpUnixDomain.h"
#endif
#ifdef SNMP_TRANSPORT_TCP_DOMAIN
#include "snmpTCPDomain.h"
#endif
#ifdef SNMP_TRANSPORT_AAL5PVC_DOMAIN
#include "snmpAAL5PVCDomain.h"
#endif
#ifdef SNMP_TRANSPORT_IPX_DOMAIN
#include "snmpIPXDomain.h"
#endif
#ifdef USING_AGENTX_PROTOCOL_MODULE
#include "agentx/protocol.h"
#endif

#ifdef USING_AGENTX_MASTER_MODULE
#include "agentx/master.h"
#endif

#define SNMP_ADDRCACHE_SIZE 10

struct addrCache {
  char *addr;
  enum { SNMP_ADDRCACHE_UNUSED = 0,
	 SNMP_ADDRCACHE_USED   = 1,
	 SNMP_ADDRCACHE_OLD    = 2 } status;
};

static struct addrCache	addrCache[SNMP_ADDRCACHE_SIZE];
int lastAddrAge = 0;
int log_addresses = 0;



typedef struct _agent_nsap {
  int			handle;
  snmp_transport       *t;
  void		       *s;	/*  Opaque internal session pointer.  */
  struct _agent_nsap   *next;
} agent_nsap;

static	agent_nsap		*agent_nsap_list = NULL;
static int snmp_vars_inc;
static struct agent_snmp_session *agent_session_list = NULL;


static void dump_var(oid *, size_t, int, void *, size_t);
int snmp_check_packet(struct snmp_session*, struct _snmp_transport *,
		      void *, int);
int snmp_check_parse(struct snmp_session*, struct snmp_pdu*, int);

static void dump_var (
    oid *var_name,
    size_t var_name_len,
    int statType,
    void *statP,
    size_t statLen)
{
  size_t buf_len = SPRINT_MAX_LEN, out_len = 0;
  struct variable_list temp_var;
  u_char *buf = (u_char *)malloc(SPRINT_MAX_LEN);
  
  if (buf) {
    temp_var.type = statType;
    temp_var.val.string = (u_char *)statP;
    temp_var.val_len = statLen;
    sprint_realloc_variable(&buf, &buf_len, &out_len, 1,
			    var_name, var_name_len, &temp_var);
    snmp_log(LOG_INFO, "    >> %s\n", buf);
    free(buf);
  }
}


int getNextSessID()
{
    static int SessionID = 0;

    return ++SessionID;
}

int
agent_check_and_process(int block) {
  int numfds;
  fd_set fdset;
  struct timeval timeout = { LONG_MAX, 0 }, *tvp = &timeout;
  int count;
  int fakeblock=0;
  
  numfds = 0;
  FD_ZERO(&fdset);
  snmp_select_info(&numfds, &fdset, tvp, &fakeblock);
  if (block != 0 && fakeblock != 0) {
    /*  There are no alarms registered, and the caller asked for blocking, so
	let select() block forever.  */

    tvp = NULL;
  } else if (block != 0 && fakeblock == 0) {
    /*  The caller asked for blocking, but there is an alarm due sooner than
	LONG_MAX seconds from now, so use the modified timeout returned by
	snmp_select_info as the timeout for select().  */

  } else if (block == 0) {
    /*  The caller does not want us to block at all.  */

    tvp->tv_sec  = 0;
    tvp->tv_usec = 0;
  }

  count = select(numfds, &fdset, 0, 0, tvp);

  if (count > 0) {
    /* packets found, process them */
    snmp_read(&fdset);
  } else switch(count) {
    case 0:
      snmp_timeout();
      break;
    case -1:
      if (errno != EINTR) {
        snmp_log_perror("select");
      }
      return -1;
    default:
      snmp_log(LOG_ERR, "select returned %d\n", count);
      return -1;
  }  /* endif -- count>0 */

  /*  Run requested alarms.  */
  run_alarms();

  return count;
}



/*  Set up the address cache.  */
void snmp_addrcache_initialise(void)
{
  int i = 0;
  
  for (i = 0; i < SNMP_ADDRCACHE_SIZE; i++) {
    addrCache[i].addr = NULL;
    addrCache[i].status = SNMP_ADDRCACHE_UNUSED;
  }
}



/*  Age the entries in the address cache.  */

void snmp_addrcache_age(void)
{
  int i = 0;
  
  lastAddrAge = 0;
  for (i = 0; i < SNMP_ADDRCACHE_SIZE; i++) {
    if (addrCache[i].status == SNMP_ADDRCACHE_OLD) {
      addrCache[i].status = SNMP_ADDRCACHE_UNUSED;
      if (addrCache[i].addr != NULL) {
	free(addrCache[i].addr);
	addrCache[i].addr = NULL;
      }
    }
    if (addrCache[i].status == SNMP_ADDRCACHE_USED) {
      addrCache[i].status = SNMP_ADDRCACHE_OLD;
    }
  }
}

/*******************************************************************-o-******
 * snmp_check_packet
 *
 * Parameters:
 *	session, transport, transport_data, transport_data_length
 *      
 * Returns:
 *	1	On success.
 *	0	On error.
 *
 * Handler for all incoming messages (a.k.a. packets) for the agent.  If using
 * the libwrap utility, log the connection and deny/allow the access. Print
 * output when appropriate, and increment the incoming counter.
 *
 */

int
snmp_check_packet(struct snmp_session *session, snmp_transport *transport,
		  void *transport_data, int transport_data_length)
{
  char *addr_string = NULL;
  int i = 0;

  /*
   * Log the message and/or dump the message.
   * Optionally cache the network address of the sender.
   */

  if (transport != NULL && transport->f_fmtaddr != NULL) {
    /*  Okay I do know how to format this address for logging.  */
    addr_string = transport->f_fmtaddr(transport, transport_data,
				       transport_data_length);
    /*  Don't forget to free() it.  */
  } else {
    /*  Don't know how to format the address for logging.  */
    addr_string = strdup("<UNKNOWN>");
  }

#ifdef  USE_LIBWRAP
  if (hosts_ctl("snmpd", addr_string, addr_string, STRING_UNKNOWN)) {
    snmp_log(allow_severity, "Connection from %s\n", addr_string);
  } else {
    snmp_log(deny_severity, "Connection from %s REFUSED\n", addr_string);
    if (addr_string != NULL) {
      free(addr_string);
    }
    return 0;
  }
#endif/*USE_LIBWRAP*/

  snmp_increment_statistic(STAT_SNMPINPKTS);

  if (log_addresses || ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE)) {
    
    for (i = 0; i < SNMP_ADDRCACHE_SIZE; i++) {
      if ((addrCache[i].status != SNMP_ADDRCACHE_UNUSED) &&
	  (strcmp(addrCache[i].addr, addr_string) == 0)) {
	break;
      }
    }

    if (i >= SNMP_ADDRCACHE_SIZE ||
	ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE)){
      /*  Address wasn't in the cache, so log the packet...  */
      snmp_log(LOG_INFO, "Received SNMP packet(s) from %s\n", addr_string);
      /*  ...and try to cache the address.  */
      for (i = 0; i < SNMP_ADDRCACHE_SIZE; i++) {
	if (addrCache[i].status == SNMP_ADDRCACHE_UNUSED) {
	  if (addrCache[i].addr != NULL) {
	    free(addrCache[i].addr);
	  }
	  addrCache[i].addr   = addr_string;
	  addrCache[i].status = SNMP_ADDRCACHE_USED;
	  addr_string         = NULL;	/* Don't free this 'temporary' string
					   since it's now part of the cache */
	  break;
	}
      }
      if (i >= SNMP_ADDRCACHE_SIZE) {
	/*  We didn't find a free slot to cache the address.  Perhaps we
	    should be using an LRU replacement policy here or something.  Oh
	    well.  */
	DEBUGMSGTL(("snmp_check_packet", "cache overrun"));
      }
    } else {
      addrCache[i].status = SNMP_ADDRCACHE_USED;
    }
  }

  if (addr_string != NULL) {
    free(addr_string);
    addr_string = NULL;
  }
  return 1;
}


int snmp_check_parse(struct snmp_session *session, struct snmp_pdu *pdu,
		     int result)
{
  if (result == 0) {
    if (ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE) &&
	snmp_get_do_logging()) {
      struct variable_list *var_ptr;
	    
      switch (pdu->command) {
      case SNMP_MSG_GET:
	snmp_log(LOG_DEBUG, "  GET message\n"); break;
      case SNMP_MSG_GETNEXT:
	snmp_log(LOG_DEBUG, "  GETNEXT message\n"); break;
      case SNMP_MSG_RESPONSE:
	snmp_log(LOG_DEBUG, "  RESPONSE message\n"); break;
      case SNMP_MSG_SET:
	snmp_log(LOG_DEBUG, "  SET message\n"); break;
      case SNMP_MSG_TRAP:
	snmp_log(LOG_DEBUG, "  TRAP message\n"); break;
      case SNMP_MSG_GETBULK:
	snmp_log(LOG_DEBUG, "  GETBULK message, non-rep=%d, max_rep=%d\n",
		 pdu->errstat, pdu->errindex); break;
      case SNMP_MSG_INFORM:
	snmp_log(LOG_DEBUG, "  INFORM message\n"); break;
      case SNMP_MSG_TRAP2:
	snmp_log(LOG_DEBUG, "  TRAP2 message\n"); break;
      case SNMP_MSG_REPORT:
	snmp_log(LOG_DEBUG, "  REPORT message\n"); break;
      }
	     
      for (var_ptr = pdu->variables; var_ptr != NULL;
	   var_ptr=var_ptr->next_variable) {
	size_t c_oidlen = 256, c_outlen = 0;
	u_char *c_oid = (u_char *)malloc(c_oidlen);

	if (c_oid) {
	  if (!sprint_realloc_objid(&c_oid, &c_oidlen, &c_outlen, 1,
				    var_ptr->name, var_ptr->name_length)) {
	    snmp_log(LOG_DEBUG, "    -- %s [TRUNCATED]\n", c_oid);
	  } else {
	    snmp_log(LOG_DEBUG, "    -- %s\n", c_oid);
	  }
	  free(c_oid);
	}
      }
    }
    return 1;
  }
  return 0; /* XXX: does it matter what the return value is?  Yes: if we
	       return 0, then the PDU is dumped.  */
}


/* Global access to the primary session structure for this agent.
   for Index Allocation use initially. */

/*  I don't understand what this is for at the moment.  AFAICS as long as it
    gets set and points at a session, that's fine.  ???  */

struct snmp_session *main_session = NULL;



/*  Set up an agent session on the given transport.  Return a handle
    which may later be used to de-register this transport.  A return
    value of -1 indicates an error.  */

int	register_agent_nsap	(snmp_transport *t)
{
  struct snmp_session *s, *sp = NULL;
  agent_nsap *a = NULL, *n = NULL, **prevNext = &agent_nsap_list;
  int handle = 0;
  void *isp = NULL;

  if (t == NULL) {
    return -1;
  }

  DEBUGMSGTL(("register_agent_nsap", "fd %d\n", t->sock));

  n = (agent_nsap *)malloc(sizeof(agent_nsap));
  if (n == NULL) {
    return -1;
  }
  s = (struct snmp_session *)malloc(sizeof(struct snmp_session));
  if (s == NULL) {
    free(n);
    return -1;
  }
  memset(s, 0, sizeof(struct snmp_session));
  snmp_sess_init(s);

  /*  Set up the session appropriately for an agent.  */

  s->version         = SNMP_DEFAULT_VERSION;
  s->callback        = handle_snmp_packet;
  s->authenticator   = NULL;
  s->flags           = ds_get_int(DS_APPLICATION_ID, DS_AGENT_FLAGS);
  s->isAuthoritative = SNMP_SESS_AUTHORITATIVE;

  sp  = snmp_add(s, t, snmp_check_packet, snmp_check_parse);
  if (sp == NULL) {
    free(s);
    free(n);
    return -1;
  }

  isp = snmp_sess_pointer(sp);
  if (isp == NULL) {	/*  over-cautious  */
    free(s);
    free(n);
    return -1;
  }

  n->s    = isp;
  n->t    = t;

  if (main_session == NULL) {
    main_session = snmp_sess_session(isp);
  }

  for (a = agent_nsap_list; a != NULL && handle+1 >= a->handle; a = a->next) {
    handle = a->handle;
    prevNext = &(a->next);
  }

  if (handle < INT_MAX) {
    n->handle = handle + 1;
    n->next   = a;
    *prevNext = n;
    free(s);
    return n->handle;
  } else {
    free(s);
    free(n);
    return -1;
  }
}



void	deregister_agent_nsap	(int handle)
{
  agent_nsap *a = NULL, **prevNext = &agent_nsap_list;
  int main_session_deregistered = 0;

  DEBUGMSGTL(("deregister_agent_nsap", "handle %d\n", handle));

  for (a = agent_nsap_list; a != NULL && a->handle < handle; a = a->next) {
    prevNext = &(a->next);
  }

  if (a != NULL && a->handle == handle) {
    *prevNext = a->next;
    if (main_session == snmp_sess_session(a->s)) {
      main_session_deregistered = 1;
    }
    snmp_close(snmp_sess_session(a->s));
    /*  The above free()s the transport and session pointers.  */
    free(a);
  }

  /*  If we've deregistered the session that main_session used to point to,
      then make it point to another one, or in the last resort, make it equal
      to NULL.  Basically this shouldn't ever happen in normal operation
      because main_session starts off pointing at the first session added by
      init_master_agent(), which then discards the handle.  */

  if (main_session_deregistered) {
    if (agent_nsap_list != NULL) {
      DEBUGMSGTL(("snmp_agent",
		  "WARNING: main_session pointer changed from %p to %p\n",
		  main_session, snmp_sess_session(agent_nsap_list->s)));
      main_session = snmp_sess_session(agent_nsap_list->s);
    } else {
      DEBUGMSGTL(("snmp_agent",
		  "WARNING: main_session pointer changed from %p to NULL\n",
		  main_session));
      main_session = NULL;
    }
  }
}



/* 

   This function has been modified to use the experimental register_agent_nsap
   interface.  The major responsibility of this function now is to interpret a
   string specified to the agent (via -p on the command line, or from a
   configuration file) as a list of agent NSAPs on which to listen for SNMP
   packets.  Typically, when you add a new transport domain "foo", you add
   code here such that if the "foo" code is compiled into the agent
   (SNMP_TRANSPORT_FOO_DOMAIN is defined), then a token of the form
   "foo:bletch-3a0054ef%wob&wob" gets turned into the appropriate transport
   descriptor.  register_agent_nsap is then called with that transport
   descriptor and sets up a listening agent session on it.

   Everything then works much as normal: the agent runs in an infinite loop
   (in the snmpd.c/receive()routine), which calls snmp_read() when a request
   is readable on any of the given transports.  This routine then traverses
   the library 'Sessions' list to identify the relevant session and eventually
   invokes '_sess_read'.  This then processes the incoming packet, calling the
   pre_parse, parse, post_parse and callback routines in turn.

   JBPN 20001117
*/

int
init_master_agent(void)
{
  snmp_transport *transport;
  char *cptr, *cptr2;
  char buf[SPRINT_MAX_LEN];

  if (ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE) != MASTER_AGENT) {
    DEBUGMSGTL(("snmp_agent", "init_master_agent; not master agent\n"));
    return 0; /*  No error if ! MASTER_AGENT  */
  }

#ifdef USING_AGENTX_MASTER_MODULE
    if ( ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_AGENTX_MASTER) == 1 )
        real_init_master();
#endif

  /*  Have specific agent ports been specified?  */
  cptr = ds_get_string(DS_APPLICATION_ID, DS_AGENT_PORTS);

  if (cptr) {
    sprintf(buf, "%s", cptr);
  } else {
    /*  No, so just specify the default port.  */
    if (ds_get_int(DS_APPLICATION_ID, DS_AGENT_FLAGS) &
	SNMP_FLAGS_STREAM_SOCKET) {
      sprintf(buf, "tcp:%d", SNMP_PORT);
    } else {
      sprintf(buf, "udp:%d", SNMP_PORT);
    }
  }

  DEBUGMSGTL(("snmp_agent", "final port spec: %s\n", buf));
  cptr = strtok(buf, ",");
  while (cptr) {
    /*  Specification format: 
	
	NONE:			  (a pseudo-transport)
	UDP:[address:]port        (also default if no transport is specified)
	TCP:[address:]port	  (if supported)
	Unix:pathname		  (if supported)
	AAL5PVC:itf.vpi.vci 	  (if supported)
        IPX:[network]:node[/port] (if supported)

    */

    DEBUGMSGTL(("snmp_agent", "installing master agent on port %s\n", cptr));

    if (!cptr || !(*cptr)) {
      snmp_log(LOG_ERR, "improper port specification\n");
      return 1;
    }

    if (strncasecmp(cptr, "none", 4) == 0) {
      DEBUGMSGTL(("snmp_agent",
		  "init_master_agent; pseudo-transport \"none\" requested\n"));
      return 0;
    } 
    transport = snmp_tdomain_transport(cptr, 1, "udp");

    if (transport == NULL) {
      snmp_log(LOG_ERR, "Error opening specified endpoint \"%s\"\n", cptr);
      return 1;
    }

    if (register_agent_nsap(transport) < 0) {
      snmp_log(LOG_ERR,
	     "Error registering specified transport \"%s\" as an agent NSAP\n",
	       cptr);
      return 1;
    } else {
      DEBUGMSGTL(("snmp_agent",
		  "init_master_agent; \"%s\" registered as an agent NSAP\n",
		  cptr));
    }

    /*  Next transport please...  */
    cptr = strtok(NULL, ",");
  }
  return 0;
}



struct agent_snmp_session  *
init_agent_snmp_session( struct snmp_session *session, struct snmp_pdu *pdu )
{
    struct agent_snmp_session  *asp;

    asp = (struct agent_snmp_session *) malloc( sizeof( struct agent_snmp_session ));

    if ( asp == NULL )
	return NULL;
    asp->session = session;
    asp->pdu      = snmp_clone_pdu(pdu);
    asp->orig_pdu = snmp_clone_pdu(pdu);
    asp->rw      = READ;
    asp->exact   = TRUE;
    asp->outstanding_requests = NULL;
    asp->next    = NULL;
    asp->mode    = RESERVE1;
    asp->status  = SNMP_ERR_NOERROR;
    asp->index   = 0;
    asp->inclusive = 0;

    asp->start = asp->pdu->variables;
    asp->end   = asp->pdu->variables;
    if ( asp->end != NULL )
	while ( asp->end->next_variable != NULL )
	    asp->end = asp->end->next_variable;

    return asp;
}

void
free_agent_snmp_session(struct agent_snmp_session *asp)
{
    if (!asp)
	return;
    if (asp->orig_pdu)
	snmp_free_pdu(asp->orig_pdu);
    if (asp->pdu)
	snmp_free_pdu(asp->pdu);

    free(asp);
}

void
dump_sess_list(void)
{
    struct agent_snmp_session *a;
    
    DEBUGMSGTL(("snmp_agent", "DUMP agent_sess_list -> "));
    for (a = agent_session_list; a != NULL; a = a->next) {
	DEBUGMSG(("snmp_agent", "%08p[session %08p] -> ", a, a->session));
    }
    DEBUGMSG(("snmp_agent", "[NIL]\n"));
}

void
remove_and_free_agent_snmp_session(struct agent_snmp_session *asp)
{
    struct agent_snmp_session *a, **prevNext = &agent_session_list;

    DEBUGMSGTL(("snmp_agent", "REMOVE %08p\n", asp));

    for (a = agent_session_list; a != NULL; a = *prevNext) {
	if (a == asp) {
	    *prevNext = a->next;
	    a->next = NULL;
	    free_agent_snmp_session(a);
	    asp = NULL;
	    break;
	} else {
	    prevNext = &(a->next);
	}
    }

    if (a == NULL && asp != NULL) {
	/*  We coulnd't find it on the list, so free it anyway.  */
	free_agent_snmp_session(asp);
    }
}

void
free_agent_snmp_session_by_session(struct snmp_session *sess,
				   void (*free_request)(struct request_list *))
{
    struct agent_snmp_session *a, *next, **prevNext = &agent_session_list;

    DEBUGMSGTL(("snmp_agent", "REMOVE session == %08p\n", sess));

    for (a = agent_session_list; a != NULL; a = next) {
	if (a->session == sess) {
	    *prevNext = a->next;
	    next = a->next;
	    if (a->outstanding_requests != NULL && free_request) {
		struct request_list *r = a->outstanding_requests, *s = NULL;

		DEBUGMSGTL(("snmp_agent", "  has outstanding requests\n"));
		for (; r != NULL; r = s) {
		    s = r->next_request;
		    free_request(r);
		}
	    }
	    free_agent_snmp_session(a);
	} else {
	    prevNext = &(a->next);
	    next = a->next;
	}
    }
}

int
count_varbinds( struct snmp_pdu *pdu )
{
  int count = 0;
  struct variable_list *var_ptr;
  
  for ( var_ptr = pdu->variables ; var_ptr != NULL ;
		  	var_ptr = var_ptr->next_variable )
	count++;

  return count;
}

int
handle_snmp_packet(int op, struct snmp_session *session, int reqid,
                   struct snmp_pdu *pdu, void *magic)
{
    struct agent_snmp_session  *asp;
    int status, allDone, i;
    struct variable_list *var_ptr, *var_ptr2;

    if (op != SNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
      return 1;
    }

    if ( magic == NULL ) {
	asp = init_agent_snmp_session( session, pdu );
	status = SNMP_ERR_NOERROR;
    } else {
	asp = (struct agent_snmp_session *)magic;
        status =   asp->status;
    }

    if (asp->outstanding_requests != NULL) {
      	DEBUGMSGTL(("snmp_handle_packet", "asp->requests != NULL\n"));
	return 1;
    }

    if ( check_access(pdu) != 0) {
        /* access control setup is incorrect */
	send_easy_trap(SNMP_TRAP_AUTHFAIL, 0);
        if (asp->pdu->version != SNMP_VERSION_1 && asp->pdu->version != SNMP_VERSION_2c) {
            asp->pdu->errstat = SNMP_ERR_AUTHORIZATIONERROR;
            asp->pdu->command = SNMP_MSG_RESPONSE;
            snmp_increment_statistic(STAT_SNMPOUTPKTS);
            if (! snmp_send( asp->session, asp->pdu ))
	        snmp_free_pdu(asp->pdu);
	    asp->pdu = NULL;
	    remove_and_free_agent_snmp_session(asp);
            return 1;
        } else {
            /* drop the request */
            remove_and_free_agent_snmp_session( asp );
            return 0;
        }
    }

    switch (pdu->command) {
    case SNMP_MSG_GET:
	if ( asp->mode != RESERVE1 )
	    break;			/* Single pass */
        snmp_increment_statistic(STAT_SNMPINGETREQUESTS);
	status = handle_next_pass( asp );
	asp->mode = RESERVE2;
	break;

    case SNMP_MSG_GETNEXT:
	if ( asp->mode != RESERVE1 )
	    break;			/* Single pass */
        snmp_increment_statistic(STAT_SNMPINGETNEXTS);
	asp->exact   = FALSE;
	status = handle_next_pass( asp );
	asp->mode = RESERVE2;
	break;

    case SNMP_MSG_GETBULK:
	    /*
	     * GETBULKS require multiple passes. The first pass handles the
	     * explicitly requested varbinds, and subsequent passes append
	     * to the existing var_op_list.  Each pass (after the first)
	     * uses the results of the preceeding pass as the input list
	     * (delimited by the start & end pointers.
	     * Processing is terminated if all entries in a pass are
	     * EndOfMib, or the maximum number of repetitions are made.
	     */
	if ( asp->mode == RESERVE1 ) {
            snmp_increment_statistic(STAT_SNMPINGETREQUESTS);
	    asp->exact   = FALSE;

	    if (asp->pdu->errindex < 0) {
		asp->pdu->errindex = 0;
	    }

	    if (asp->pdu->errstat < 0) {
		asp->pdu->errstat = 0;
	    }

		    /*
		     * Limit max repetitions to something reasonable
		     *	XXX: We should figure out what will fit somehow...
		     */
	    if ( asp->pdu->errindex > 100 )
	        asp->pdu->errindex = 100;
    
		    /*
		     * If max-repetitions is 0, we shouldn't
		     *   process the non-nonrepeaters at all
		     *   so set up 'asp->end' accordingly
		     */
	    if ( asp->pdu->errindex == 0 ) {
		if ( asp->pdu->errstat == 0 ) {
				/* Nothing to do at all */
		    snmp_free_varbind(asp->pdu->variables);
		    asp->pdu->variables=NULL;
		    asp->start=NULL;
		} else {
		    asp->end = asp->pdu->variables;
		    i = asp->pdu->errstat;
		    while ( --i > 0 ) {
			if ( asp->end ) {
			    asp->end = asp->end->next_variable;
			}
		    }
		    
		    /*  Note that there may be zero varbinds in the
			request, so asp->end could be NULL here.  */

		    if (asp->end) {
			snmp_free_varbind(asp->end->next_variable);
			asp->end->next_variable = NULL;
		    }
		}
	    }

	    status = handle_next_pass( asp );	/* First pass */
	    asp->mode = RESERVE2;
	    if ( status != SNMP_ERR_NOERROR )
	        break;
    
	    while ( asp->pdu->errstat-- > 0 )	/* Skip non-repeaters */
	    {
	        if ( NULL != asp->start )	/* if there are variables ... */
		    asp->start = asp->start->next_variable;
	    }
	    asp->pdu->errindex--;           /* Handled first repetition */

	    if ( asp->outstanding_requests != NULL )
		return 1;
	}

	if ( NULL != asp->start )	/* if there are variables ... */
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
		if ( var_ptr->type != SNMP_ENDOFMIBVIEW ) {
		    var_ptr2 = snmp_add_null_var(asp->pdu, var_ptr->name, MAX_OID_LEN);
		    for ( i=var_ptr->name_length ; i<MAX_OID_LEN ; i++)
			var_ptr2->name[i] = 0;
		    var_ptr2->name_length = var_ptr->name_length;

		    allDone = FALSE;
		}
	    }
	    if ( allDone )
		break;

	    asp->start = asp->end->next_variable;
	    while ( asp->end->next_variable != NULL )
		asp->end = asp->end->next_variable;
	    
	    status = handle_next_pass( asp );
	    if ( status != SNMP_ERR_NOERROR )
		break;
	    if ( asp->outstanding_requests != NULL )
		return 1;
	}
	break;

    case SNMP_MSG_SET:
    	    /*
	     * SETS require 3-4 passes through the var_op_list.  The first two
	     * passes verify that all types, lengths, and values are valid
	     * and may reserve resources and the third does the set and a
	     * fourth executes any actions.  Then the identical GET RESPONSE
	     * packet is returned.
	     * If either of the first two passes returns an error, another
	     * pass is made so that any reserved resources can be freed.
	     * If the third pass returns an error, another pass is made so that
	     * any changes can be reversed.
	     * If the fourth pass (or any of the error handling passes)
	     * return an error, we'd rather not know about it!
	     */
	if ( asp->mode == RESERVE1 ) {
            snmp_increment_statistic(STAT_SNMPINSETREQUESTS);
	    asp->rw      = WRITE;

	    status = handle_next_pass( asp );

	    if ( status != SNMP_ERR_NOERROR )
	        asp->mode = FREE;
	    else
	        asp->mode = RESERVE2;

	    if ( asp->outstanding_requests != NULL )
		return 1;
	}

	if ( asp->mode == RESERVE2 ) {
	    status = handle_next_pass( asp );

	    if ( status != SNMP_ERR_NOERROR )
	        asp->mode = FREE;
	    else
	        asp->mode = ACTION;

	    if ( asp->outstanding_requests != NULL )
		return 1;
	}

	if ( asp->mode == ACTION ) {
	    status = handle_next_pass( asp );

	    if ( status != SNMP_ERR_NOERROR )
	        asp->mode = UNDO;
	    else
	        asp->mode = COMMIT;

	    if ( asp->outstanding_requests != NULL )
		return 1;
	}

	if ( asp->mode == COMMIT ) {
	    status = handle_next_pass( asp );

	    if ( status != SNMP_ERR_NOERROR ) {
		status    = SNMP_ERR_COMMITFAILED;
	        asp->mode = FINISHED_FAILURE;
	    }
	    else
	        asp->mode = FINISHED_SUCCESS;

	    if ( asp->outstanding_requests != NULL )
		return 1;
	}

	if ( asp->mode == UNDO ) {
	    if (handle_next_pass( asp ) != SNMP_ERR_NOERROR )
		status = SNMP_ERR_UNDOFAILED;

	    asp->mode = FINISHED_FAILURE;
	    break;
	}

	if ( asp->mode == FREE ) {
	    (void) handle_next_pass( asp );
	    break;
	}

	break;

    case SNMP_MSG_RESPONSE:
        snmp_increment_statistic(STAT_SNMPINGETRESPONSES);
	remove_and_free_agent_snmp_session( asp );
	return 0;
    case SNMP_MSG_TRAP:
    case SNMP_MSG_TRAP2:
        snmp_increment_statistic(STAT_SNMPINTRAPS);
	remove_and_free_agent_snmp_session( asp );
	return 0;
    default:
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
	remove_and_free_agent_snmp_session( asp );
	return 0;
    }

    if ( asp->outstanding_requests != NULL ) {
	struct agent_snmp_session *a = agent_session_list;
	asp->status = status;
	
	/*  Careful not to add duplicates.  */

	for (; a != NULL; a = a->next) {
	    if (a == asp) {
		break;
	    }
	}
	if (a == NULL) {
	    asp->next = agent_session_list;
	    agent_session_list = asp;
	    DEBUGMSGTL(("snmp_agent", "ADDED %08p agent_sess_list -> ", asp));
	    for (a = agent_session_list; a != NULL; a = a->next) {
		DEBUGMSG(("snmp_agent", "%08p -> ", a));
	    }
	    DEBUGMSG(("snmp_agent", "[NIL]\n"));
	} else {
	    DEBUGMSGTL(("snmp_agent", "DID NOT ADD %08p (duplicate)\n", asp));
	}
    } else {
		/*
		 * May need to "dumb down" a SET error status for a
		 *  v1 query.  See RFC2576 - section 4.3
		 */
	if (( asp->pdu                          ) &&
	    ( asp->pdu->command == SNMP_MSG_SET ) &&
	    ( asp->pdu->version == SNMP_VERSION_1 )) {
	    switch ( status ) {
		case SNMP_ERR_WRONGVALUE:
		case SNMP_ERR_WRONGENCODING:
		case SNMP_ERR_WRONGTYPE:
		case SNMP_ERR_WRONGLENGTH:
		case SNMP_ERR_INCONSISTENTVALUE:
			status = SNMP_ERR_BADVALUE;
			break;
		case SNMP_ERR_NOACCESS:
		case SNMP_ERR_NOTWRITABLE:
		case SNMP_ERR_NOCREATION:
		case SNMP_ERR_INCONSISTENTNAME:
			status = SNMP_ERR_NOSUCHNAME;
			break;
		case SNMP_ERR_AUTHORIZATIONERROR:
		    /*  From RFC 2576, p. 24: "Whenever the SNMPv2
			error-status value of authorizationError is translated
			to an SNMPv1 error-status value of noSuchName, the
			value of snmpInBadCommunityUses MUST be incremented."*/
		    snmp_increment_statistic(STAT_SNMPINBADCOMMUNITYUSES);
		    status = SNMP_ERR_NOSUCHNAME;
		    break;
		case SNMP_ERR_RESOURCEUNAVAILABLE:
		case SNMP_ERR_COMMITFAILED:
		case SNMP_ERR_UNDOFAILED:
			status = SNMP_ERR_GENERR;
			break;
	    }
	}
		/*
		 * Similarly we may need to "dumb down" v2 exception
		 *  types to throw an error for a v1 query.
		 *  See RFC2576 - section 4.1.2.3
		 */
	if (( asp->pdu                          ) &&
	    ( asp->pdu->command != SNMP_MSG_SET ) &&
	    ( asp->pdu->version == SNMP_VERSION_1 )) {
		for ( var_ptr = asp->pdu->variables, i=1 ;
			var_ptr != NULL ;
			var_ptr = var_ptr->next_variable, i++ ) {
	    	    switch ( var_ptr->type ) {
			case SNMP_NOSUCHOBJECT:
			case SNMP_NOSUCHINSTANCE:
			case SNMP_ENDOFMIBVIEW:
			case ASN_COUNTER64:
				status = SNMP_ERR_NOSUCHNAME;
				asp->index=i;
				break;
		    }
	    }
	}

	if (( status == SNMP_ERR_NOERROR ) && ( asp->pdu )) {
	    snmp_increment_statistic_by(
		(asp->pdu->command == SNMP_MSG_SET ?
			STAT_SNMPINTOTALSETVARS : STAT_SNMPINTOTALREQVARS ),
	    	count_varbinds( asp->pdu ));
	} else {
		/*
		 * Use a copy of the original request
		 *   to report failures.
		 */
	    snmp_free_pdu( asp->pdu );
	    asp->pdu = asp->orig_pdu;
	    asp->orig_pdu = NULL;
	}

	if ( asp->pdu ) {
	    asp->pdu->command  = SNMP_MSG_RESPONSE;
	    asp->pdu->errstat  = status;
	    if (status == SNMP_ERR_NOERROR) {
		asp->pdu->errindex = 0;
	    } else {
		asp->pdu->errindex = asp->index;
	    }
	    if (!snmp_send(asp->session, asp->pdu)) {
	        snmp_free_pdu(asp->pdu);
	    }
	    snmp_increment_statistic(STAT_SNMPOUTPKTS);
	    snmp_increment_statistic(STAT_SNMPOUTGETRESPONSES);
	    asp->pdu = NULL;
	    remove_and_free_agent_snmp_session(asp);
	}
    }
    DEBUGMSGTL(("snmp_agent", "end of handle_snmp_packet, asp = %08p\n", asp));
    return 1;
}

#ifdef USING_AGENTX_PROTOCOL_MODULE
void fully_free_agentx_request(struct request_list *req);
#endif

int
handle_next_pass(struct agent_snmp_session  *asp)
{
    struct request_list *req_p, *next_req, **prevNext;
    int status, er;


    if (asp->outstanding_requests != NULL) {
	return SNMP_ERR_NOERROR;
    }

    status = handle_var_list(asp);
    
    if (asp->outstanding_requests != NULL) {
	if (status == SNMP_ERR_NOERROR) {
	    /*  Send out any subagent requests.  */

	    prevNext = &(asp->outstanding_requests);

	    for (req_p = asp->outstanding_requests; req_p; req_p = next_req) {
		next_req = req_p->next_request;
		er = req_p->pdu->flags & UCD_MSG_FLAG_EXPECT_RESPONSE;

		if (snmp_async_send(req_p->session, req_p->pdu,
				    req_p->callback, req_p->cb_data) == 0) {
		    /*  Send failed - call callback to handle this.  */
		    (void)req_p->callback(SNMP_CALLBACK_OP_SEND_FAILED,
					  req_p->session,
					  req_p->pdu->reqid,
					  req_p->pdu,
					  req_p->cb_data);
		    return SNMP_ERR_GENERR;
		}

		if (!er) {
		    /*  We don't expect a response, so this can come off the
			oustanding request queue now.  */

		    DEBUGMSGTL(("snmp_agent", "no response expected\n"));
		    *prevNext = next_req;
#ifdef USING_AGENTX_PROTOCOL_MODULE
		    fully_free_agentx_request(req_p);
#else
		    /*  This probably leaks memory as it doesn't do a "deep
			free".  It shouldn't ever get called though (maybe
			SMUX?).  */
		    free(req_p);
#endif
		} else {
		    prevNext = &(req_p->next_request);
		}
	    }
	} else {
	    /*  Discard outstanding requests.  */
	    for (req_p = asp->outstanding_requests; req_p; req_p = next_req) {
		next_req = req_p->next_request;
#ifdef USING_AGENTX_PROTOCOL_MODULE
		fully_free_agentx_request(req_p);
#else
		/*  This probably leaks memory as it doesn't do a "deep
		    free".  It shouldn't ever get called though (maybe
		    SMUX?).  */
		free(req_p);
#endif
	    }
	    asp->outstanding_requests = NULL;
	}
    }
    return status;
}

	/*
	 *  Private structure to save the results of a getStatPtr call.
	 *  This data can then be used to avoid repeating this call on
	 *  subsequent SET handling passes.
	 */
struct saved_var_data {
    WriteMethod *write_method;
    u_char	*statP;
    u_char	statType;
    size_t	statLen;
    u_short	acl;
};


int
handle_var_list(struct agent_snmp_session  *asp)
{
    struct variable_list *varbind_ptr;
    int     status;
    int     count;

    count = 0;
    varbind_ptr = asp->start;
    if ( !varbind_ptr ) {
	return SNMP_ERR_NOERROR;
    }

    while (1) {
	count++;
	asp->index = count;

	if (varbind_ptr->type == ASN_PRIV_INCL_RANGE) {
	  DEBUGMSGTL(("snmp_agent", "inclusive range for "));
	  DEBUGMSGOID(("snmp_agent", varbind_ptr->name, varbind_ptr->name_length));
	  DEBUGMSG(("snmp_agent", " (exact %d)\n", asp->exact));
	  asp->exact = 1;
	  status = handle_one_var(asp, varbind_ptr);

	  if (status == SNMP_ERR_NOERROR &&
	      (varbind_ptr->type != SNMP_NOSUCHOBJECT) &&
	      (varbind_ptr->type != SNMP_NOSUCHINSTANCE)) {
	    DEBUGMSGTL(("snmp_agent", "exact get did the trick\n"));
	  } else {
	    DEBUGMSGTL(("snmp_agent", "exact no good, try inexact\n"));
	    asp->exact = 0;
	    status = handle_one_var(asp, varbind_ptr);
	  }
	} else {
	  status = handle_one_var(asp, varbind_ptr);
	}

	if (status != SNMP_ERR_NOERROR) {
	    return status;
	}

	if (varbind_ptr == asp->end) {
	     break;
	}
	varbind_ptr = varbind_ptr->next_variable;
	if (asp->mode == RESERVE1) {
	    snmp_vars_inc++;
	}
   }

   return SNMP_ERR_NOERROR;
}

static struct agent_snmp_session *current_agent_session = NULL;
struct agent_snmp_session  *
get_current_agent_session() {
    return current_agent_session;
}

void
set_current_agent_session(struct agent_snmp_session  *asp) {
    current_agent_session = asp;
}

int
handle_one_var(struct agent_snmp_session  *asp, struct variable_list *varbind_ptr)
{
    u_char  statType;
    u_char *statP;
    size_t  statLen;
    u_short acl;
    struct saved_var_data *saved;
    WriteMethod *write_method;
    AddVarMethod *add_method;
    int	    noSuchObject = TRUE;
    int     view;
    oid	    save[MAX_OID_LEN];
    size_t  savelen = 0;
    
statp_loop:
	if ( asp->rw == WRITE && varbind_ptr->data != NULL ) {
		/*
		 * SET handling is "multi-pass", so restore
		 *  results from an earlier 'getStatPtr' call
		 *  to avoid repeating this processing.
		 */
	    saved = (struct saved_var_data *) varbind_ptr->data;
	    write_method = saved->write_method;
	    statP        = saved->statP;
	    statType     = saved->statType;
	    statLen      = saved->statLen;
	    acl          = saved->acl;
	}
	else {
		/*
		 *  For exact requests (i.e. GET/SET),
		 *   check whether this object is accessible
		 *   before actually doing any work
		 */
	    if ( asp->exact )
		view = in_a_view(varbind_ptr->name, &varbind_ptr->name_length,
				   asp->pdu, varbind_ptr->type);
	    else
		view = 0;	/* Assume accessible */
	    
            memcpy(save, varbind_ptr->name,
			varbind_ptr->name_length*sizeof(oid));
            savelen = varbind_ptr->name_length;
	    if ( view == 0 ) {
                struct agent_snmp_session  *oldval = get_current_agent_session();
                set_current_agent_session(asp);
	        statP = getStatPtr(  varbind_ptr->name,
			   &varbind_ptr->name_length,
			   &statType, &statLen, &acl,
			   asp->exact, &write_method, asp->pdu, &noSuchObject);
                set_current_agent_session(oldval);
            }
	    else {
		if (view != 5) send_easy_trap(SNMP_TRAP_AUTHFAIL, 0);
		statP        = NULL;
		write_method = NULL;
	    }
	}
			   
		/*
		 * For a valid SET request, having no existing value
		 *  is (possibly) acceptable (and implies creation).
		 * In all other situations, this indicates failure.
		 */
	if (statP == NULL && (asp->rw != WRITE || write_method == NULL)) {
	        /*  Careful -- if the varbind was lengthy, it will have
		    allocated some memory.  */
	        snmp_set_var_value(varbind_ptr, NULL, 0);
		if ( asp->exact ) {
	            if ( noSuchObject == TRUE ){
		        statType = SNMP_NOSUCHOBJECT;
		    } else {
		        statType = SNMP_NOSUCHINSTANCE;
		    }
		} else {
	            statType = SNMP_ENDOFMIBVIEW;
		}
		if (asp->pdu->version == SNMP_VERSION_1) {
		    return SNMP_ERR_NOSUCHNAME;
		}
		else if (asp->rw == WRITE) {
		    return
			( noSuchObject	? SNMP_ERR_NOTWRITABLE
					: SNMP_ERR_NOCREATION ) ;
		}
		else
		    varbind_ptr->type = statType;
	}
                /*
		 * Delegated variables should be added to the
                 *  relevant outgoing request
		 */
        else if (IS_DELEGATED(statType)) {
                add_method = (AddVarMethod*)statP;
                return (*add_method)(asp, varbind_ptr);
        }
		/*
		 * GETNEXT/GETBULK should just skip inaccessible entries
		 */
	else if (!asp->exact &&
		 (view = in_a_view(varbind_ptr->name, &varbind_ptr->name_length,
				   asp->pdu, varbind_ptr->type))) {

		if (view != 5) send_easy_trap(SNMP_TRAP_AUTHFAIL, 0);
		goto statp_loop;
	}
		/*
		 * Other access problems are permanent
		 *   (i.e. writing to non-writeable objects)
		 */
	else if ( asp->rw == WRITE && !((acl & 2) && write_method)) {
	    send_easy_trap(SNMP_TRAP_AUTHFAIL, 0);
	    if (asp->pdu->version == SNMP_VERSION_1 ) {
		return SNMP_ERR_NOSUCHNAME;
	    }
	    else {
		return SNMP_ERR_NOTWRITABLE;
	    }
        }
		
	else {
		/*
		 *  Things appear to have worked (so far)
		 *  Dump the current value of this object
		 */
	    if (ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE) && statP)
	        dump_var(varbind_ptr->name, varbind_ptr->name_length,
				statType, statP, statLen);

		/*
		 *  FINALLY we can act on SET requests ....
		 */
	    if ( asp->rw == WRITE ) {
                    struct agent_snmp_session  *oldval =
                        get_current_agent_session();
		    if ( varbind_ptr->data == NULL ) {
				/*
				 * Save the results from 'getStatPtr'
				 *  to avoid repeating this call
				 */
			saved = (struct saved_var_data *)malloc(sizeof(struct saved_var_data));
			if ( saved == NULL ) {
			    return SNMP_ERR_GENERR;
			}
	    		saved->write_method = write_method;
	    		saved->statP        = statP;
	    		saved->statType     = statType;
	    		saved->statLen      = statLen;
	    		saved->acl          = acl;
			varbind_ptr->data = (void *)saved;
		    }
				/*
				 * Call the object's write method
				 */
                    set_current_agent_session(asp);
		    return (*write_method)(asp->mode,
                                               varbind_ptr->val.string,
                                               varbind_ptr->type,
                                               varbind_ptr->val_len, statP,
                                               varbind_ptr->name,
                                               varbind_ptr->name_length);
                    set_current_agent_session(oldval);
	    }
		/*
		 * ... or save the results from assorted GET requests
		 */
	    else {
		snmp_set_var_value(varbind_ptr, statP, statLen);
		varbind_ptr->type = statType;
	    }
	}

	return SNMP_ERR_NOERROR;
	
}
