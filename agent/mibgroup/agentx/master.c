/*
 *  AgentX master agent
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

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp.h"

#include "snmp_vars.h"
#include "var_struct.h"
#include "snmpd.h"
#include "agentx/protocol.h"
#include "agentx/master_admin.h"
#include "agentx/master_request.h"
#include "snmp_debug.h"
#include "default_store.h"
#include "ds_agent.h"
#include "system.h"
#include "snmp_logging.h"
#include "read_config.h"
#include "agent_read_config.h"


void parse_master_extensions(const char *token, 
				 char *cptr)
{
    int i;
    char buf[BUFSIZ];

    if ( !strcmp( cptr, "agentx" ) ||
         !strcmp( cptr, "all"    ) ||
         !strcmp( cptr, "yes"    ) ||
         !strcmp( cptr, "on"     )) {
		i = 1;
         snmp_log(LOG_INFO,
		"Turning on AgentX master support.\n");
	 snmp_log(LOG_INFO,
		"Note this is still experimental and shouldn't be used on critical systems.\n");
    }
    else if ( !strcmp( cptr, "no"  ) ||
              !strcmp( cptr, "off" ))
		i = 0;
    else
		i = atoi(cptr);

    if (i < 0 || i > 1) {
	sprintf(buf, "master '%s' unrecognised", cptr);
	config_perror( buf );
    }
    else
	ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_AGENTX_MASTER, i );
}

void init_master(void)
{
    /*
     * Don't set this up as part of the per-module initialisation.
     * Delay this until the 'init_master_agent()' routine is called,
     *   so that the config settings have been processed.
     * This means that we can use a config directive to determine
     *   whether or not to run as an AgentX master.
     */

  snmpd_register_config_handler("master",
                          parse_master_extensions, NULL,
                          "specify 'agentx' for AgentX support");
}

void real_init_master(void)
{
    struct snmp_session sess, *session;

    if ( ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE) != MASTER_AGENT )
	return;

    DEBUGMSGTL(("agentx/master","initializing...\n"));
    snmp_sess_init( &sess );
    sess.version  = AGENTX_VERSION_1;
    sess.flags  |= SNMP_FLAGS_STREAM_SOCKET;
    if ( ds_get_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET) )
	sess.peername = strdup(ds_get_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET));
    else
	sess.peername = strdup(AGENTX_SOCKET);

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
    session = snmp_open_ex( &sess, 0, agentx_parse, 0, agentx_build,
                            agentx_check_packet );

    if ( session == NULL && sess.s_errno == EADDRINUSE ) {
		/*
		 * Could be a left-over socket (now deleted)
		 * Try again
		 */
        session = snmp_open_ex( &sess, 0, agentx_parse, 0, agentx_build,
                            agentx_check_packet );
    }

    if ( session == NULL ) {
      /* diagnose snmp_open errors with the input struct snmp_session pointer */
	snmp_sess_perror("init_master", &sess);
	if (!ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS))
	    exit(1);
    }

    DEBUGMSGTL(("agentx/master","initializing...   DONE\n"));
}

u_char *
agentx_var(struct variable *vp,
           oid *name,
           size_t *length,
           int exact,
           size_t *var_len,
           WriteMethod **write_method)
{
    int result;
    AddVarMethod *add_method;

    DEBUGMSGTL(("agentx/master","request to pass to client:  "));
    DEBUGMSGOID(("agentx/master", name, *length));
    DEBUGMSG(("agentx/master","\n"));
	/*
	 * If the requested OID precedes the area of responsibility
	 * of this subagent (and hence it's presumable a non-exact match),
	 * then update the "matched" name to be the starting point
	 */
        /* XXX shouldn't we check exact in this case? */
    result = snmp_oid_compare(name, *length, vp->name, vp->namelen);
    if ( result < 0 ) {
	memcpy((char *)name,(char *)vp->name, vp->namelen*sizeof(oid));
	*length = vp->namelen;
    }
				/* Return a pointer to an appropriate method */
    add_method  = agentx_add_request;
    *var_len = sizeof( add_method );
    return (u_char*)add_method;
}

struct variable2 agentx_varlist[] = {
  {0, ASN_PRIV_DELEGATED, RWRITE /* or RONLY ? */, agentx_var, 0, {0}}
};
