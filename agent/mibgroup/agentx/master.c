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
      /* diagnose snmp_open errors with the input struct snmp_session pointer */
	snmp_sess_perror("real_init_master", &sess);
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

    DEBUGMSGTL(("agentx/master", "%sexact request to pass to client: ",
		exact?"":"in"));
    DEBUGMSGOID(("agentx/master", name, *length));
    DEBUGMSG(("agentx/master", " (vp->name "));
    DEBUGMSGOID(("agentx/master", vp->name, vp->namelen));
    DEBUGMSG(("agentx/master", ")\n"));

	/*
	 * If the requested OID precedes the area of responsibility
	 * of this subagent (and hence it's presumable a non-exact match),
	 * then update the "matched" name to be the starting point
	 */
        /* XXX shouldn't we check exact in this case? */

    result = snmp_oid_compare(name, *length, vp->name, vp->namelen);
    DEBUGMSGTL(("agentx/master", "snmp_oid_compare(name, vp->name) = %d\n",
		result));

    if (result < 0) {
	/*  In this case, we will want an INCLUSIVE search range.  */
	memcpy((char *)name, (char *)vp->name, vp->namelen*sizeof(oid));
	*length = vp->namelen;
	add_method  = agentx_add_inclusive;
    } else {
	/*  Otherwise we want an EXCLUSIVE search range.  */
	add_method  = agentx_add_exclusive;
    }

    *var_len = sizeof(add_method);
    return (u_char*)add_method;
}

struct variable2 agentx_varlist[] = {
  {0, ASN_PRIV_DELEGATED, RWRITE /* or RONLY ? */, agentx_var, 0, {0}}
};
