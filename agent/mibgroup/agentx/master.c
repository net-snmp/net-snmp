/*
 *  AgentX master agent
 */
#include "config.h"

#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/errno.h>

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
#include "default_store.h"
#include "ds_agent.h"


int
get_agentx_transID( int reqID, snmp_ipaddr *address )
{
	/*
	 * This needs to distinguish duplicate request ID's
	 *   from separate adresses or sessions
	 */

    return reqID;	/* It'll do for now */
}

void init_master(void)
{
    struct snmp_session sess, *session=&sess;

    if ( ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE) != MASTER_AGENT )
	return;

    snmp_sess_init( session );
    session->version  = AGENTX_VERSION_1;
    session->peername = strdup(AGENTX_SOCKET);
    session->flags  |= SNMP_FLAGS_STREAM_SOCKET;

    session->local_port = 1;         /* server */
    session->callback = handle_master_agentx_packet;
    session = snmp_open( &sess );

    if ( session == NULL && sess.s_errno == EADDRINUSE ) {
		/*
		 * Could be a left-over socket (now deleted)
		 * Try again
		 */
        session = snmp_open( &sess );
    }

    if ( session == NULL ) {
	snmp_sess_perror("init_master", &sess);
	/*return;*/
	exit(1);
    }

    set_parse( session, agentx_parse );
    set_build( session, agentx_build );
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
    return (u_char*)add_method;
}

struct variable2 agentx_varlist[] = {
  {0, ASN_PRIV_DELEGATED, RWRITE /* or RONLY ? */, agentx_var, 0, {0}}
};
