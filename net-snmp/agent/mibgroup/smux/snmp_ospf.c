/* $Id$ */

/*
 * Smux module authored by Rohit Dube.
 */

#include <config.h>

#include <stdio.h>
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
#if HAVE_ERR_H
#include <err.h>
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
#include <errno.h>
#include <netdb.h>

#include <sys/stat.h>
#include <sys/socket.h>
#if HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "../../../snmplib/system.h"
#include "asn1.h"
#include "snmp.h"
#include "mib.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_vars.h"
#include "smux.h"
#include "snmp_ospf.h"

static oid max_ospf_mib[] = {1, 3, 6, 1, 2, 1, 14, 14, 1, 6, 0};
static oid min_ospf_mib[] = {1, 3, 6, 1, 2, 1, 14, 1, 1, 0, 0, 0, 0};
extern u_char smux_type;

u_char *
var_ospf(vp, name, length, exact, var_len, write_method)
	register struct variable *vp;
	register oid        *name;
	register int        *length;
	int                 exact;
	int                 *var_len;
	int                 (**write_method)__P((int, u_char *, u_char, int, u_char *, oid *, int));
{
	u_char *var;
	int result;
        char c_oid[MAX_NAME_LEN];

        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, name, *length);
          DEBUGP("[var_ospf] var len %d, oid requested Len %d-%s\n",*var_len, *length,c_oid);
        }
        
	/* 
	 * Pass on the request to Gated.
	 * If the request sent out was a get next, check to see if
	 * it lies in the ospf range. If it doesn't, return NULL.
	 * In either case, make sure that errors are checked on the
	 * returned packets.
	 */

	/* No writes for now */
	*write_method = NULL;

	/*
	 * Donot allow access to the peer stuff as it crashes gated.
	 * However A GetNext on the last 23.3.1.9 variable will force gated into
	 * the peer stuff and cause it to crash.
	 * The only way to fix this is to either solve the Gated problem, or 
	 * remove the peer variables from Gated itself and cause it to return
	 * NULL at the crossing. Currently doing the later.
	 */

	/* Reject GET and GETNEXT for anything above ospfifconf range */
	result = compare(name, *length, max_ospf_mib, 
		         sizeof(max_ospf_mib)/sizeof(u_int));

	if (result >= 0) {
                DEBUGP("Over shot\n");
		return NULL;
	}

	/* for GETs we need to be in the ospf range so reject anything below */
	result = compare(name, *length, min_ospf_mib, 
			 sizeof(min_ospf_mib)/sizeof(u_int));
	if (exact && (result < 0)) {
                DEBUGP("Exact but doesn't match length %d, size %d\n",
			*length, sizeof(min_ospf_mib));
		return NULL;
	}

	/* 
	 * On return, 'var' points to the value returned which is of length
	 * '*var_len'. 'name' points to the new (same as the one passed in for 
	 * GETs) oid which has 'length' suboids.
	 * 'smux_type' contains the type of the variable.
	 */
	var = smux_snmp_process(exact, name, length, var_len);

        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, name, *length);
          DEBUGP("[var_ospf] var len %d, oid obtained Len %d-%s\n",*var_len, *length,c_oid);
        }

	vp->type = smux_type;

	/* XXX Need a mechanism to return errors in gated's responses */

	if (var == NULL)
		return NULL;

	/* 
	 * Any resullt returned should be within the ospf tree.
	 * ospf_mib - static u_int ospf_mib[] = {1, 3, 6, 1, 2, 1, 14};
	 */
	if (memcmp(ospf_mib, name, sizeof(ospf_mib)) != 0) {
		return NULL;
	}
	else {
		return var;
	}
}
