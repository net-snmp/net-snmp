/* $Id$ */

/*
 * Smux module authored by Rohit Dube.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <time.h>
#include <errno.h>
#include <netdb.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/filio.h> 

#include <netinet/in.h>


#include "asn1.h"
#include "snmp.h"
#include "mib.h"
#include "snmp_impl.h"
#include "snmp_vars.h"
#include "smux.h"

static u_int max_ospf_mib[] = {1, 3, 6, 1, 2, 1, 14, 14, 1, 6, 0};
static u_int min_ospf_mib[] = {1, 3, 6, 1, 2, 1, 14, 1, 1, 0, 0, 0, 0};
extern u_char smux_type;

u_char *
var_ospf(vp, name, length, exact, var_len, write_method)
	register struct variable *vp;
	register oid        *name;
	register int        *length;
	int                 exact;
	int                 *var_len;
	int                 (**write_method)();
{
	u_char *var;
	int result;

#ifdef SMUXDEBUG
	printf("[var_ospf] var len %d, oid requested Len %d-",*var_len, *length);
	print_oid(name, *length);
	printf("\n");
#endif

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
#ifdef SMUXDEBUG
		printf("Over shot\n");
#endif
		return NULL;
	}

	/* for GETs we need to be in the ospf range so reject anything below */
	result = compare(name, *length, min_ospf_mib, 
			 sizeof(min_ospf_mib)/sizeof(u_int));
	if (exact && (result < 0)) {
#ifdef SMUXDEBUG
		printf("Exact but doesn't match length %d, size %d\n",
			*length, sizeof(min_ospf_mib));
#endif
		return NULL;
	}

	/* 
	 * On return, 'var' points to the value returned which is of length
	 * '*var_len'. 'name' points to the new (same as the one passed in for 
	 * GETs) oid which has 'length' suboids.
	 * 'smux_type' contains the type of the variable.
	 */
	var = smux_snmp_process(exact, name, length, var_len);

#ifdef SMUXDEBUG
	printf("[var_ospf] var len %d, oid obtained Len %d-",*var_len, *length);
	print_oid(name, *length);
	printf("\n");
#endif

	vp->type = smux_type;

	/* XXX Need a mechanism to return errors in gated's responses */

	if (var == NULL)
		return NULL;

	/* 
	 * Any resullt returned should be within the ospf tree.
	 * ospf_mib - static u_int ospf_mib[] = {1, 3, 6, 1, 2, 1, 14};
	 */
	if (bcmp(ospf_mib, name, sizeof(ospf_mib)) != 0) {
		return NULL;
	}
	else {
		return var;
	}
}
