/*
 *  SNMPv1 MIB group implementation - snmp.c
 *
 */

#include <config.h>
#include <sys/types.h>
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

#include "mibincl.h"
#include "system.h"
#include "util_funcs.h"

#include "snmp_mib.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

extern int snmp_enableauthentraps;
       int old_snmp_enableauthentraps;

/*********************
 *
 *  Initialisation & common implementation functions
 *
 *********************/

/* define the structure we're going to ask the agent to register our
   information at */
struct variable2 snmp_variables[] = {
    {SNMPINPKTS,              ASN_COUNTER, RONLY,  var_snmp, 1, {1}},
    {SNMPOUTPKTS,             ASN_COUNTER, RONLY,  var_snmp, 1, {2}},
    {SNMPINBADVERSIONS,       ASN_COUNTER, RONLY,  var_snmp, 1, {3}},
    {SNMPINBADCOMMUNITYNAMES, ASN_COUNTER, RONLY,  var_snmp, 1, {4}},
    {SNMPINBADCOMMUNITYUSES,  ASN_COUNTER, RONLY,  var_snmp, 1, {5}},
    {SNMPINASNPARSEERRORS,    ASN_COUNTER, RONLY,  var_snmp, 1, {6}},
    {SNMPINTOOBIGS,           ASN_COUNTER, RONLY,  var_snmp, 1, {8}},
    {SNMPINNOSUCHNAMES,       ASN_COUNTER, RONLY,  var_snmp, 1, {9}},
    {SNMPINBADVALUES,         ASN_COUNTER, RONLY,  var_snmp, 1, {10}},
    {SNMPINREADONLYS,         ASN_COUNTER, RONLY,  var_snmp, 1, {11}},
    {SNMPINGENERRS,           ASN_COUNTER, RONLY,  var_snmp, 1, {12}},
    {SNMPINTOTALREQVARS,      ASN_COUNTER, RONLY,  var_snmp, 1, {13}},
    {SNMPINTOTALSETVARS,      ASN_COUNTER, RONLY,  var_snmp, 1, {14}},
    {SNMPINGETREQUESTS,       ASN_COUNTER, RONLY,  var_snmp, 1, {15}},
    {SNMPINGETNEXTS,          ASN_COUNTER, RONLY,  var_snmp, 1, {16}},
    {SNMPINSETREQUESTS,       ASN_COUNTER, RONLY,  var_snmp, 1, {17}},
    {SNMPINGETRESPONSES,      ASN_COUNTER, RONLY,  var_snmp, 1, {18}},
    {SNMPINTRAPS,             ASN_COUNTER, RONLY,  var_snmp, 1, {19}},
    {SNMPOUTTOOBIGS,          ASN_COUNTER, RONLY,  var_snmp, 1, {20}},
    {SNMPOUTNOSUCHNAMES,      ASN_COUNTER, RONLY,  var_snmp, 1, {21}},
    {SNMPOUTBADVALUES,        ASN_COUNTER, RONLY,  var_snmp, 1, {22}},
    {SNMPOUTGENERRS,          ASN_COUNTER, RONLY,  var_snmp, 1, {24}},
    {SNMPOUTGETREQUESTS,      ASN_COUNTER, RONLY,  var_snmp, 1, {25}},
    {SNMPOUTGETNEXTS,         ASN_COUNTER, RONLY,  var_snmp, 1, {26}},
    {SNMPOUTSETREQUESTS,      ASN_COUNTER, RONLY,  var_snmp, 1, {27}},
    {SNMPOUTGETRESPONSES,     ASN_COUNTER, RONLY,  var_snmp, 1, {28}},
    {SNMPOUTTRAPS,            ASN_COUNTER, RONLY,  var_snmp, 1, {29}},
    {SNMPENABLEAUTHENTRAPS,   ASN_INTEGER, RWRITE, var_snmp, 1, {30}},
    {SNMPSILENTDROPS,         ASN_COUNTER, RONLY,  var_snmp, 1, {31}},
    {SNMPPROXYDROPS,          ASN_COUNTER, RONLY,  var_snmp, 1, {32}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
oid snmp_variables_oid[] = { SNMP_OID_MIB2,11 };

void
init_snmp_mib(void) {
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/snmp", snmp_variables, variable2, snmp_variables_oid);
}


	/*********************
	 *
	 *  System specific implementation functions
	 *	(actually common!)
	 *
	 *********************/


u_char *
var_snmp(struct variable *vp,
	 oid *name,
	 size_t *length,
	 int exact,
	 size_t *var_len,
	 WriteMethod **write_method)
{
    static long long_ret;

    if (header_generic(vp, name, length, exact, var_len, write_method)
				== MATCH_FAILED)
	return NULL;

    /* this is where we do the value assignments for the mib results. */
    if (vp->magic == SNMPENABLEAUTHENTRAPS) {
	*write_method = write_snmp;
	long_return = snmp_enableauthentraps;
	return (u_char *) &long_return;
    } else if ( (vp->magic >= 1) &&
	        (vp->magic <= (STAT_SNMP_STATS_END-STAT_SNMP_STATS_START+1))) {
	long_ret = snmp_get_statistic(vp->magic + STAT_SNMP_STATS_START - 1);
	return (unsigned char *) &long_ret;
    }
    return NULL;
}

/*
 * only for snmpEnableAuthenTraps:
 */

int
write_snmp (int action,
	    u_char *var_val,
	    u_char var_val_type,
	    size_t var_val_len,
	    u_char *statP,
	    oid *name,
	    size_t name_len)
{
    long intval = *((long *) var_val);

    switch ( action ) {
	case RESERVE1:			/* Check values for acceptability */
	    if (var_val_type != ASN_INTEGER){
	        DEBUGMSGTL(("mibII/snmp_mib", "%x not integer type", var_val_type));
		return SNMP_ERR_WRONGTYPE;
	    }
	
	    if (intval != 1 && intval != 2) {
	        DEBUGMSGTL(("mibII/snmp_mib", "not valid %x\n", intval));
		return SNMP_ERR_WRONGVALUE;
	    }
	    break;

	case RESERVE2:			/* Allocate memory and similar resources */

		/* Using static variables, so nothing needs to be done */
	    break;

	case ACTION:			/* Perform the SET action (if reversible) */

		/* Save the old value, in case of UNDO */
	    old_snmp_enableauthentraps = snmp_enableauthentraps;
	    snmp_enableauthentraps = intval;	
	    break;

	case UNDO:			/* Reverse the SET action and free resources */

	    snmp_enableauthentraps = old_snmp_enableauthentraps;
	    break;

	case COMMIT:			/* Confirm the SET, performing any irreversible actions,
						and free resources */
	    /* save_into_conffile ("authentraps:", intval == 1 ? "yes" : "no"); */
	    break;

	case FREE:			/* Free any resources allocated */
	    break;
    }
    return SNMP_ERR_NOERROR;
}
