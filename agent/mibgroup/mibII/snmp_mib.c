/*
 *  SNMPv1 MIB group implementation - snmp.c
 *
 */

#include <config.h>
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "../mibincl.h"
#include "../../../snmplib/system.h"

/* #include "../common_header.h" */
#include "snmp_mib.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


int snmp_inpkts = 0;
int snmp_outpkts = 0;
int snmp_inbadversions = 0;
int snmp_inbadcommunitynames = 0;
int snmp_inbadcommunityuses = 0;
int snmp_inasnparseerrors = 0;
int snmp_intoobigs = 0;
int snmp_innosuchnames = 0;
int snmp_inbadvalues = 0;
int snmp_inreadonlys = 0;
int snmp_ingenerrs = 0;
int snmp_intotalreqvars = 0;
int snmp_intotalsetvars = 0;
int snmp_ingetrequests = 0;
int snmp_ingetnexts = 0;
int snmp_insetrequests = 0;
int snmp_ingetresponses = 0;
int snmp_intraps = 0;
int snmp_outtoobigs = 0;
int snmp_outnosuchnames = 0;
int snmp_outbadvalues = 0;
int snmp_outgenerrs = 0;
int snmp_outgetrequests = 0;
int snmp_outgetnexts = 0;
int snmp_outsetrequests = 0;
int snmp_outgetresponses = 0;
int snmp_outtraps = 0;

extern int snmp_enableauthentraps;

/*********************
 *
 *  Initialisation & common implementation functions
 *
 *********************/

/* define the structure we're going to ask the agent to register our
   information at */
struct variable2 snmp_variables[] = {
    {SNMPINPKTS, ASN_COUNTER, RONLY, var_snmp, 1, {1}},
    {SNMPOUTPKTS, ASN_COUNTER, RONLY, var_snmp, 1, {2}},
    {SNMPINBADVERSIONS, ASN_COUNTER, RONLY, var_snmp, 1, {3}},
    {SNMPINBADCOMMUNITYNAMES, ASN_COUNTER, RONLY, var_snmp, 1, {4}},
    {SNMPINBADCOMMUNITYUSES, ASN_COUNTER, RONLY, var_snmp, 1, {5}},
    {SNMPINASNPARSEERRORS, ASN_COUNTER, RONLY, var_snmp, 1, {6}},
    {SNMPINTOOBIGS, ASN_COUNTER, RONLY, var_snmp, 1, {8}},
    {SNMPINNOSUCHNAMES, ASN_COUNTER, RONLY, var_snmp, 1, {9}},
    {SNMPINBADVALUES, ASN_COUNTER, RONLY, var_snmp, 1, {10}},
    {SNMPINREADONLYS, ASN_COUNTER, RONLY, var_snmp, 1, {11}},
    {SNMPINGENERRS, ASN_COUNTER, RONLY, var_snmp, 1, {12}},
    {SNMPINTOTALREQVARS, ASN_COUNTER, RONLY, var_snmp, 1, {13}},
    {SNMPINTOTALSETVARS, ASN_COUNTER, RONLY, var_snmp, 1, {14}},
    {SNMPINGETREQUESTS, ASN_COUNTER, RONLY, var_snmp, 1, {15}},
    {SNMPINGETNEXTS, ASN_COUNTER, RONLY, var_snmp, 1, {16}},
    {SNMPINSETREQUESTS, ASN_COUNTER, RONLY, var_snmp, 1, {17}},
    {SNMPINGETRESPONSES, ASN_COUNTER, RONLY, var_snmp, 1, {18}},
    {SNMPINTRAPS, ASN_COUNTER, RONLY, var_snmp, 1, {19}},
    {SNMPOUTTOOBIGS, ASN_COUNTER, RONLY, var_snmp, 1, {20}},
    {SNMPOUTNOSUCHNAMES, ASN_COUNTER, RONLY, var_snmp, 1, {21}},
    {SNMPOUTBADVALUES, ASN_COUNTER, RONLY, var_snmp, 1, {22}},
    {SNMPOUTGENERRS, ASN_COUNTER, RONLY, var_snmp, 1, {24}},
    {SNMPOUTGETREQUESTS, ASN_COUNTER, RONLY, var_snmp, 1, {25}},
    {SNMPOUTGETNEXTS, ASN_COUNTER, RONLY, var_snmp, 1, {26}},
    {SNMPOUTSETREQUESTS, ASN_COUNTER, RONLY, var_snmp, 1, {27}},
    {SNMPOUTGETRESPONSES, ASN_COUNTER, RONLY, var_snmp, 1, {28}},
    {SNMPOUTTRAPS, ASN_COUNTER, RONLY, var_snmp, 1, {29}},
    {SNMPENABLEAUTHENTRAPS, ASN_INTEGER, RWRITE, var_snmp, 1, {30}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
oid snmp_variables_oid[] = { 1,3,6,1,2,1,11 };

void
init_snmp_mib(void) {
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/snmp", snmp_variables, variable2, snmp_variables_oid);
}

#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

/*
  header_snmp(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/

static int
header_snmp(struct variable *vp,
	    oid *name,
	    int *length,
	    int exact,
	    int *var_len,
	    int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
{
#define SNMP_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGMSGTL(("mibII/snmp_mib", "var_snmp: %s %d\n", c_oid, exact));
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[SNMP_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
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
	 int *length,
	 int exact,
	 int *var_len,
	 int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
{
    if (header_snmp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /* default value: */
    long_return = 0;

    switch (vp->magic){
	case SNMPINPKTS:
	    long_return = snmp_inpkts;
      	    break;
	case SNMPOUTPKTS:
	    long_return = snmp_outpkts;
      	    break;
	case SNMPINBADVERSIONS:
	    long_return = snmp_inbadversions;
      	    break;
	case SNMPINBADCOMMUNITYNAMES:
	    long_return = snmp_inbadcommunitynames;
      	    break;
	case SNMPINBADCOMMUNITYUSES:
      	    break;
	case SNMPINASNPARSEERRORS:
	    long_return = snmp_inasnparseerrors;
      	    break;
	case SNMPINTOOBIGS:
	    long_return = snmp_intoobigs;
      	    break;
	case SNMPINNOSUCHNAMES:
      	    break;
	case SNMPINBADVALUES:
	    long_return = snmp_inbadvalues;
      	    break;
	case SNMPINREADONLYS:
	    long_return = snmp_inreadonlys;
      	    break;
	case SNMPINGENERRS:
	    long_return = snmp_ingenerrs;
      	    break;
	case SNMPINTOTALREQVARS:
	    long_return = snmp_intotalreqvars;
      	    break;
	case SNMPINTOTALSETVARS:
	    long_return = snmp_intotalsetvars;
      	    break;
	case SNMPINGETREQUESTS:
	    long_return = snmp_ingetrequests;
      	    break;
	case SNMPINGETNEXTS:
	    long_return = snmp_ingetnexts;
      	    break;
	case SNMPINSETREQUESTS:
	    long_return = snmp_insetrequests;
      	    break;
	case SNMPINGETRESPONSES:
	    long_return = snmp_ingetresponses;
      	    break;
	case SNMPINTRAPS:
	    long_return = snmp_intraps;
      	    break;
	case SNMPOUTTOOBIGS:
	    long_return = snmp_outtoobigs;
      	    break;
	case SNMPOUTNOSUCHNAMES:
	    long_return = snmp_outnosuchnames;
      	    break;
	case SNMPOUTBADVALUES:
	    long_return = snmp_outbadvalues;
      	    break;
	case SNMPOUTGENERRS:
	    long_return = snmp_outgenerrs;
      	    break;
	case SNMPOUTGETREQUESTS:
	    long_return = snmp_outgetrequests;
      	    break;
	case SNMPOUTGETNEXTS:
	    long_return = snmp_outgetnexts;
      	    break;
	case SNMPOUTSETREQUESTS:
	    long_return = snmp_outsetrequests;
      	    break;
	case SNMPOUTGETRESPONSES:
	    long_return = snmp_outgetresponses;
      	    break;
	case SNMPOUTTRAPS:
	    long_return = snmp_outtraps;
      	    break;
	case SNMPENABLEAUTHENTRAPS:
	    *write_method = write_snmp;
	    long_return = snmp_enableauthentraps;
      	    break;
	default:
	    ERROR_MSG("unknown snmp var");
	    return NULL;
    }

    return (u_char *) &long_return;
}




/*
 * only for snmpEnableAuthenTraps:
 */

int
write_snmp (int action,
	    u_char *var_val,
	    u_char var_val_type,
	    int var_val_len,
	    u_char *statP,
	    oid *name,
	    int name_len)
{
    int bigsize = 4;
    long intval;

    if (var_val_type != ASN_INTEGER){
	ERROR_MSG("not integer");
	return SNMP_ERR_WRONGTYPE;
    }

    asn_parse_int(var_val, &bigsize, &var_val_type, &intval, sizeof (intval));
    if (intval != 1 && intval != 2) {
        DEBUGMSGTL(("mibII/snmp_mib", "not valid %x\n", intval));
	return SNMP_ERR_WRONGVALUE;
    }

    if (action == COMMIT) {
	snmp_enableauthentraps = intval;	
	/* save_into_conffile ("authentraps:", intval == 1 ? "yes" : "no"); */
    }
    return SNMP_ERR_NOERROR;
}

/*********************
 *
 *  Internal implementation functions
 *
 *********************/
