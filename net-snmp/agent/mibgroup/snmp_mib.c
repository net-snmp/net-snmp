/*
 *  SNMPv1 MIB group implementation - snmp.c
 *
 */

#include "../common_header.h"
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


int snmp_enableauthentraps = 2;		/* default: 2 == disabled */
char *snmp_trapsink;
char *snmp_trapcommunity;

static int header_snmp __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

static int
header_snmp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define SNMP_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_snmp: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[SNMP_NAME_LENGTH] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
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
var_snmp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
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
write_snmp (action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
    int bigsize = 4;
    long intval;

    if (var_val_type != INTEGER){
	ERROR_MSG("not integer");
	return SNMP_ERR_WRONGTYPE;
    }

    asn_parse_int(var_val, &bigsize, &var_val_type, &intval, sizeof (intval));
    if (intval != 1 && intval != 2) {
#ifdef DEBUG	    
	printf("not valid %x\n", intval);
#endif
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
