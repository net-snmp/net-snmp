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

#include "snmp_mib.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

extern int snmp_enableauthentraps;

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
  static long long_ret;

  *write_method = 0;         /* assume it isnt writable for the time being */
  *var_len = sizeof(long_ret); /* assume an integer and change later if not */

  if (header_generic(vp, name, length, exact, var_len, write_method)
      == MATCH_FAILED)
    return NULL;

    /* this is where we do the value assignments for the mib results. */
  if ( (vp->magic >= 1)
       && (vp->magic <= (STAT_SNMP_STATS_END - STAT_SNMP_STATS_START + 1)) ) {
    long_ret = snmp_get_statistic(vp->magic + STAT_SNMP_STATS_START);
    return (unsigned char *) &long_ret;
  } else if (vp->magic == SNMPENABLEAUTHENTRAPS) {
    *write_method = write_snmp;
    long_return = snmp_enableauthentraps;
    return (u_char *) &long_return;
  }
  return NULL;
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

    if (var_val_type != ASN_INTEGER){
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
