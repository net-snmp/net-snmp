
/* snmpMPDStats.c: tallies errors for SNMPv3 message processing. */

#include <config.h>

#include "mibincl.h"
#include "snmpMPDStats.h"

void init_snmpMPDStats(void) {
  int i;
#ifdef USING_MIBII_SYSORTABLE_MODULE
  static oid reg[] = {1,3,6,1,6,3,11,3,1,1};
  register_sysORTable(reg,10,"The MIB for Message Processing and Dispatching.");
#endif
}

unsigned char *
var_snmpMPDStats(vp, name, length, exact, var_len, write_method)
    struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, unsigned char *,unsigned char, int, unsigned char *,oid*, int));
{

  /* variables we may use later */
  static long long_ret;
  static unsigned char string[1500];
  static oid objid[30];
  static struct counter64 c64;

  *write_method = 0;           /* assume it isnt writable for the time being */
  *var_len = sizeof(long_ret); /* assume an integer and change later if not */

  if (header_generic(vp,name,length,exact,var_len,write_method))
      return 0;

  /* this is where we do the value assignments for the mib results. */

  if ( (vp->magic >= 0)
	&& (vp->magic <= (STAT_MPD_STATS_END - STAT_MPD_STATS_START)) )
  {
    long_ret = snmp_get_statistic(vp->magic + STAT_MPD_STATS_START);
    return (unsigned char *) &long_ret;
  }
  return 0;
}

