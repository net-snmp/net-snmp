
/* usmStats.c: implements the usmStats portion of the SNMP-USER-BASED-SM-MIB */

#include <config.h>

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

#include "mibincl.h"
#include "../mibII/sysORTable.h"
#include "usmStats.h"



void init_usmStats __P((void)) {
#ifdef USING_MIBII_SYSORTABLE_MODULE
  static oid reg[] = {1,3,6,1,6,3,12,2,1,1};
  register_sysORTable(reg,10,"The management information definitions for the SNMP User-based Security Model.");
#endif
}

unsigned char *
var_usmStats(vp, name, length, exact, var_len, write_method)
    struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, unsigned char *,unsigned char, int, unsigned char *,oid*, int));
{

  /* variables we may use later */
  static long long_ret;


  *write_method = 0;           /* assume it isnt writable for the time being */
  *var_len = sizeof(long_ret); /* assume an integer and change later if not */

  if (header_generic(vp,name,length,exact,var_len,write_method))
      return 0;

  /* this is where we do the value assignments for the mib results. */
  if ( (vp->magic >= 0)
	&& (vp->magic <= (STAT_USM_STATS_END - STAT_USM_STATS_START)) )
  {
    long_ret = snmp_get_statistic(vp->magic + STAT_USM_STATS_START);
    return (unsigned char *) &long_ret;
  }
  return 0;
}

