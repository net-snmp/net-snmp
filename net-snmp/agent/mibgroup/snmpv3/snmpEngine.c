
/* snmpEngine.c: implement's the SNMP-FRAMEWORK-MIB. */

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
#include "snmpv3.h"
#include "util_funcs.h"
#include "../mibII/sysORTable.h"
#include "snmpEngine.h"


void init_snmpEngine __P((void)) {
/* place any initialization routines needed here */
#ifdef USING_MIBII_SYSORTABLE_MODULE
  static oid reg[] = {1,3,6,1,6,3,10,3,1,1};
  register_sysORTable(reg,10,"The SNMP Management Architecture MIB.");
#endif
}

extern struct timeval starttime;

unsigned char *
var_snmpEngine(vp, name, length, exact, var_len, write_method)
    struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, unsigned char *,unsigned char, int, unsigned char *,oid*, int));
{

  /* variables we may use later */
  static long long_ret;
  static unsigned char engineID[1500];
  static oid objid[30];
  static struct counter64 c64;
  struct timeval now;

  *write_method = 0;           /* assume it isnt writable for the time being */
  *var_len = sizeof(long_ret); /* assume an integer and change later if not */

  if (header_generic(vp,name,length,exact,var_len,write_method))
      return 0;

  /* this is where we do the value assignments for the mib results. */
  switch(vp->magic) {

    case SNMPENGINEID:
      *var_len = snmpv3_get_engineID(engineID);
      return (unsigned char *) engineID;

    case SNMPENGINEBOOTS:
      long_ret = snmpv3_get_engine_boots();
      return (unsigned char *) &long_ret;

    case SNMPENGINETIME:
      long_ret = snmpv3_get_engineTime();
      return (unsigned char *) &long_ret;

    case SNMPENGINEMAXMESSAGESIZE:
      long_ret = 1500;
      return (unsigned char *) &long_ret;

    default:
      ERROR_MSG("");
  }
  return 0;
}

