#include<config.h>

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
#ifdef USING_SYSORTABLE_MODULE
#include "sysORTable.h"
#endif

void
init_mibII __P((void)) {
#ifdef USING_SYSORTABLE_MODULE
  static oid reg[] = {1,3,6,1,6,3,1};
  register_sysORTable(reg,7,"The Mib module for SNMPv2 entities.");
#endif
}
