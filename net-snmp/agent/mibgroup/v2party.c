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
init_v2party __P((void)) {
#ifdef USING_SYSORTABLE_MODULE
  static oid reg[] = {1,3,6,1,6,3,2};
  register_sysORTable(reg,7,"The Manager-to-Manager MIB module.");
#endif
}
