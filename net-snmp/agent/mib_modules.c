/*
 * wrapper to call all the mib module initialization functions 
 */

#include <net-snmp/agent/mib_module_config.h>
#include <net-snmp/net-snmp-config.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "m2m.h"

#include "mibgroup/struct.h"
#include <net-snmp/agent/mib_modules.h>
#include <net-snmp/agent/table.h>
#include <net-snmp/agent/table_iterator.h>
#include "mib_module_includes.h"
#ifdef USING_AGENTX_SUBAGENT_MODULE
#include "mibgroup/agentx/subagent.h"
#endif


void
init_mib_modules(void)
{
#ifdef USING_IF_MIB_DATA_ACCESS_INTERFACE_MODULE
    netsnmp_access_interface_init();
#endif
#  include "mib_module_inits.h"
}
