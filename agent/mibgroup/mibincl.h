/*
 * mibincl.h
 */

#include <stdio.h>
#include <sys/types.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
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

#include "mib_module_config.h"

#include <net-snmp/asn1.h>
#include <net-snmp/snmp_api.h>
#include <net-snmp/snmp_impl.h>
#include <net-snmp/snmp_client.h>

#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/agent/agent_read_config.h>
#include <net-snmp/agent/agent_handler.h>
#include <net-snmp/agent/agent_registry.h>
#include <net-snmp/agent/var_struct.h>

#include <net-snmp/snmp.h>
#include <net-snmp/mib.h>
#include <net-snmp/snmp_debug.h>
#include <net-snmp/snmp_logging.h>
#include <net-snmp/snmp_alarm.h>
#include <net-snmp/read_config.h>
#include <net-snmp/tools.h>
#include <net-snmp/agent/agent_trap.h>
#include <net-snmp/callback.h>
#define u_char unsigned char
#define u_short unsigned short


