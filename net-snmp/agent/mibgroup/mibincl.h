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

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"

#include "snmp_vars.h"
#include "agent_read_config.h"
#include "var_struct.h"

#include "snmp.h"
#include "mib.h"
#include "snmp_debug.h"
#include "snmp_logging.h"
#include "read_config.h"
#include "tools.h"
#include "agent_trap.h"
#include "callback.h"
#define u_char unsigned char
#define u_short unsigned short


