/*
 * mibincl.h
 */

#include <stdio.h>
#include <sys/types.h>

#ifdef HAVE_NETINET_IN_H
#	include <netinet/in.h>
#endif

#include "../../snmplib/asn1.h"
#include "../../snmplib/snmp_api.h"
#include "../../snmplib/snmp_impl.h"
#include "../snmp_vars.h"
#include "../var_struct.h"
#include "../../snmplib/snmp.h"
#include "../../snmplib/mib.h"
#include "util_funcs.h"


#define u_char unsigned char
#define u_short unsigned short

