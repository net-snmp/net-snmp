#include <stdio.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/time.h>

/* uncomment if you don't have in_addr_t in netinet/in.h */
/* typedef u_int in_addr_t; */

#include <net-snmp/snmplib/asn1.h>
#include <net-snmp/snmplib/snmp_api.h>
#include <net-snmp/snmplib/snmp_impl.h>
#include <net-snmp/snmplib/snmp_client.h>
#include <net-snmp/snmplib/mib.h>
#include <net-snmp/snmplib/snmp.h>
#include <net-snmp/snmplib/snmp-tc.h>

#include <net-snmp/snmplib/default_store.h>
#include <net-snmp/snmplib/snmp_logging.h>
#include <net-snmp/snmplib/snmp_debug.h>
#include <net-snmp/snmplib/read_config.h>
#include <net-snmp/snmplib/tools.h>
#include <net-snmp/snmplib/system.h>
