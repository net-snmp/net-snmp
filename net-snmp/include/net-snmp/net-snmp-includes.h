#include <stdio.h>
#include <sys/types.h>

#include <netinet/in.h>
#include <sys/time.h>

/* uncomment if you don't have in_addr_t in netinet/in.h */
/* typedef u_int in_addr_t; */

#include <net-snmp/asn1.h>
#include <net-snmp/snmp_api.h>
#include <net-snmp/snmp_impl.h>
#include <net-snmp/snmp_client.h>
#include <net-snmp/mib.h>
#include <net-snmp/snmp.h>
#include <net-snmp/snmp-tc.h>

#include <net-snmp/default_store.h>
#include <net-snmp/snmp_logging.h>
#include <net-snmp/snmp_debug.h>
#include <net-snmp/read_config.h>
#include <net-snmp/tools.h>
#include <net-snmp/system.h>
