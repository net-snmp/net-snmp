#ifndef NET_SNMP_UTILITIES_H
#define NET_SNMP_UTILITIES_H

    /**
     *  Library API routines not specifically concerned with SNMP directly,
     *    but used more generally within the library, agent and other applications.
     *
     *  This also includes "standard" system routines, which are missing on
     *    particular O/S distributiones.
     */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>

    /*
     *  For the initial release, this will just refer to the
     *  relevant UCD header files.
     *    In due course, the routines relevant to this area of the
     *  API will be identified, and listed here directly.
     *
     *  But for the time being, this header file is a placeholder,
     *  to allow application writers to adopt the new header file names.
     */

#include <net-snmp/snmp_api.h>
#include <net-snmp/snmp_client.h>
#include <net-snmp/getopt.h>

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>			/* for in_addr_t */
#endif
#include <net-snmp/system.h>
#include <net-snmp/tools.h>
#include <net-snmp/asn1.h>		/* for counter64 */
#include <net-snmp/int64.h>

#include <net-snmp/mt_support.h>
#include <net-snmp/snmp_locking.h>
#include <net-snmp/snmp_alarm.h>
#include <net-snmp/data_list.h>
#include <net-snmp/snmp.h>
#include <net-snmp/snmp_impl.h>
#include <net-snmp/snmp-tc.h>

#include <net-snmp/version.h>

#endif /* NET_SNMP_UTILITIES_H */
