#ifndef NET_SNMP_SNMPV3_H
#define NET_SNMP_SNMPV3_H

    /**
     *  Library API routines concerned with SNMPv3 handling.
     *
     *  Most of these would typically not be used directly,
     *     but be invoked via version-independent API routines.
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

#include <net-snmp/callback.h>
#include <net-snmp/snmpv3.h>
#include <net-snmp/transform_oids.h>
#include <net-snmp/keytools.h>
#include <net-snmp/scapi.h>
#include <net-snmp/lcd_time.h>
#include <net-snmp/md5.h>

#include <net-snmp/snmp_secmod.h>
#include <net-snmp/snmpksm.h>
#include <net-snmp/snmpusm.h>

#endif /* NET_SNMP_SNMPV3_H */
