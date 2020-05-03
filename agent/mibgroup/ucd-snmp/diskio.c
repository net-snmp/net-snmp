/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright © 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

#include <net-snmp/net-snmp-config.h>

/*
 * needed by util_funcs.h 
 */
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
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
/*
 * include our .h file 
 */
#include "diskio.h"
#include "diskio_darwin.h"
#include "diskio_netbsd.h"
#include "diskio_aix.h"
#include "diskio_freebsd.h"
#include "diskio_openbsd.h"
#include "diskio_bsdi.h"
#include "diskio_linux.h"
#include "diskio_solaris.h"

static time_t cache_time;

void
init_diskio(void)
{
    /*
     * Define a 'variable' structure that is a representation of our mib. 
     */

    /*
     * first, we have to pick the variable type.  They are all defined in
     * the var_struct.h file in the agent subdirectory.  I'm picking the
     * variable2 structure since the longest sub-component of the oid I
     * want to load is .2.1 and .2.2 so I need at most 2 spaces in the
     * last entry. 
     */

    static const struct variable2 diskio_variables[] = {
        {DISKIO_INDEX, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {1}},
        {DISKIO_DEVICE, ASN_OCTET_STR, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {2}},
        {DISKIO_NREAD, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {3}},
        {DISKIO_NWRITTEN, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {4}},
        {DISKIO_READS, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {5}},
        {DISKIO_WRITES, ASN_COUNTER, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {6}},
#if defined(HAVE_GETDEVS) || defined(HAVE_DEVSTAT_GETDEVS) || defined(linux)
        {DISKIO_LA1, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {9}},
        {DISKIO_LA5, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {10}},
        {DISKIO_LA15, ASN_INTEGER, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {11}},
#endif
        {DISKIO_NREADX, ASN_COUNTER64, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {12}},
        {DISKIO_NWRITTENX, ASN_COUNTER64, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {13}},
        {DISKIO_BUSYTIME, ASN_COUNTER64, NETSNMP_OLDAPI_RONLY,
         var_diskio, 1, {14}},
    };

    /*
     * Define the OID pointer to the top of the mib tree that we're
     * registering underneath. 
     */
    static const oid diskio_variables_oid[] = {
        1, 3, 6, 1, 4, 1, 2021, 13, 15, 1, 1
    };

    /*
     * register ourselves with the agent to handle our mib tree
     * 
     * This is a macro defined in ../../snmp_vars.h.  The arguments are:
     * 
     * descr:   A short description of the mib group being loaded.
     * var:     The variable structure to load.
     * vartype: The variable structure used to define it (variable2, variable4, ...)
     * theoid:  A *initialized* *exact length* oid pointer.
     * (sizeof(theoid) *must* return the number of elements!)  
     */
    REGISTER_MIB("diskio", diskio_variables, variable2,
                 diskio_variables_oid);

#ifdef solaris2
    init_diskio_solaris();
#endif

#ifdef darwin
    init_diskio_darwin();
#endif

#if defined(aix4)
    init_diskio_aix();
#endif

#if defined (HAVE_GETDEVS) || defined(HAVE_DEVSTAT_GETDEVS) || defined(linux)
    devla_getstats(0, NULL);
    /* collect LA data regularly */
    snmp_alarm_register(DISKIO_SAMPLE_INTERVAL, SA_REPEAT, devla_getstats,
                        NULL);
#endif

#if defined(linux)
    init_diskio_linux();
#endif
}

int diskio_cache_valid(time_t now)
{
    return cache_time + 1/*second*/ > now;
}

void diskio_set_cache_time(time_t now)
{
    cache_time = now;
}
