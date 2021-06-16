/*
 *  Template MIB group interface - at.h
 *
 */

#ifndef _MIBGROUP_AT_H
#define _MIBGROUP_AT_H

#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

config_arch_require(solaris2, kernel_sunos5)

     extern void     init_at(void);
     extern FindVarMethod var_atEntry;


#define ATIFINDEX	0
#define ATPHYSADDRESS	1
#define ATNETADDRESS	2

#define IPMEDIAIFINDEX          0
#define IPMEDIAPHYSADDRESS      1
#define IPMEDIANETADDRESS       2
#define IPMEDIATYPE             3

/* InfiniBand uses HW addr > 6 */
#define MAX_MAC_ADDR_LEN 32

#if defined(WIN32) || defined(cygwin)
config_require(mibII/data_access/at_iphlpapi)
#elif defined(solaris2)
config_require(mibII/data_access/at_solaris)
#elif defined(linux)
config_require(mibII/data_access/at_linux)
config_require(mibII/data_access/at_unix)
#elif defined(HAVE_SYS_SYSCTL_H) && (defined(RTF_LLINFO) || defined(RTF_LLDATA))
config_require(mibII/data_access/at_sysctl)
config_require(mibII/data_access/at_unix)
#elif defined(HAVE_NLIST_H)
config_require(mibII/data_access/at_nlist)
config_require(mibII/data_access/at_unix)
#endif

#endif                          /* _MIBGROUP_AT_H */
