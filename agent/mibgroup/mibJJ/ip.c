/*
 *  IP MIB group implementation - ip.c
 *
 */

#include <config.h>
#include "mibincl.h"
#include "util_funcs.h"

#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/socket.h>

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_SYS_SYSCTL_H
#ifdef _I_DEFINED_KERNEL
#undef _KERNEL
#endif
#include <sys/sysctl.h>
#ifdef _I_DEFINED_KERNEL
#define _KERNEL 1
#endif
#endif
#if HAVE_SYS_SYSMP_H
#include <sys/sysmp.h>
#endif
#if HAVE_SYS_TCPIPSTATS_H
#include <sys/tcpipstats.h>
#endif
#include <net/if.h>
#if HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
#ifdef _I_DEFINED_KERNEL
#undef _KERNEL
#endif
#if HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#if HAVE_SYS_HASHING_H
#include <sys/hashing.h>
#endif
#if HAVE_NETINET_IN_VAR_H
#include <netinet/in_var.h>
#endif
#include <netinet/ip.h>
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#include <net/route.h>
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif


#ifdef solaris2
#include "kernel_sunos5.h"
#else
#include "kernel.h"
#endif
#ifdef linux
#include "kernel_linux.h"
#endif
#ifdef hpux
#include <sys/mib.h>
#include "kernel_hpux.h"
#endif

#include "system.h"
#include "auto_nlist.h"

#include "ip.h"
#include "interfaces.h"
#include "sysORTable.h"

#ifndef IP_STATS_CACHE_TIMEOUT
#define IP_STATS_CACHE_TIMEOUT	MIB_STATS_CACHE_TIMEOUT
#endif
marker_t ip_stats_cache_marker = NULL;

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#if defined(linux) || defined(hpux)
#define IP_STAT_STRUCTURE	struct ip_mib
#define	USES_SNMP_DESIGNED_IPSTAT
#undef  IPSTAT_SYMBOL
#endif

#ifdef solaris2
#define IP_STAT_STRUCTURE	mib2_ip_t
#define	USES_SNMP_DESIGNED_IPSTAT
#endif

#if !defined(IP_STAT_STRUCTURE)
struct snmp_ipstat {
    int			forwarding;
    int			ttl;
    struct ipstat	stats;
};
#define IP_STAT_STRUCTURE	struct snmp_ipstat
#define	USES_TRADITIONAL_IPSTAT
#endif

long      read_ip_stat (IP_STAT_STRUCTURE *, int);
long arch_read_ip_stat (IP_STAT_STRUCTURE *, int);

	/*********************
	 *
	 *  Initialisation
	 *
	 *********************/



/* define the structure we're going to ask the agent to register our
   information at */
struct variable2 ip_variables[] = {
    {IPFORWARDING,    ASN_INTEGER, RONLY, var_ip, 1, {1 }},
    {IPDEFAULTTTL,    ASN_INTEGER, RONLY, var_ip, 1, {2 }},
#ifndef sunV3
    {IPINRECEIVES,    ASN_COUNTER, RONLY, var_ip, 1, {3 }},
#endif
    {IPINHDRERRORS,   ASN_COUNTER, RONLY, var_ip, 1, {4 }},
#ifndef sunV3
    {IPINADDRERRORS,  ASN_COUNTER, RONLY, var_ip, 1, {5 }},
    {IPFORWDATAGRAMS, ASN_COUNTER, RONLY, var_ip, 1, {6 }},
#endif
    {IPINUNKNOWNPROTOS, ASN_COUNTER, RONLY, var_ip, 1, {7 }},
#ifndef sunV3
    {IPINDISCARDS,    ASN_COUNTER, RONLY, var_ip, 1, {8 }},
    {IPINDELIVERS,    ASN_COUNTER, RONLY, var_ip, 1, {9 }},
#endif
    {IPOUTREQUESTS,   ASN_COUNTER, RONLY, var_ip, 1, {10 }},
    {IPOUTDISCARDS,   ASN_COUNTER, RONLY, var_ip, 1, {11 }},
    {IPOUTNOROUTES,   ASN_COUNTER, RONLY, var_ip, 1, {12 }},
    {IPREASMTIMEOUT,  ASN_INTEGER, RONLY, var_ip, 1, {13 }},
#ifndef sunV3
    {IPREASMREQDS,    ASN_COUNTER, RONLY, var_ip, 1, {14 }},
    {IPREASMOKS,      ASN_COUNTER, RONLY, var_ip, 1, {15 }},
    {IPREASMFAILS,    ASN_COUNTER, RONLY, var_ip, 1, {16 }},
#endif
    {IPFRAGOKS,       ASN_COUNTER, RONLY, var_ip, 1, {17 }},
    {IPFRAGFAILS,     ASN_COUNTER, RONLY, var_ip, 1, {18 }},
    {IPFRAGCREATES,   ASN_COUNTER, RONLY, var_ip, 1, {19 }},
		/*
		 * The tables handled by
		 *	 ipAddr.c
		 *	 ipRoute.c
		 *	 ipMedia.c
		 * will be inserted here
		 */
    {IPROUTEDISCARDS, ASN_COUNTER, RONLY, var_ip, 1, {23 }}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath, and the OID of the MIB module */
oid ip_variables_oid[] = { SNMP_OID_MIB2,4 };
oid ip_module_oid[]    = { SNMP_OID_MIB2,4 };

void init_ip(void)
{
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/ip", ip_variables, variable2, ip_variables_oid);
      REGISTER_SYSOR_ENTRY( ip_module_oid,
		"The MIB module for managing IP and ICMP implementations");


  /* for speed optimization, we call this now to do the lookup */
#ifdef IPSTAT_SYMBOL
  auto_nlist(IPSTAT_SYMBOL,0,0);
#endif
#ifdef IP_FORWARDING_SYMBOL
  auto_nlist(IP_FORWARDING_SYMBOL,0,0);
#endif
#ifdef TCP_TTL_SYMBOL
  auto_nlist(TCP_TTL_SYMBOL,0,0);
#endif
#ifdef MIB_IPCOUNTER_SYMBOL
  auto_nlist(MIB_IPCOUNTER_SYMBOL,0,0);
#endif
}


	/*********************
	 *
	 *  Main variable handling routine
	 *
	 *********************/


u_char *
var_ip(struct variable *vp,
       oid *name,
       size_t *length,
       int exact,
       size_t *var_len,
       WriteMethod **write_method)
{
    static IP_STAT_STRUCTURE ipstat;
    static long ret_value;

    if (header_generic(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    ret_value = read_ip_stat (&ipstat, vp->magic);
    if ( ret_value < 0 )
	return NULL;

    switch (vp->magic){
#ifdef USES_SNMP_DESIGNED_IPSTAT
	case IPFORWARDING:	return (u_char *) &ipstat.ipForwarding;
	case IPDEFAULTTTL:	return (u_char *) &ipstat.ipDefaultTTL;
	case IPINRECEIVES:	return (u_char *) &ipstat.ipInReceives;
	case IPINHDRERRORS:	return (u_char *) &ipstat.ipInHdrErrors;
	case IPINADDRERRORS:	return (u_char *) &ipstat.ipInAddrErrors;
	case IPFORWDATAGRAMS:	return (u_char *) &ipstat.ipForwDatagrams;
	case IPINUNKNOWNPROTOS:	return (u_char *) &ipstat.ipInUnknownProtos;
	case IPINDISCARDS:	return (u_char *) &ipstat.ipInDiscards;
	case IPINDELIVERS:	return (u_char *) &ipstat.ipInDelivers;
	case IPOUTREQUESTS:	return (u_char *) &ipstat.ipOutRequests;
	case IPOUTDISCARDS:	return (u_char *) &ipstat.ipOutDiscards;
	case IPOUTNOROUTES:	return (u_char *) &ipstat.ipOutNoRoutes;
	case IPREASMTIMEOUT:	return (u_char *) &ipstat.ipReasmTimeout;
	case IPREASMREQDS:	return (u_char *) &ipstat.ipReasmReqds;
	case IPREASMOKS:	return (u_char *) &ipstat.ipReasmOKs;
	case IPREASMFAILS:	return (u_char *) &ipstat.ipReasmFails;
	case IPFRAGOKS:		return (u_char *) &ipstat.ipFragOKs;
	case IPFRAGFAILS:	return (u_char *) &ipstat.ipFragFails;
	case IPFRAGCREATES:	return (u_char *) &ipstat.ipFragCreates;
	case IPROUTEDISCARDS:	return (u_char *) &ipstat.ipRoutingDiscards;
#endif



#ifdef USES_TRADITIONAL_IPSTAT
	case IPFORWARDING:	long_return = ipstat.forwarding;
			        return (u_char *) &long_return;
	case IPDEFAULTTTL:	long_return = ipstat.ttl;
			        return (u_char *) &long_return;
	case IPINRECEIVES:	long_return = ipstat.stats.ips_total;
			        return (u_char *) &long_return;
	case IPINHDRERRORS:	long_return = ipstat.stats.ips_badsum
					 + ipstat.stats.ips_tooshort
					 + ipstat.stats.ips_toosmall
					 + ipstat.stats.ips_badhlen
					 + ipstat.stats.ips_badlen;
				return (u_char *) &long_return;
	case IPINADDRERRORS:	long_return = ipstat.stats.ips_cantforward;
			        return (u_char *) &long_return;
	case IPFORWDATAGRAMS:	long_return = ipstat.stats.ips_forward;
			        return (u_char *) &long_return;
	case IPINUNKNOWNPROTOS:
#if STRUCT_IPSTAT_HAS_IPS_NOPROTO
				long_return = ipstat.stats.ips_noproto;
				return (u_char *) &long_return;
#else
				return NULL;
#endif
	case IPINDISCARDS:
#if STRUCT_IPSTAT_HAS_IPS_FRAGDROPPED
				long_return = ipstat.stats.ips_fragdropped;	/* ?? */
				return (u_char *) &long_return;
#else
				return NULL;
#endif
	case IPINDELIVERS:
#if STRUCT_IPSTAT_HAS_IPS_DELIVERED
				long_return = ipstat.stats.ips_delivered;
			        return (u_char *) &long_return;
#else
				return NULL;
#endif
	case IPOUTREQUESTS:
#if STRUCT_IPSTAT_HAS_IPS_LOCALOUT
				long_return = ipstat.stats.ips_localout;
				return (u_char *) &long_return;
#else
				return NULL;
#endif
	case IPOUTDISCARDS:
#if STRUCT_IPSTAT_HAS_IPS_ODROPPED
				long_return = ipstat.stats.ips_odropped;
				return (u_char *) &long_return;
#else
				return NULL;
#endif
	case IPOUTNOROUTES:
#if STRUCT_IPSTAT_HAS_IPS_CANTFORWARD
				long_return = ipstat.stats.ips_cantforward;
			        return (u_char *) &long_return;
#else
#if STRUCT_IPSTAT_HAS_IPS_NOROUTE
				long_return = ipstat.stats.ips_noroute;
			        return (u_char *) &long_return;
#else
				return NULL;
#endif
#endif
	case IPREASMTIMEOUT:
#if STRUCT_IPSTAT_HAS_IPS_FRAGTIMEOUT
				long_return = ipstat.stats.ips_fragtimeout;
#else
				long_return = IPFRAGTTL;
#endif
			        return (u_char *) &long_return;
	case IPREASMREQDS:	long_return = ipstat.stats.ips_fragments;
			        return (u_char *) &long_return;
	case IPREASMOKS:
#if STRUCT_IPSTAT_HAS_IPS_REASSEMBLED
				long_return = ipstat.stats.ips_reassembled;
				return (u_char *) &long_return;
#else
				return NULL;
#endif
	case IPREASMFAILS:	long_return = ipstat.stats.ips_fragdropped
					 + ipstat.stats.ips_fragtimeout;
				return (u_char *) &long_return;
	case IPFRAGOKS:			/* XXX */
				long_return = ipstat.stats.ips_fragments
				      - (ipstat.stats.ips_fragdropped + ipstat.stats.ips_fragtimeout);
				return (u_char *) &long_return;
	case IPFRAGFAILS:
#if STRUCT_IPSTAT_HAS_IPS_CANTFRAG
				long_return = ipstat.stats.ips_cantfrag;
				return (u_char *) &long_return;
#else
				return NULL;
#endif
	case IPFRAGCREATES:
#if STRUCT_IPSTAT_HAS_IPS_OFRAGMENTS
				long_return = ipstat.stats.ips_ofragments;
				return (u_char *) &long_return;
#else
				return NULL;
#endif
	case IPROUTEDISCARDS:
#if STRUCT_IPSTAT_HAS_IPS_NOROUTE
				long_return = ipstat.stats.ips_noroute;
				return (u_char *) &long_return;
#else
				return NULL;
#endif

#endif		/* USE_TRADITIONAL_IPSTAT */

	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ip\n", vp->magic));
    }
    return NULL;

}



	/*********************
	 *
	 *  System-independent internal implementation function
	 *
	 *********************/


long
read_ip_stat( IP_STAT_STRUCTURE *ipstat, int magic )
{
    long ret_value;
    int i;

    if (  ip_stats_cache_marker &&
	(!atime_ready( ip_stats_cache_marker, IP_STATS_CACHE_TIMEOUT*1000 )))
	return 0;

    if (ip_stats_cache_marker )
	atime_setMarker( ip_stats_cache_marker );
    else
	ip_stats_cache_marker = atime_newMarker();

    ret_value = arch_read_ip_stat( ipstat, magic );

    if ( ret_value == -1 ) {
	free( ip_stats_cache_marker );
	ip_stats_cache_marker = NULL;
    }
    return ret_value;

}


	/*********************
	 *
	 *  System-specific functions to read
	 *   in the list of interfaces
	 *
	 *********************/

#ifdef  hpux
#define READ_IP_STAT
long arch_read_ip_stat( IP_STAT_STRUCTURE *ipstat, int magic )
{
    return hpux_read_stat((char*)ipstat, sizeof(*ipstat), ID_ip);
}
#endif

#ifdef  linux
#define READ_IP_STAT
long arch_read_ip_stat( IP_STAT_STRUCTURE *ipstat, int magic )
{
    return linux_read_ip_stat(ipstat);
}
#endif

#ifdef  solaris2
#define READ_IP_STAT
long arch_read_ip_stat( IP_STAT_STRUCTURE *ipstat, int magic )
{
    return getMibstat(MIB_IP, ipstat, sizeof(mib2_ip_t), GET_FIRST, &Get_everything, NULL);
}
#endif

#ifdef  HAVE_SYS_TCPIPSTATS_H
#define READ_IP_STAT
long arch_read_ip_stat( IP_STAT_STRUCTURE *ipstat, int magic )
{
    int name[] = { CTL_NET, PF_INET, IPPROTO_IP, IPCTL_FORWARDING };
    size_t = len;
    struct kna full_stats;
    int result;

    len = sizeof( result );
    if ( sysctl (name, sizeof(name)/sizeof(int), &result, &len, 0,0) == -1 )
	return -1;
    else
	ipstat->forwarding = (result ? 1	/* GATEWAY */
				     : 2	/* HOST    */ );

    if (!auto_nlist(TCP_TTL_SYMBOL,(char *) &result, sizeof( result )))
	return -1;
    else
	ipstat->ttl = result;

    result = sysmp (MP_SAGET, MPSA_TCPIPSTATS, &full_stats, sizeof(full_stats));
    if ( result != -1 )
	memcpy(&(ipstat->stats), &full_stats.ipstats, sizeof( full_stats.tcpstats ));
    return result;
}
#endif

#if defined(CAN_USE_SYSCTL) && defined(IPCTL_STATS)
#define READ_IP_STAT
long arch_read_ip_stat( IP_STAT_STRUCTURE *ipstat, int magic )
{
    int name[] = { CTL_NET, PF_INET, IPPROTO_IP, 0 };
    size_t len;
    int result;

    len = sizeof( result );
    name[3] = IPCTL_FORWARDING;
    if ( sysctl (name, sizeof(name)/sizeof(int), &result, &len, 0,0) == -1 )
	return -1;
    else
	ipstat->forwarding = (result ? 1	/* GATEWAY */
				     : 2	/* HOST    */ );

    len = sizeof( result );
    name[3] = IPCTL_DEFTTL;
    if ( sysctl (name, sizeof(name)/sizeof(int), &result, &len, 0,0) == -1 )
	return -1;
    else
	ipstat->ttl = result;

    len = sizeof( ipstat->stats );
    name[3] = IPCTL_STATS;
    return sysctl (name, sizeof(name)/sizeof(int), &(ipstat->stats), &len, 0,0);
}
#endif


			/* Catch-all */
#ifndef READ_IP_STAT
long arch_read_ip_stat( IP_STAT_STRUCTURE *ipstat, int magic )
{
    int result;

    if (!auto_nlist(IP_FORWARDING_SYMBOL,(char *) &result, sizeof( result )))
	return -1;
    else
	ipstat->forwarding = (result ? 1	/* GATEWAY */
				     : 2	/* HOST    */ );

    if (!auto_nlist(TCP_TTL_SYMBOL,(char *) &result, sizeof( result )))
	return -1;
    else
	ipstat->ttl = result;

    if (!auto_nlist(IPSTAT_SYMBOL,(char *) &(ipstat->stats), sizeof( ipstat->stats )))
	return -1;
    return 0;
}
#endif
