/*
 *  UDP MIB group implementation - udp.c
 *
 */

#include <config.h>
#include "mibincl.h"
#include "util_funcs.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_SYS_SYSMP_H
#include <sys/sysmp.h>
#endif
#if HAVE_SYS_TCPIPSTATS_H
#include <sys/tcpipstats.h>
#endif
#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#include <net/if.h>
#if HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
#ifdef _I_DEFINED_KERNEL
#undef _KERNEL
#endif

#if HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#if HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#if HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#endif
#if HAVE_SYS_SOCKETVAR_H
#include <sys/socketvar.h>
#endif
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif
#ifdef INET6
#if HAVE_NETINET6_IP6_VAR_H
#include <netinet6/ip6_var.h>
#endif
#endif
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#include <netinet/udp.h>
#if HAVE_NETINET_UDP_VAR_H
#include <netinet/udp_var.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
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
#include "asn1.h"
#include "snmp_debug.h"
#include "tools.h"

#include "auto_nlist.h"

#ifdef linux
#include "tcp.h"
#endif
#include "udp.h"
#include "sysORTable.h"

#ifdef CAN_USE_SYSCTL
#include <sys/sysctl.h>
#endif

#ifndef UDP_STATS_CACHE_TIMEOUT
#define UDP_STATS_CACHE_TIMEOUT	MIB_STATS_CACHE_TIMEOUT
#endif
marker_t udp_stats_cache_marker = NULL;

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#if defined(linux) || defined(hpux)
#define UDP_STAT_STRUCTURE	struct udp_mib
#define UDP_INDGRAM_FIELD	udpInDatagrams
#define UDP_NOPORTS_FIELD	udpNoPorts
#define UDP_INERRS_FIELD	udpInErrors
#define UDP_OUTDGRAM_FIELD	udpOutDatagrams
#undef UDPSTAT_SYMBOL
#endif

#ifdef solaris2
struct snmp_udpstats {
    int		udpNoPorts;
    mib2_udp_t	stats;
};
#define UDP_STAT_STRUCTURE	struct snmp_udpstats
#define UDP_INDGRAM_FIELD	stats.udpInDatagrams
#define UDP_NOPORTS_FIELD	udpNoPorts
#define UDP_INERRS_FIELD	stats.udpInErrors
#define UDP_OUTDGRAM_FIELD	stats.udpOutDatagrams
#endif

#if !defined(UDP_STAT_STRUCTURE)		/* traditional format */
#define UDP_STAT_STRUCTURE	struct udpstat
#if     STRUCT_UDPSTAT_HAS_UDPS_IPACKETS
#define UDP_INDGRAM_FIELD	udps_ipackets
#endif
#if     STRUCT_UDPSTAT_HAS_UDPS_NOPORT
#define UDP_NOPORTS_FIELD	udps_noport
#endif
#if     STRUCT_UDPSTAT_HAS_UDPS_OPACKETS
#define UDP_OUTDGRAM_FIELD	udps_opackets
#endif
#undef  UDP_INERRS_FIELD			/* sum the individual errors */
#endif

long      read_udp_stat (UDP_STAT_STRUCTURE *, int);
long arch_read_udp_stat (UDP_STAT_STRUCTURE *, int);


	/*********************
	 *
	 *  Initialisation
	 *
	 *********************/

struct variable2 udp_variables[] = {
    {UDPINDATAGRAMS,  ASN_COUNTER, RONLY, var_udp, 1, {1}},
    {UDPNOPORTS,      ASN_COUNTER, RONLY, var_udp, 1, {2}},
    {UDPINERRORS,     ASN_COUNTER, RONLY, var_udp, 1, {3}},
    {UDPOUTDATAGRAMS, ASN_COUNTER, RONLY, var_udp, 1, {4}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath, and the OID for the MIB module */
oid udp_variables_oid[] = { SNMP_OID_MIB2,7 };
oid udp_module_oid[]    = { SNMP_OID_MIB2,50 };

void init_udp(void)
{

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/udp", udp_variables, variable2, udp_variables_oid);
  REGISTER_SYSOR_ENTRY( udp_module_oid,
		"The MIB module for managing UDP implementations");

#ifdef UDPSTAT_SYMBOL
  auto_nlist( UDPSTAT_SYMBOL,0,0 );
#endif
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

u_char *
var_udp(struct variable *vp,
	oid *name,
	size_t *length,
	int exact,
	size_t *var_len,
	WriteMethod **write_method)
{
    static UDP_STAT_STRUCTURE udpstat;
    static long ret_value;

    if (header_generic(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    ret_value = read_udp_stat (&udpstat, vp->magic);
    if ( ret_value < 0 )
	return NULL;


    switch (vp->magic) {
	case UDPINDATAGRAMS:
#ifdef UDP_INDGRAM_FIELD
				return (u_char *) &udpstat.UDP_INDGRAM_FIELD;
#else
				return NULL;
#endif
	case UDPNOPORTS:
#ifdef UDP_NOPORTS_FIELD
				return (u_char *) &udpstat.UDP_NOPORTS_FIELD;
#else
				return NULL;
#endif
	case UDPOUTDATAGRAMS:
#ifdef UDP_OUTDGRAM_FIELD
				return (u_char *) &udpstat.UDP_OUTDGRAM_FIELD;
#else
				return NULL;
#endif
	case UDPINERRORS:
#ifdef UDP_INERRS_FIELD
				return (u_char *) &udpstat.UDP_INERRS_FIELD;
#else
				long_return = udpstat.udps_hdrops +
					      udpstat.udps_badsum +
#ifdef STRUCT_UDPSTAT_HAS_UDPS_DISCARD
                   			      udpstat.udps_discard +
#endif
					      udpstat.udps_badlen;
				return (u_char *) &long_return;
#endif

	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_udp\n", vp->magic));
    }
    return NULL;

}


	/*********************
	 *
	 *  System-independent internal implementation functions
	 *
	 *********************/


long
read_udp_stat( UDP_STAT_STRUCTURE *udpstat, int magic )
{
   long ret_value = -1;
   int i;

    if (  udp_stats_cache_marker &&
	(!atime_ready(udp_stats_cache_marker, UDP_STATS_CACHE_TIMEOUT*1000)))
	return 0;

    if (udp_stats_cache_marker )
	atime_setMarker( udp_stats_cache_marker );
    else
	udp_stats_cache_marker = atime_newMarker();

    ret_value = arch_read_udp_stat(udpstat, magic);

    if ( ret_value == -1 ) {
	free( udp_stats_cache_marker );
	udp_stats_cache_marker = NULL;
    }
    return ret_value;
}

	/*********************
	 *
	 *  System-specific implementation functions
	 *   to read in the statistics
	 *
	 *********************/

#ifdef  hpux
#define READ_UDP_STAT
long arch_read_udp_stat( UDP_STAT_STRUCTURE *udpstat, int magic )
{
    return hpux_read_stat((char*)udpstat, sizeof(*udpstat), ID_udp);
}
#endif

#ifdef  linux
#define READ_UDP_STAT
long arch_read_udp_stat(  UDP_STAT_STRUCTURE *udpstat, int magic )
{
    return linux_read_udp_stat(udpstat);
}
#endif

#ifdef  solaris2
#define READ_UDP_STAT
long arch_read_udp_stat(  UDP_STAT_STRUCTURE *udpstat, int magic )
{
    mib2_ip_t ipstat;

    if (getMibstat(MIB_IP, ppstat, sizeof(mib2_pp_t), GET_FIRST, &Get_everything, NULL) < 0 )
	return -1;

    if (getMibstat(MIB_UDP, &(udpstat->stats), sizeof(mib2_udp_t), GET_FIRST, &Get_everything, NULL) < 0 )
	return -1;

    udpstat->udpNoPorts = ipstat.udpNoPorts;
    return 0;
}
#endif

#ifdef  HAVE_SYS_TCPIPSTATS_H
#define READ_UDP_STAT
long arch_read_udp_stat(  UDP_STAT_STRUCTURE *udpstat, int magic )
{
    struct kna full_stats;
    int res;

    res = sysmp (MP_SAGET, MPSA_TCPIPSTATS, &full_stats, sizeof(struct kna));
    if ( res != -1 )
	memcpy( udpstat, &(full_stats.udpstats), sizeof( UDP_STAT_STRUCTURE ));
    return res;
}
#endif

#if defined(CAN_USE_SYSCTL) && defined(UDPCTL_STATS)
#define READ_UDP_STAT
long arch_read_udp_stat(  UDP_STAT_STRUCTURE *udpstat, int magic )
{
    int sname[4] = { CTL_NET, PF_INET, IPPROTO_UDP, UDPCTL_STATS };
    size_t len = sizeof( *udpstat );

    return sysctl(sname, 4, udpstat, &len, 0, 0);
}
#endif

			/* Catch-all */
#ifndef READ_UDP_STAT
long arch_read_udp_stat(  UDP_STAT_STRUCTURE *udpstat, int magic )
{
    if (auto_nlist(UDPSTAT_SYMBOL, (char *)udpstat, sizeof (*udpstat)))
	return 0;
    else
	return -1;
}
#endif
