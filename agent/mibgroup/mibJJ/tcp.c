
/*
 *  TCP MIB group implementation - tcp.c
 *
 */

#include <config.h>
#include "mibincl.h"
#include "util_funcs.h"

#include <unistd.h>

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_PROTOSW_H
#include <sys/protosw.h>
#endif

#if HAVE_SYS_SYSMP_H
#include <sys/sysmp.h>
#endif
#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
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
#ifdef INET6
#include <netinet/ip6.h>
#endif
#if HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#endif
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif
#ifdef INET6
#if HAVE_NETINET6_IP6_VAR_H
#include <netinet6/ip6_var.h>
#endif
#endif
#if HAVE_SYS_SOCKETVAR_H
#include <sys/socketvar.h>
#endif
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
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
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if defined(osf4) || defined(aix4) || defined(hpux10)
/* these are undefed to remove a stupid warning on osf compilers
   because they get redefined with a slightly different notation of the
   same value.  -- Wes */
#undef TCP_NODELAY
#undef TCP_MAXSEG
#endif
#include <netinet/tcp.h>
#if HAVE_NETINET_TCPIP_H
#include <netinet/tcpip.h>
#endif
#if HAVE_NETINET_TCP_TIMER_H
#include <netinet/tcp_timer.h>
#endif
#if HAVE_NETINET_TCP_VAR_H
#include <netinet/tcp_var.h>
#endif
#if HAVE_NETINET_TCP_FSM_H
#include <netinet/tcp_fsm.h>
#endif
#if HAVE_SYS_TCPIPSTATS_H
#include <sys/tcpipstats.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "auto_nlist.h"
#include "tools.h"


#include "tcp.h"
#include "tcpTable.h"
#include "sysORTable.h"

#ifndef TCP_STATS_CACHE_TIMEOUT
#define TCP_STATS_CACHE_TIMEOUT	MIB_STATS_CACHE_TIMEOUT
#endif
marker_t tcp_stats_cache_marker = NULL;

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef linux
#define TCP_STAT_STRUCTURE	struct tcp_mib
#define USES_SNMP_DESIGNED_TCPSTAT
#endif

#ifdef hpux
#define TCP_STAT_STRUCTURE	struct tcp_mib
#define USES_SNMP_DESIGNED_TCPSTAT
#define TCP_INERRS_FIELD	tcpInErrs
#define TCP_OUTRSTS_FIELD	tcpOutRsts
#endif

#ifdef solaris2
#define TCP_STAT_STRUCTURE	mib2_tcp_t
#define USES_SNMP_DESIGNED_TCPSTAT
#define TCP_INERRS_FIELD	tcpOutAck	/* Re-use an unneeded field */
#define TCP_OUTRSTS_FIELD	tcpOutRsts
#endif

#if !defined(TCP_STAT_STRUCTURE)
#define TCP_STAT_STRUCTURE	struct tcpstat
#define USES_TRADITIONAL_TCPSTAT
#endif

long      read_tcp_stat (TCP_STAT_STRUCTURE *, int);
long arch_read_tcp_stat (TCP_STAT_STRUCTURE *, int);

#ifdef freebsd4
static unsigned int hz;
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

struct variable2 tcp_variables[] = {
    {TCPRTOALGORITHM, ASN_INTEGER, RONLY, var_tcp, 1, {1}},
    {TCPRTOMIN,       ASN_INTEGER, RONLY, var_tcp, 1, {2}},
#ifndef sunV3
    {TCPRTOMAX,       ASN_INTEGER, RONLY, var_tcp, 1, {3}},
#endif
    {TCPMAXCONN,      ASN_INTEGER, RONLY, var_tcp, 1, {4}},
#ifndef sunV3
    {TCPACTIVEOPENS,  ASN_COUNTER, RONLY, var_tcp, 1, {5}},
    {TCPPASSIVEOPENS, ASN_COUNTER, RONLY, var_tcp, 1, {6}},
    {TCPATTEMPTFAILS, ASN_COUNTER, RONLY, var_tcp, 1, {7}},
    {TCPESTABRESETS,  ASN_COUNTER, RONLY, var_tcp, 1, {8}},
#endif
    {TCPCURRESTAB,    ASN_GAUGE,   RONLY, var_tcp, 1, {9}},
#ifndef sunV3
    {TCPINSEGS,       ASN_COUNTER, RONLY, var_tcp, 1, {10}},
    {TCPOUTSEGS,      ASN_COUNTER, RONLY, var_tcp, 1, {11}},
    {TCPRETRANSSEGS,  ASN_COUNTER, RONLY, var_tcp, 1, {12}},
#endif
    {TCPINERRS,       ASN_COUNTER, RONLY, var_tcp, 1, {14}},
    {TCPOUTRSTS,      ASN_COUNTER, RONLY, var_tcp, 1, {15}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath, and the OID for the MIB module */
oid tcp_variables_oid[] = { SNMP_OID_MIB2,6 };
oid tcp_module_oid[]    = { SNMP_OID_MIB2,49 };

void init_tcp(void)
{
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/tcp", tcp_variables, variable2, tcp_variables_oid);
  REGISTER_SYSOR_ENTRY( tcp_module_oid,
		"The MIB module for managing TCP implementations");

#ifdef TCPSTAT_SYMBOL
  auto_nlist( TCPSTAT_SYMBOL,0,0 );
#endif
#ifdef TCP_SYMBOL
  auto_nlist( TCP_SYMBOL,0,0 );
#endif
#if freebsd4
  hz=sysconf(_SC_CLK_TCK); /* get ticks/s from system */
#endif
}


	/*********************
	 *
	 *  Main variable handling routine
	 *
	 *********************/


u_char *
var_tcp(struct variable *vp,
	oid *name,
	size_t *length,
	int exact,
	size_t *var_len,
	WriteMethod **write_method)
{
    static TCP_STAT_STRUCTURE tcpstat;
    static long ret_value;
#ifdef TCPTV_NEEDS_HZ
    /*
     * I don't know of any such system now, but maybe they'll figure
     * it out some day.
     */
    int hz = 1000;
#endif

    if (header_generic(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    ret_value = read_tcp_stat (&tcpstat, vp->magic);
    if ( ret_value < 0 )
	return NULL;

    switch (vp->magic){
#ifdef USES_SNMP_DESIGNED_TCPSTAT
	case TCPRTOALGORITHM:	return (u_char *) &tcpstat.tcpRtoAlgorithm;
	case TCPRTOMIN:		return (u_char *) &tcpstat.tcpRtoMin;
	case TCPRTOMAX:		return (u_char *) &tcpstat.tcpRtoMax;
	case TCPMAXCONN:	return (u_char *) &tcpstat.tcpMaxConn;
	case TCPACTIVEOPENS:	return (u_char *) &tcpstat.tcpActiveOpens;
	case TCPPASSIVEOPENS:	return (u_char *) &tcpstat.tcpPassiveOpens;
	case TCPATTEMPTFAILS:	return (u_char *) &tcpstat.tcpAttemptFails;
	case TCPESTABRESETS:	return (u_char *) &tcpstat.tcpEstabResets;
	case TCPCURRESTAB:	return (u_char *) &tcpstat.tcpCurrEstab;
	case TCPINSEGS:		return (u_char *) &tcpstat.tcpInSegs;
	case TCPOUTSEGS:	return (u_char *) &tcpstat.tcpOutSegs;
	case TCPRETRANSSEGS:	return (u_char *) &tcpstat.tcpRetransSegs;
	case TCPINERRS:
#ifdef TCP_INERRS_FIELD
				return (u_char *) &tcpstat.TCP_INERRS_FIELD;
#else
				return NULL;
#endif
	case TCPOUTRSTS:
#ifdef TCP_OUTRSTS_FIELD
				return (u_char *) &tcpstat.TCP_OUTRSTS_FIELD;
#else
				return NULL;
#endif
#endif




#ifdef USES_TRADITIONAL_TCPSTAT
	case TCPRTOALGORITHM:		/* Assume Van Jacobsen's algorithm */
				long_return = 4;
				return (u_char *) &long_return;
	case TCPRTOMIN:
#ifdef TCPTV_NEEDS_HZ
				long_return = TCPTV_MIN;
#else
				long_return = TCPTV_MIN / PR_SLOWHZ * 1000;
#endif
				return (u_char *) &long_return;
	case TCPRTOMAX:	
#ifdef TCPTV_NEEDS_HZ
				long_return = TCPTV_REXMTMAX;
#else
				long_return = TCPTV_REXMTMAX / PR_SLOWHZ * 1000;
#endif
				return (u_char *) &long_return;
	case TCPMAXCONN:	return NULL;
	case TCPACTIVEOPENS:	return (u_char *) &tcpstat.tcps_connattempt;
	case TCPPASSIVEOPENS:	return (u_char *) &tcpstat.tcps_accepts;
		/*
		 * NB:  tcps_drops is actually the sum of the two MIB
		 *	counters tcpAttemptFails and tcpEstabResets.
		 */
	case TCPATTEMPTFAILS:	return (u_char *) &tcpstat.tcps_conndrops;
	case TCPESTABRESETS:	return (u_char *) &tcpstat.tcps_drops;
	case TCPCURRESTAB:
				long_return = TCP_Count_Connections();
				return (u_char *) &long_return;
	case TCPINSEGS:		return (u_char *) &tcpstat.tcps_rcvtotal;
	case TCPOUTSEGS:
		/*
		 * RFC 1213 defines this as the number of segments sent
		 * "excluding those containing only retransmitted octets"
		 */
				long_return = tcpstat.tcps_sndtotal
			    		    - tcpstat.tcps_sndrexmitpack;
				return (u_char *) &long_return;
	case TCPRETRANSSEGS:	return (u_char *) &tcpstat.tcps_sndrexmitpack;
	case TCPINERRS:
				long_return = tcpstat.tcps_rcvbadsum
					    + tcpstat.tcps_rcvbadoff 
#ifdef STRUCT_TCPSTAT_HAS_TCPS_RCVMEMDROP
					    + tcpstat.tcps_rcvmemdrop
#endif
					    + tcpstat.tcps_rcvshort;
				return (u_char *) &long_return;
	case TCPOUTRSTS:
				long_return = tcpstat.tcps_sndctrl
					    - tcpstat.tcps_closed;
				return (u_char *) &long_return;
#endif

	default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_tcp\n", vp->magic));
    }
    return NULL;

}


	/*********************
	 *
	 *  System-independent internal implementation function
	 *
	 *********************/


long
read_tcp_stat( TCP_STAT_STRUCTURE *tcpstat, int magic )
{
   long ret_value = -1;
   int i;

    if (  tcp_stats_cache_marker &&
	(!atime_ready(tcp_stats_cache_marker, TCP_STATS_CACHE_TIMEOUT*1000)))
	return 0;

    if (tcp_stats_cache_marker )
	atime_setMarker( tcp_stats_cache_marker );
    else
	tcp_stats_cache_marker = atime_newMarker();

    ret_value = arch_read_tcp_stat(tcpstat, magic);

    if ( ret_value == -1 ) {
	free( tcp_stats_cache_marker );
	tcp_stats_cache_marker = NULL;
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
#define READ_TCP_STAT
long arch_read_tcp_stat( TCP_STAT_STRUCTURE *tcpstat, int magic )
{
    return hpux_read_stat((char *)tcpstat, sizeof(*tcpstat), ID_tcp);
}
#endif

#ifdef linux
#define READ_TCP_STAT
long arch_read_tcp_stat(  TCP_STAT_STRUCTURE *tcpstat, int magic )
{
    return linux_read_tcp_stat(tcpstat);
}
#endif

#ifdef solaris2
#define READ_TCP_STAT
long arch_read_tcp_stat(  TCP_STAT_STRUCTURE *tcpstat, int magic )
{
    mib2_ip_t ipstat;

    if (getMibstat(MIB_IP, &ipstat, sizeof(mib2_ip_t), GET_FIRST, &Get_everything, NULL) < 0 )
	return -1;

    if (getMibstat(MIB_TCP, tcpstat, sizeof(mib2_tcp_t), GET_FIRST, &Get_everything, NULL) < 0 )
	return -1;

    tcpstat->TCP_INERRS_FIELD = ipstat.tcpInErrs;
    return 0;
}
#endif

#ifdef HAVE_SYS_TCPIPSTATS_H
#define READ_TCP_STAT
long arch_read_tcp_stat(  TCP_STAT_STRUCTURE *tcpstat, int magic )
{
    struct kna full_stats;
    int res;

    res = sysmp (MP_SAGET, MPSA_TCPIPSTATS, &full_stats, sizeof(struct kna));
    if ( res != -1 )
	memcpy( tcpstat, &full_stats.tcpstats, sizeof( full_stats.tcpstats ));
    return res;
}
#endif

#if defined(CAN_USE_SYSCTL) && defined(TCPCTL_STATS)
#define READ_TCP_STAT
long arch_read_tcp_stat(  TCP_STAT_STRUCTURE *tcpstat, int magic )
{
    int sname[4] = { CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_STATS };
    size_t len = sizeof( *tcpstat );

    return sysctl(sname, 4, tcpstat, &len, 0, 0);
}
#endif

#ifndef READ_TCP_STAT
long arch_read_tcp_stat(  TCP_STAT_STRUCTURE *tcpstat, int magic )
{
    if (auto_nlist(TCPSTAT_SYMBOL, (char *)tcpstat, sizeof (*tcpstat)))
	return 0;
    else
	return -1;
}
#endif
