/*
 *  ICMP MIB group implementation - icmp.c
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
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#include <netinet/ip.h>

#include <netinet/ip_icmp.h>
#if HAVE_NETINET_ICMP_VAR_H
#include <netinet/icmp_var.h>
#endif

#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#ifdef solaris2
#include "kernel_sunos5.h"
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

#include "auto_nlist.h"

#include "icmp.h"

#ifndef ICMP_STATS_CACHE_TIMEOUT
#define ICMP_STATS_CACHE_TIMEOUT	MIB_STATS_CACHE_TIMEOUT
#endif

marker_t icmp_stats_cache_marker = NULL;

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#if defined(linux) || defined(hpux)
#define ICMP_STAT_STRUCTURE	struct icmp_mib
#define USES_SNMP_DESIGNED_ICMPSTAT
#endif

#ifdef solaris2
#define ICMP_STAT_STRUCTURE	mib2_icmp_t
#define USES_SNMP_DESIGNED_ICMPSTAT
#endif

#if !defined(ICMP_STAT_STRUCTURE)
#define ICMP_STAT_STRUCTURE	struct icmpstat
#define USES_TRADITIONAL_ICMPSTAT
#endif

long      read_icmp_stat (ICMP_STAT_STRUCTURE *, int);
long arch_read_icmp_stat (ICMP_STAT_STRUCTURE *, int);


	/*********************
	 *
	 *  Initialisation
	 *
	 *********************/


/* define the structure we're going to ask the agent to register our
   information at */
struct variable2 icmp_variables[] = {
    {ICMPINMSGS,         ASN_COUNTER, RONLY, var_icmp, 1, {1}},
    {ICMPINERRORS,       ASN_COUNTER, RONLY, var_icmp, 1, {2}},
    {ICMPINDESTUNREACHS, ASN_COUNTER, RONLY, var_icmp, 1, {3}},
    {ICMPINTIMEEXCDS,    ASN_COUNTER, RONLY, var_icmp, 1, {4}},
    {ICMPINPARMPROBS,    ASN_COUNTER, RONLY, var_icmp, 1, {5}},
    {ICMPINSRCQUENCHS,   ASN_COUNTER, RONLY, var_icmp, 1, {6}},
    {ICMPINREDIRECTS,    ASN_COUNTER, RONLY, var_icmp, 1, {7}},
    {ICMPINECHOS,        ASN_COUNTER, RONLY, var_icmp, 1, {8}},
    {ICMPINECHOREPS,     ASN_COUNTER, RONLY, var_icmp, 1, {9}},
    {ICMPINTIMESTAMPS,   ASN_COUNTER, RONLY, var_icmp, 1, {10}},
    {ICMPINTIMESTAMPREPS,ASN_COUNTER, RONLY, var_icmp, 1, {11}},
    {ICMPINADDRMASKS,    ASN_COUNTER, RONLY, var_icmp, 1, {12}},
    {ICMPINADDRMASKREPS, ASN_COUNTER, RONLY, var_icmp, 1, {13}},
    {ICMPOUTMSGS,        ASN_COUNTER, RONLY, var_icmp, 1, {14}},
    {ICMPOUTERRORS,      ASN_COUNTER, RONLY, var_icmp, 1, {15}},
    {ICMPOUTDESTUNREACHS,ASN_COUNTER, RONLY, var_icmp, 1, {16}},
    {ICMPOUTTIMEEXCDS,   ASN_COUNTER, RONLY, var_icmp, 1, {17}},
    {ICMPOUTPARMPROBS,   ASN_COUNTER, RONLY, var_icmp, 1, {18}},
    {ICMPOUTSRCQUENCHS,  ASN_COUNTER, RONLY, var_icmp, 1, {19}},
    {ICMPOUTREDIRECTS,   ASN_COUNTER, RONLY, var_icmp, 1, {20}},
    {ICMPOUTECHOS,       ASN_COUNTER, RONLY, var_icmp, 1, {21}},
    {ICMPOUTECHOREPS,    ASN_COUNTER, RONLY, var_icmp, 1, {22}},
    {ICMPOUTTIMESTAMPS,  ASN_COUNTER, RONLY, var_icmp, 1, {23}},
    {ICMPOUTTIMESTAMPREPS,ASN_COUNTER, RONLY, var_icmp, 1, {24}},
    {ICMPOUTADDRMASKS,   ASN_COUNTER, RONLY, var_icmp, 1, {25}},
    {ICMPOUTADDRMASKREPS,ASN_COUNTER, RONLY, var_icmp, 1, {26}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
oid icmp_variables_oid[] = { SNMP_OID_MIB2,5 };

void init_icmp(void)
{
    /* register ourselves with the agent to handle our mib tree */
    REGISTER_MIB("mibII/icmp", icmp_variables, variable2, icmp_variables_oid);

#ifdef ICMPSTAT_SYMBOL
    auto_nlist( ICMPSTAT_SYMBOL,0,0 );
#endif
}


	/*********************
	 *
	 *  Main variable handling routine
	 *
	 *********************/


u_char *
var_icmp(struct variable *vp,
	 oid *name,
	 size_t *length,
	 int exact,
	 size_t *var_len,
	 WriteMethod **write_method)
{
    static ICMP_STAT_STRUCTURE	icmpstat;
    static long ret_value;
    int i;

    if (header_generic(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    ret_value = read_icmp_stat (&icmpstat, vp->magic);
    if ( ret_value < 0 )
	return NULL;


    switch (vp->magic){
#ifdef USES_SNMP_DESIGNED_ICMPSTAT
	case ICMPINMSGS:	return (u_char *) &icmpstat.icmpInMsgs;
	case ICMPINERRORS:	return (u_char *) &icmpstat.icmpInErrors;
	case ICMPINDESTUNREACHS:return (u_char *) &icmpstat.icmpInDestUnreachs;
	case ICMPINTIMEEXCDS:	return (u_char *) &icmpstat.icmpInTimeExcds;
	case ICMPINPARMPROBS:	return (u_char *) &icmpstat.icmpInParmProbs;
	case ICMPINSRCQUENCHS:	return (u_char *) &icmpstat.icmpInSrcQuenchs;
	case ICMPINREDIRECTS:	return (u_char *) &icmpstat.icmpInRedirects;
	case ICMPINECHOS:	return (u_char *) &icmpstat.icmpInEchos;
	case ICMPINECHOREPS:	return (u_char *) &icmpstat.icmpInEchoReps;
	case ICMPINTIMESTAMPS:	return (u_char *) &icmpstat.icmpInTimestamps;
	case ICMPINTIMESTAMPREPS:return (u_char *) &icmpstat.icmpInTimestampReps;
	case ICMPINADDRMASKS:	return (u_char *) &icmpstat.icmpInAddrMasks;
	case ICMPINADDRMASKREPS:return (u_char *) &icmpstat.icmpInAddrMaskReps;
	case ICMPOUTMSGS:	return (u_char *) &icmpstat.icmpOutMsgs;
	case ICMPOUTERRORS:	return (u_char *) &icmpstat.icmpOutErrors;
	case ICMPOUTDESTUNREACHS:return (u_char *) &icmpstat.icmpOutDestUnreachs;
	case ICMPOUTTIMEEXCDS:	return (u_char *) &icmpstat.icmpOutTimeExcds;
	case ICMPOUTPARMPROBS:	return (u_char *) &icmpstat.icmpOutParmProbs;
	case ICMPOUTSRCQUENCHS:	return (u_char *) &icmpstat.icmpOutSrcQuenchs;
	case ICMPOUTREDIRECTS:	return (u_char *) &icmpstat.icmpOutRedirects;
	case ICMPOUTECHOS:	return (u_char *) &icmpstat.icmpOutEchos;
	case ICMPOUTECHOREPS:	return (u_char *) &icmpstat.icmpOutEchoReps;
	case ICMPOUTTIMESTAMPS:	return (u_char *) &icmpstat.icmpOutTimestamps;
	case ICMPOUTTIMESTAMPREPS:return (u_char *)&icmpstat.icmpOutTimestampReps;
	case ICMPOUTADDRMASKS:	return (u_char *) &icmpstat.icmpOutAddrMasks;
	case ICMPOUTADDRMASKREPS:return (u_char *) &icmpstat.icmpOutAddrMaskReps;
#endif /* USES_SNMP_DESIGNED_ICMPSTAT */

#ifdef USES_TRADITIONAL_ICMPSTAT

	case ICMPINMSGS:
				long_return = icmpstat.icps_badcode +
					      icmpstat.icps_tooshort +
					      icmpstat.icps_checksum +
					      icmpstat.icps_badlen;
	    			for (i=0; i <= ICMP_MAXTYPE; i++)
				    long_return += icmpstat.icps_inhist[i];
				return (u_char *)&long_return;
	case ICMPINERRORS:
				long_return = icmpstat.icps_badcode +
					      icmpstat.icps_tooshort +
					      icmpstat.icps_checksum +
					      icmpstat.icps_badlen;
				return (u_char *)&long_return;
	case ICMPINDESTUNREACHS:
			return (u_char *) &icmpstat.icps_inhist[ICMP_UNREACH];
	case ICMPINTIMEEXCDS:	
			return (u_char *) &icmpstat.icps_inhist[ICMP_TIMXCEED];
	case ICMPINPARMPROBS:	
			return (u_char *) &icmpstat.icps_inhist[ICMP_PARAMPROB];
	case ICMPINSRCQUENCHS:	
			return (u_char *) &icmpstat.icps_inhist[ICMP_SOURCEQUENCH];
	case ICMPINREDIRECTS:	
			return (u_char *) &icmpstat.icps_inhist[ICMP_REDIRECT];
	case ICMPINECHOS:	
			return (u_char *) &icmpstat.icps_inhist[ICMP_ECHO];
	case ICMPINECHOREPS:	
			return (u_char *) &icmpstat.icps_inhist[ICMP_ECHOREPLY];
	case ICMPINTIMESTAMPS:	
			return (u_char *) &icmpstat.icps_inhist[ICMP_TSTAMP];
	case ICMPINTIMESTAMPREPS:
			return (u_char *) &icmpstat.icps_inhist[ICMP_TSTAMPREPLY];
	case ICMPINADDRMASKS:	
			return (u_char *) &icmpstat.icps_inhist[ICMP_MASKREQ];
	case ICMPINADDRMASKREPS:
			return (u_char *) &icmpstat.icps_inhist[ICMP_MASKREPLY];
	case ICMPOUTMSGS:
				long_return = icmpstat.icps_oldshort +
					      icmpstat.icps_oldicmp;
	    			for (i=0; i <= ICMP_MAXTYPE; i++)
				    long_return += icmpstat.icps_outhist[i];
				return (u_char *)&long_return;
	case ICMPOUTERRORS:
				long_return = icmpstat.icps_oldshort +
					      icmpstat.icps_oldicmp;
				return (u_char *)&long_return;
	case ICMPOUTDESTUNREACHS:
			return (u_char *) &icmpstat.icps_outhist[ICMP_UNREACH];
	case ICMPOUTTIMEEXCDS:	
			return (u_char *) &icmpstat.icps_outhist[ICMP_TIMXCEED];
	case ICMPOUTPARMPROBS:	
			return (u_char *) &icmpstat.icps_outhist[ICMP_PARAMPROB];
	case ICMPOUTSRCQUENCHS:	
			return (u_char *) &icmpstat.icps_outhist[ICMP_SOURCEQUENCH];
	case ICMPOUTREDIRECTS:	
			return (u_char *) &icmpstat.icps_outhist[ICMP_REDIRECT];
	case ICMPOUTECHOS:	
			return (u_char *) &icmpstat.icps_outhist[ICMP_ECHO];
	case ICMPOUTECHOREPS:	
			return (u_char *) &icmpstat.icps_outhist[ICMP_ECHOREPLY];
	case ICMPOUTTIMESTAMPS:	
			return (u_char *) &icmpstat.icps_outhist[ICMP_TSTAMP];
	case ICMPOUTTIMESTAMPREPS:
			return (u_char *) &icmpstat.icps_outhist[ICMP_TSTAMPREPLY];
	case ICMPOUTADDRMASKS:	
			return (u_char *) &icmpstat.icps_outhist[ICMP_MASKREQ];
	case ICMPOUTADDRMASKREPS:
			return (u_char *) &icmpstat.icps_outhist[ICMP_MASKREPLY];
#endif /* USES_TRADITIONAL_ICMPSTAT */

	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_icmp\n", vp->magic));
    }

    return NULL;
}


	/*********************
	 *
	 *  System-independent internal implementation functions
	 *
	 *********************/


long
read_icmp_stat( ICMP_STAT_STRUCTURE *icmpstat, int magic )
{
   long ret_value = -1;
   int i;

    if (  icmp_stats_cache_marker &&
	(!atime_ready(icmp_stats_cache_marker, ICMP_STATS_CACHE_TIMEOUT*1000)))
	return 0;

    if (icmp_stats_cache_marker )
	atime_setMarker( icmp_stats_cache_marker );
    else
	icmp_stats_cache_marker = atime_newMarker();

    ret_value = arch_read_icmp_stat(icmpstat, magic);

    if ( ret_value == -1 ) {
	free( icmp_stats_cache_marker );
	icmp_stats_cache_marker = NULL;
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
#define READ_ICMP_STAT
long arch_read_icmp_stat( ICMP_STAT_STRUCTURE *icmpstat, int magic )
{
    return hpux_read_stat((char*)icmpstat, sizeof(*icmpstat), ID_icmp);
}
#endif

#ifdef linux
#define READ_ICMP_STAT
long arch_read_icmp_stat(  ICMP_STAT_STRUCTURE *icmpstat, int magic )
{
    return linux_read_icmp_stat(icmpstat);
}
#endif

#ifdef solaris2
#define READ_ICMP_STAT
long arch_read_icmp_stat(  ICMP_STAT_STRUCTURE *icmpstat, int magic )
{
    return getMibstat(MIB_ICMP, icmpstat, sizeof(mib2_icmp_t), GET_FIRST, &Get_everything, NULL);
}
#endif

#ifdef HAVE_SYS_TCPIPSTATS_H
#define READ_ICMP_STAT
long arch_read_icmp_stat(  ICMP_STAT_STRUCTURE *icmpstat, int magic )
{
    struct kna full_stats;
    int res;

    res = sysmp (MP_SAGET, MPSA_TCPIPSTATS, &full_stats, sizeof(struct kna));
    if ( res != -1 )
	memcpy( icmpstat, &full_stats.icmpstats, sizeof( full_stats.icmpstats ));
    return res;
}
#endif

#if defined(CAN_USE_SYSCTL) && defined(ICMPCTL_STATS)
#define READ_ICMP_STAT
long arch_read_icmp_stat(  ICMP_STAT_STRUCTURE *icmpstat, int magic )
{
    int sname[4] = { CTL_NET, PF_INET, IPPROTO_ICMP, ICMPCTL_STATS };
    size_t len = sizeof( *icmpstat );

    return sysctl(sname, 4, icmpstat, &len, 0, 0);
}
#endif


			/* Catch-all */
#ifndef READ_ICMP_STAT
long arch_read_icmp_stat(  ICMP_STAT_STRUCTURE *icmpstat, int magic )
{
    if (auto_nlist(ICMPSTAT_SYMBOL, (char *)icmpstat, sizeof (*icmpstat)))
	return 0;
    else
	return -1;
    return -1
}
#endif
