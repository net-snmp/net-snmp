/*
 *  ICMP MIB group implementation - icmp.c
 *
 */

#include <config.h>
#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/socket.h>

#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
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

#include "system.h"
#include "asn1.h"
#include "snmp_debug.h"

#include "mibincl.h"
#include "auto_nlist.h"

#ifdef hpux
#include <sys/mib.h>
#include <netinet/mib_kern.h>
#endif /* hpux */

/* #include "../common_header.h" */

#include "icmp.h"
#include "sysORTable.h"

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef linux
static void
linux_read_icmp_stat (struct icmp_mib *);
#endif



	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


/* define the structure we're going to ask the agent to register our
   information at */
struct variable2 icmp_variables[] = {
    {ICMPINMSGS, ASN_COUNTER, RONLY, var_icmp, 1, {1}},
    {ICMPINERRORS, ASN_COUNTER, RONLY, var_icmp, 1, {2}},
    {ICMPINDESTUNREACHS, ASN_COUNTER, RONLY, var_icmp, 1, {3}},
    {ICMPINTIMEEXCDS, ASN_COUNTER, RONLY, var_icmp, 1, {4}},
    {ICMPINPARMPROBS, ASN_COUNTER, RONLY, var_icmp, 1, {5}},
    {ICMPINSRCQUENCHS, ASN_COUNTER, RONLY, var_icmp, 1, {6}},
    {ICMPINREDIRECTS, ASN_COUNTER, RONLY, var_icmp, 1, {7}},
    {ICMPINECHOS, ASN_COUNTER, RONLY, var_icmp, 1, {8}},
    {ICMPINECHOREPS, ASN_COUNTER, RONLY, var_icmp, 1, {9}},
    {ICMPINTIMESTAMPS, ASN_COUNTER, RONLY, var_icmp, 1, {10}},
    {ICMPINTIMESTAMPREPS, ASN_COUNTER, RONLY, var_icmp, 1, {11}},
    {ICMPINADDRMASKS, ASN_COUNTER, RONLY, var_icmp, 1, {12}},
    {ICMPINADDRMASKREPS, ASN_COUNTER, RONLY, var_icmp, 1, {13}},
    {ICMPOUTMSGS, ASN_COUNTER, RONLY, var_icmp, 1, {14}},
    {ICMPOUTERRORS, ASN_COUNTER, RONLY, var_icmp, 1, {15}},
    {ICMPOUTDESTUNREACHS, ASN_COUNTER, RONLY, var_icmp, 1, {16}},
    {ICMPOUTTIMEEXCDS, ASN_COUNTER, RONLY, var_icmp, 1, {17}},
    {ICMPOUTPARMPROBS, ASN_COUNTER, RONLY, var_icmp, 1, {18}},
    {ICMPOUTSRCQUENCHS, ASN_COUNTER, RONLY, var_icmp, 1, {19}},
    {ICMPOUTREDIRECTS, ASN_COUNTER, RONLY, var_icmp, 1, {20}},
    {ICMPOUTECHOS, ASN_COUNTER, RONLY, var_icmp, 1, {21}},
    {ICMPOUTECHOREPS, ASN_COUNTER, RONLY, var_icmp, 1, {22}},
    {ICMPOUTTIMESTAMPS, ASN_COUNTER, RONLY, var_icmp, 1, {23}},
    {ICMPOUTTIMESTAMPREPS, ASN_COUNTER, RONLY, var_icmp, 1, {24}},
    {ICMPOUTADDRMASKS, ASN_COUNTER, RONLY, var_icmp, 1, {25}},
    {ICMPOUTADDRMASKREPS, ASN_COUNTER, RONLY, var_icmp, 1, {26}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
oid icmp_variables_oid[] = { SNMP_OID_MIB2,5 };
#ifdef USING_MIBII_IP_MODULE
extern oid ip_module_oid[];
extern int ip_module_oid_len;
extern int ip_module_count;
#endif

void init_icmp(void)
{
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/icmp", icmp_variables, variable2, icmp_variables_oid);

#ifdef USING_MIBII_IP_MODULE
  if ( ++ip_module_count == 2 )
	REGISTER_SYSOR_TABLE( ip_module_oid, ip_module_oid_len,
		"The MIB module for managing IP and ICMP implementations");
#endif 

#ifdef ICMPSTAT_SYMBOL
    auto_nlist( ICMPSTAT_SYMBOL,0,0 );
#endif
}

/*
  header_icmp(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/
int
header_icmp(struct variable *vp,
	    oid *name,
	    size_t *length,
	    int exact,
	    size_t *var_len,
	    WriteMethod **write_method)
{
#define ICMP_NAME_LENGTH	8
    oid newname[MAX_OID_LEN];
    int result;

    DEBUGMSGTL(("mibII/icmp", "var_icmp: "));
    DEBUGMSGOID(("mibII/icmp", name, *length));
    DEBUGMSG(("mibII/icmp"," %d\n", exact));

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[ICMP_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

#ifndef solaris2
#ifndef linux
#if HAVE_SYS_TCPIPSTATS_H

u_char *
var_icmp(struct variable *vp,
	 oid *name,
	 size_t *length,
	 int exact,
	 size_t *var_len,
	 WriteMethod **write_method)
{
    register int i;
    static struct icmpstat icmpstat;
    static struct kna tcpipstats;
    if (header_icmp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *	Get the ICMP statistics from the kernel...
     */
    if (sysmp (MP_SAGET, MPSA_TCPIPSTATS, &tcpipstats, sizeof tcpipstats) == -1) {
	snmp_log_perror ("sysmp(MP_SAGET)(MPSA_TCPIPSTATS)");
    }
#define icmpstat tcpipstats.icmpstat

    switch (vp->magic){
	case ICMPINMSGS:
	    long_return = icmpstat.icps_badcode + icmpstat.icps_tooshort +
			  icmpstat.icps_checksum + icmpstat.icps_badlen;
	    for (i=0; i <= ICMP_MAXTYPE; i++)
		long_return += icmpstat.icps_inhist[i];
	    return (u_char *)&long_return;
	case ICMPINERRORS:
	    long_return = icmpstat.icps_badcode + icmpstat.icps_tooshort +
			  icmpstat.icps_checksum + icmpstat.icps_badlen;
	    return (u_char *)&long_return;
	case ICMPINDESTUNREACHS:
          long_return = icmpstat.icps_inhist[ICMP_UNREACH];
          return (u_char *) &long_return;
	case ICMPINTIMEEXCDS:
          long_return = icmpstat.icps_inhist[ICMP_TIMXCEED];
          return (u_char *) &long_return;
	case ICMPINPARMPROBS:
          long_return = icmpstat.icps_inhist[ICMP_PARAMPROB];
          return (u_char *) &long_return;
	case ICMPINSRCQUENCHS:
          long_return = icmpstat.icps_inhist[ICMP_SOURCEQUENCH];
          return (u_char *) &long_return;
	case ICMPINREDIRECTS:
          long_return = icmpstat.icps_inhist[ICMP_REDIRECT];
          return (u_char *) &long_return;
	case ICMPINECHOS:
          long_return = icmpstat.icps_inhist[ICMP_ECHO];
          return (u_char *) &long_return;
	case ICMPINECHOREPS:
          long_return = icmpstat.icps_inhist[ICMP_ECHOREPLY];
          return (u_char *) &long_return;
	case ICMPINTIMESTAMPS:
          long_return = icmpstat.icps_inhist[ICMP_TSTAMP];
          return (u_char *) &long_return;
	case ICMPINTIMESTAMPREPS:
          long_return = icmpstat.icps_inhist[ICMP_TSTAMPREPLY];
          return (u_char *) &long_return;
	case ICMPINADDRMASKS:
          long_return = icmpstat.icps_inhist[ICMP_MASKREQ];
          return (u_char *) &long_return;
	case ICMPINADDRMASKREPS:
          long_return = icmpstat.icps_inhist[ICMP_MASKREPLY];
          return (u_char *) &long_return;
	case ICMPOUTMSGS:
	    long_return = icmpstat.icps_oldshort + icmpstat.icps_oldicmp;
	    for (i=0; i <= ICMP_MAXTYPE; i++)
		long_return += icmpstat.icps_outhist[i];
	    return (u_char *)&long_return;
	case ICMPOUTERRORS:
	    long_return = icmpstat.icps_oldshort + icmpstat.icps_oldicmp;
	    return (u_char *)&long_return;
	case ICMPOUTDESTUNREACHS:
          long_return = icmpstat.icps_outhist[ICMP_UNREACH];
          return (u_char *) &long_return;
	case ICMPOUTTIMEEXCDS:
          long_return = icmpstat.icps_outhist[ICMP_TIMXCEED];
          return (u_char *) &long_return;
	case ICMPOUTPARMPROBS:
          long_return = icmpstat.icps_outhist[ICMP_PARAMPROB];
          return (u_char *) &long_return;
	case ICMPOUTSRCQUENCHS:
          long_return = icmpstat.icps_outhist[ICMP_SOURCEQUENCH];
          return (u_char *) &long_return;
	case ICMPOUTREDIRECTS:
          long_return = icmpstat.icps_outhist[ICMP_REDIRECT];
          return (u_char *) &long_return;
	case ICMPOUTECHOS:
          long_return = icmpstat.icps_outhist[ICMP_ECHO];
          return (u_char *) &long_return;
	case ICMPOUTECHOREPS:
          long_return = icmpstat.icps_outhist[ICMP_ECHOREPLY];
          return (u_char *) &long_return;
	case ICMPOUTTIMESTAMPS:
          long_return = icmpstat.icps_outhist[ICMP_TSTAMP];
          return (u_char *) &long_return;
	case ICMPOUTTIMESTAMPREPS:
          long_return = icmpstat.icps_outhist[ICMP_TSTAMPREPLY];
          return (u_char *) &long_return;
	case ICMPOUTADDRMASKS:
          long_return = icmpstat.icps_outhist[ICMP_MASKREQ];
          return (u_char *) &long_return;
	case ICMPOUTADDRMASKREPS:
          long_return = icmpstat.icps_outhist[ICMP_MASKREPLY];
          return (u_char *) &long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_icmp\n", vp->magic));
    }

    return NULL;
}

#else /* not HAVE_SYS_TCPIPSTATS_H */

u_char *
var_icmp(struct variable *vp,
	 oid *name,
	 size_t *length,
	 int exact,
	 size_t *var_len,
	 WriteMethod **write_method)
{
    register int i;
    static struct icmpstat icmpstat;

   if (header_icmp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *        Get the ICMP statistics from the kernel...
     */
#if !defined(CAN_USE_SYSCTL) || !defined(ICMPCTL_STATS)
    auto_nlist(ICMPSTAT_SYMBOL, (char *)&icmpstat, sizeof (icmpstat));
#else
    {
	    int sname[] = { CTL_NET, PF_INET, IPPROTO_ICMP, ICMPCTL_STATS };
	    size_t len;
	    
	    len = sizeof icmpstat;
	    if (sysctl(sname, 4, &icmpstat, &len, 0, 0) < 0)
		    return NULL;
    }
#endif /* use sysctl */

    switch (vp->magic) {
	case ICMPINMSGS:
	    long_return = icmpstat.icps_badcode + icmpstat.icps_tooshort +
			  icmpstat.icps_checksum + icmpstat.icps_badlen;
	    for (i=0; i <= ICMP_MAXTYPE; i++)
		long_return += icmpstat.icps_inhist[i];
	    return (u_char *)&long_return;
	case ICMPINERRORS:
	    long_return = icmpstat.icps_badcode + icmpstat.icps_tooshort +
			  icmpstat.icps_checksum + icmpstat.icps_badlen;
	    return (u_char *)&long_return;
	case ICMPINDESTUNREACHS:
          long_return = icmpstat.icps_inhist[ICMP_UNREACH];
          return (u_char *) &long_return;
	case ICMPINTIMEEXCDS:
          long_return = icmpstat.icps_inhist[ICMP_TIMXCEED];
          return (u_char *) &long_return;
	case ICMPINPARMPROBS:
          long_return = icmpstat.icps_inhist[ICMP_PARAMPROB];
          return (u_char *) &long_return;
	case ICMPINSRCQUENCHS:
          long_return = icmpstat.icps_inhist[ICMP_SOURCEQUENCH];
          return (u_char *) &long_return;
	case ICMPINREDIRECTS:
          long_return = icmpstat.icps_inhist[ICMP_REDIRECT];
          return (u_char *) &long_return;
	case ICMPINECHOS:
          long_return = icmpstat.icps_inhist[ICMP_ECHO];
          return (u_char *) &long_return;
	case ICMPINECHOREPS:
          long_return = icmpstat.icps_inhist[ICMP_ECHOREPLY];
          return (u_char *) &long_return;
	case ICMPINTIMESTAMPS:
          long_return = icmpstat.icps_inhist[ICMP_TSTAMP];
          return (u_char *) &long_return;
	case ICMPINTIMESTAMPREPS:
          long_return = icmpstat.icps_inhist[ICMP_TSTAMPREPLY];
          return (u_char *) &long_return;
	case ICMPINADDRMASKS:
          long_return = icmpstat.icps_inhist[ICMP_MASKREQ];
          return (u_char *) &long_return;
	case ICMPINADDRMASKREPS:
          long_return = icmpstat.icps_inhist[ICMP_MASKREPLY];
          return (u_char *) &long_return;
	case ICMPOUTMSGS:
	    long_return = icmpstat.icps_oldshort + icmpstat.icps_oldicmp;
	    for (i=0; i <= ICMP_MAXTYPE; i++)
		long_return += icmpstat.icps_outhist[i];
	    return (u_char *)&long_return;
	case ICMPOUTERRORS:
	    long_return = icmpstat.icps_oldshort + icmpstat.icps_oldicmp;
	    return (u_char *)&long_return;
	case ICMPOUTDESTUNREACHS:
          long_return = icmpstat.icps_outhist[ICMP_UNREACH];
          return (u_char *) &long_return;
	case ICMPOUTTIMEEXCDS:
          long_return = icmpstat.icps_outhist[ICMP_TIMXCEED];
          return (u_char *) &long_return;
	case ICMPOUTPARMPROBS:
          long_return = icmpstat.icps_outhist[ICMP_PARAMPROB];
          return (u_char *) &long_return;
	case ICMPOUTSRCQUENCHS:
          long_return = icmpstat.icps_outhist[ICMP_SOURCEQUENCH];
          return (u_char *) &long_return;
	case ICMPOUTREDIRECTS:
          long_return = icmpstat.icps_outhist[ICMP_REDIRECT];
          return (u_char *) &long_return;
	case ICMPOUTECHOS:
          long_return = icmpstat.icps_outhist[ICMP_ECHO];
          return (u_char *) &long_return;
	case ICMPOUTECHOREPS:
          long_return = icmpstat.icps_outhist[ICMP_ECHOREPLY];
          return (u_char *) &long_return;
	case ICMPOUTTIMESTAMPS:
          long_return = icmpstat.icps_outhist[ICMP_TSTAMP];
          return (u_char *) &long_return;
	case ICMPOUTTIMESTAMPREPS:
          long_return = icmpstat.icps_outhist[ICMP_TSTAMPREPLY];
          return (u_char *) &long_return;
	case ICMPOUTADDRMASKS:
          long_return = icmpstat.icps_outhist[ICMP_MASKREQ];
          return (u_char *) &long_return;
	case ICMPOUTADDRMASKREPS:
          long_return = icmpstat.icps_outhist[ICMP_MASKREPLY];
          return (u_char *) &long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_icmp\n", vp->magic));
    }

    return NULL;
}

#endif /* not HAVE_SYS_TCPIPSTATS_H */

#else /* linux */

u_char *
var_icmp(struct variable *vp,
	 oid *name,
	 size_t *length,
	 int exact,
	 size_t *var_len,
	 WriteMethod **write_method)
{
    static struct icmp_mib icmpstat;

   if (header_icmp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return(NULL);

    linux_read_icmp_stat (&icmpstat);

    switch (vp->magic){
    case ICMPINMSGS: return (u_char *) &icmpstat.IcmpInMsgs;
    case ICMPINERRORS: return (u_char *) &icmpstat.IcmpInErrors;
    case ICMPINDESTUNREACHS: return (u_char *) &icmpstat.IcmpInDestUnreachs;
    case ICMPINTIMEEXCDS: return (u_char *) &icmpstat.IcmpInTimeExcds;
    case ICMPINPARMPROBS: return (u_char *) &icmpstat.IcmpInParmProbs;
    case ICMPINSRCQUENCHS: return (u_char *) &icmpstat.IcmpInSrcQuenchs;
    case ICMPINREDIRECTS: return (u_char *) &icmpstat.IcmpInRedirects;
    case ICMPINECHOS: return (u_char *) &icmpstat.IcmpInEchos;
    case ICMPINECHOREPS: return (u_char *) &icmpstat.IcmpInEchoReps;
    case ICMPINTIMESTAMPS: return (u_char *) &icmpstat.IcmpInTimestamps;
    case ICMPINTIMESTAMPREPS: return (u_char *) &icmpstat.IcmpInTimestampReps;
    case ICMPINADDRMASKS: return (u_char *) &icmpstat.IcmpInAddrMasks;
    case ICMPINADDRMASKREPS: return (u_char *) &icmpstat.IcmpInAddrMaskReps;
    case ICMPOUTMSGS: return (u_char *) &icmpstat.IcmpOutMsgs;
    case ICMPOUTERRORS: return (u_char *) &icmpstat.IcmpOutErrors;
    case ICMPOUTDESTUNREACHS: return (u_char *) &icmpstat.IcmpOutDestUnreachs;
    case ICMPOUTTIMEEXCDS: return (u_char *) &icmpstat.IcmpOutTimeExcds;
    case ICMPOUTPARMPROBS: return (u_char *) &icmpstat.IcmpOutParmProbs;
    case ICMPOUTSRCQUENCHS: return (u_char *) &icmpstat.IcmpOutSrcQuenchs;
    case ICMPOUTREDIRECTS: return (u_char *) &icmpstat.IcmpOutRedirects;
    case ICMPOUTECHOS: return (u_char *) &icmpstat.IcmpOutEchos;
    case ICMPOUTECHOREPS: return (u_char *) &icmpstat.IcmpOutEchoReps;
    case ICMPOUTTIMESTAMPS: return (u_char *) &icmpstat.IcmpOutTimestamps;
    case ICMPOUTTIMESTAMPREPS: return (u_char *)&icmpstat.IcmpOutTimestampReps;
    case ICMPOUTADDRMASKS: return (u_char *) &icmpstat.IcmpOutAddrMasks;
    case ICMPOUTADDRMASKREPS: return (u_char *) &icmpstat.IcmpOutAddrMaskReps;

    default:
      DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_icmp\n", vp->magic));
    }
    return NULL;

}

#endif /* linux */
#else /* solaris2 */

u_char *
var_icmp(struct variable *vp,
	 oid *name,
	 size_t *length,
	 int exact,
	 size_t *var_len,
	 WriteMethod **write_method)
{
    mib2_icmp_t icmpstat;

    if (header_icmp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return(NULL);

    /*
     *	Get the ICMP statistics from the kernel...
     */
    if (getMibstat(MIB_ICMP, &icmpstat, sizeof(mib2_icmp_t), GET_FIRST, &Get_everything, NULL) < 0)
      return (NULL);		/* Things are ugly ... */

    switch (vp->magic){
	case ICMPINMSGS:
      		long_return = icmpstat.icmpInMsgs;
      		break;
	case ICMPINERRORS:
      		long_return = icmpstat.icmpInErrors;
      		break;
	case ICMPINDESTUNREACHS:
      		long_return = icmpstat.icmpInDestUnreachs;
      		break;
	case ICMPINTIMEEXCDS:
      		long_return = icmpstat.icmpInTimeExcds;
      		break;
	case ICMPINPARMPROBS:
      		long_return = icmpstat.icmpInParmProbs;
      		break;
	case ICMPINSRCQUENCHS:
      		long_return = icmpstat.icmpInSrcQuenchs;
      		break;
	case ICMPINREDIRECTS:
      		long_return = icmpstat.icmpInRedirects;
      		break;
	case ICMPINECHOS:
      		long_return = icmpstat.icmpInEchos;
      		break;
	case ICMPINECHOREPS:
      		long_return = icmpstat.icmpInEchoReps;
      		break;
	case ICMPINTIMESTAMPS:
      		long_return = icmpstat.icmpInTimestamps;
      		break;
	case ICMPINTIMESTAMPREPS:
      		long_return = icmpstat.icmpInTimestampReps;
      		break;
	case ICMPINADDRMASKS:
      		long_return = icmpstat.icmpInAddrMasks;
      		break;
	case ICMPINADDRMASKREPS:
      		long_return = icmpstat.icmpInAddrMaskReps;
      		break;
	case ICMPOUTMSGS:
      		long_return = icmpstat.icmpOutMsgs;
      		break;
	case ICMPOUTERRORS:
      		long_return = icmpstat.icmpOutErrors;
      		break;
	case ICMPOUTDESTUNREACHS:
      		long_return = icmpstat.icmpOutDestUnreachs;
      		break;
	case ICMPOUTTIMEEXCDS:
      		long_return = icmpstat.icmpOutTimeExcds;
      		break;
	case ICMPOUTPARMPROBS:
      		long_return = icmpstat.icmpOutParmProbs;
      		break;
	case ICMPOUTSRCQUENCHS:
      		long_return = icmpstat.icmpOutSrcQuenchs;
      		break;
	case ICMPOUTREDIRECTS:
      		long_return = icmpstat.icmpOutRedirects;
      		break;
	case ICMPOUTECHOS:
      		long_return = icmpstat.icmpOutEchos;
      		break;
	case ICMPOUTECHOREPS:
      		long_return = icmpstat.icmpOutEchoReps;
      		break;
	case ICMPOUTTIMESTAMPS:
      		long_return = icmpstat.icmpOutTimestamps;
      		break;
	case ICMPOUTTIMESTAMPREPS:
      		long_return = icmpstat.icmpOutTimestampReps;
      		break;
	case ICMPOUTADDRMASKS:
      		long_return = icmpstat.icmpOutAddrMasks;
      		break;
	case ICMPOUTADDRMASKREPS:
      		long_return = icmpstat.icmpOutAddrMaskReps;
      		break;
	default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_icmp\n", vp->magic));
                return(NULL);
    }
    return ((u_char *) &long_return);
}
#endif /* solaris2 */


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/


#ifdef linux
/*
 * lucky days. since 1.1.16 the icmp statistics are avail by the proc
 * file-system.
 */

static void
linux_read_icmp_stat (struct icmp_mib *icmpstat)
{
  FILE *in = fopen ("/proc/net/snmp", "r");
  char line [1024];

  memset ((char *) icmpstat,(0), sizeof (*icmpstat));

  if (! in)
    return;

  while (line == fgets (line, sizeof(line), in))
    {
      if (26 == sscanf (line,
"Icmp: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
   &icmpstat->IcmpInMsgs, &icmpstat->IcmpInErrors, &icmpstat->IcmpInDestUnreachs, 
   &icmpstat->IcmpInTimeExcds, &icmpstat->IcmpInParmProbs, &icmpstat->IcmpInSrcQuenchs,
   &icmpstat->IcmpInRedirects, &icmpstat->IcmpInEchos, &icmpstat->IcmpInEchoReps, 
   &icmpstat->IcmpInTimestamps, &icmpstat->IcmpInTimestampReps, &icmpstat->IcmpInAddrMasks,
   &icmpstat->IcmpInAddrMaskReps, &icmpstat->IcmpOutMsgs, &icmpstat->IcmpOutErrors,
   &icmpstat->IcmpOutDestUnreachs, &icmpstat->IcmpOutTimeExcds, 
   &icmpstat->IcmpOutParmProbs, &icmpstat->IcmpOutSrcQuenchs, &icmpstat->IcmpOutRedirects,
   &icmpstat->IcmpOutEchos, &icmpstat->IcmpOutEchoReps, &icmpstat->IcmpOutTimestamps, 
   &icmpstat->IcmpOutTimestampReps, &icmpstat->IcmpOutAddrMasks,
   &icmpstat->IcmpOutAddrMaskReps))
	break;
    }
  fclose (in);
}

#endif /* linux */


