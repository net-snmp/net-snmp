/*
 *  IP MIB group implementation - ip.c
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
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
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

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "mibincl.h"

#ifdef solaris2
#include "kernel_sunos5.h"
#else
#include "kernel.h"
#endif

#include "system.h"
#include "asn1.h"
#include "snmp_debug.h"

#include "auto_nlist.h"

#ifdef MIB_IPCOUNTER_SYMBOL
#include <sys/mib.h>
#include <netinet/mib_kern.h>
#endif /* MIB_IPCOUNTER_SYMBOL */

/* #include "../common_header.h" */

#include "ip.h"
#include "interfaces.h"
#include "sysORTable.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef linux
static void linux_read_ip_stat (struct ip_mib *);
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

extern void init_routes (void);


/* define the structure we're going to ask the agent to register our
   information at */
struct variable4 ip_variables[] = {
    {IPFORWARDING, ASN_INTEGER, RONLY, var_ip, 1, {1 }},
    {IPDEFAULTTTL, ASN_INTEGER, RONLY, var_ip, 1, {2 }},
#ifndef sunV3
    {IPINRECEIVES, ASN_COUNTER, RONLY, var_ip, 1, {3 }},
#endif
    {IPINHDRERRORS, ASN_COUNTER, RONLY, var_ip, 1, {4 }},
#ifndef sunV3
    {IPINADDRERRORS, ASN_COUNTER, RONLY, var_ip, 1, {5 }},
    {IPFORWDATAGRAMS, ASN_COUNTER, RONLY, var_ip, 1, {6 }},
#endif
    {IPINUNKNOWNPROTOS, ASN_COUNTER, RONLY, var_ip, 1, {7 }},
#ifndef sunV3
    {IPINDISCARDS, ASN_COUNTER, RONLY, var_ip, 1, {8 }},
    {IPINDELIVERS, ASN_COUNTER, RONLY, var_ip, 1, {9 }},
#endif
    {IPOUTREQUESTS, ASN_COUNTER, RONLY, var_ip, 1, {10 }},
    {IPOUTDISCARDS, ASN_COUNTER, RONLY, var_ip, 1, {11 }},
    {IPOUTNOROUTES, ASN_COUNTER, RONLY, var_ip, 1, {12 }},
    {IPREASMTIMEOUT, ASN_INTEGER, RONLY, var_ip, 1, {13 }},
#ifndef sunV3
    {IPREASMREQDS, ASN_COUNTER, RONLY, var_ip, 1, {14 }},
    {IPREASMOKS, ASN_COUNTER, RONLY, var_ip, 1, {15 }},
    {IPREASMFAILS, ASN_COUNTER, RONLY, var_ip, 1, {16 }},
#endif
    {IPFRAGOKS, ASN_COUNTER, RONLY, var_ip, 1, {17 }},
    {IPFRAGFAILS, ASN_COUNTER, RONLY, var_ip, 1, {18 }},
    {IPFRAGCREATES, ASN_COUNTER, RONLY, var_ip, 1, {19 }},
    {IPADADDR, ASN_IPADDRESS, RONLY, var_ipAddrEntry, 3, {20, 1, 1}},
    {IPADIFINDEX, ASN_INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 2}},
#ifndef sunV3
    {IPADNETMASK, ASN_IPADDRESS, RONLY, var_ipAddrEntry, 3, {20, 1, 3}},
#endif
    {IPADBCASTADDR, ASN_INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 4}},
    {IPADREASMMAX, ASN_INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 5}},
    {IPROUTEDEST, ASN_IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 1}},
    {IPROUTEIFINDEX, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 2}},
    {IPROUTEMETRIC1, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 3}},
    {IPROUTEMETRIC2, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 4}},
    {IPROUTEMETRIC3, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 5}},
    {IPROUTEMETRIC4, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 6}},
    {IPROUTENEXTHOP, ASN_IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 7}},
    {IPROUTETYPE, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 8}},
    {IPROUTEPROTO, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 9}},
    {IPROUTEAGE, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 10}},
    {IPROUTEMASK, ASN_IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 11}},
    {IPROUTEMETRIC5, ASN_INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 12}},
    {IPROUTEINFO, ASN_OBJECT_ID, RONLY, var_ipRouteEntry, 3, {21, 1, 13}},
    {IPMEDIAIFINDEX, ASN_INTEGER, RONLY, var_atEntry, 3, {22, 1, 1}},
    {IPMEDIAPHYSADDRESS, ASN_OCTET_STR, RONLY, var_atEntry, 3, {22, 1, 2}},
    {IPMEDIANETADDRESS, ASN_IPADDRESS, RONLY, var_atEntry, 3, {22, 1, 3}},
    {IPMEDIATYPE, ASN_INTEGER, RONLY, var_atEntry, 3, {22, 1, 4}},
    {IPROUTEDISCARDS, ASN_COUNTER, RONLY, var_ip, 1, {23 }}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath, and the OID of the MIB module */
oid ip_variables_oid[] = { SNMP_OID_MIB2,4 };
oid ip_module_oid[]    = { SNMP_OID_MIB2,4 };
oid ip_module_oid_len  = sizeof(ip_module_oid) / sizeof( oid );
int ip_module_count    = 0;   /* Need to liaise with icmp.c */

void init_ip(void)
{
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/ip", ip_variables, variable4, ip_variables_oid);
  if ( ++ip_module_count == 2 )
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


/*
  header_ip(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/

static int
header_ip(struct variable *vp,
	  oid *name,
	  size_t *length,
	  int exact,
	  size_t *var_len,
	  WriteMethod **write_method)
{
#define IP_NAME_LENGTH	8
    oid newname[MAX_OID_LEN];
    int result;

    DEBUGMSGTL(("mibII/ip", "var_ip: "));
    DEBUGMSGOID(("mibII/ip", name, *length));
    DEBUGMSG(("mibII/ip"," %d\n", exact));

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[IP_NAME_LENGTH] = 0;
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



#if !defined(CAN_USE_SYSCTL) || !defined(IPCTL_STATS)
#ifndef solaris2
#ifndef linux
#ifndef HAVE_SYS_TCPIPSTATS_H

u_char *
var_ip(struct variable *vp,
       oid *name,
       size_t *length,
       int exact,
       size_t *var_len,
       WriteMethod **write_method)
{
    static struct ipstat ipstat;
#ifdef MIB_IPCOUNTER_SYMBOL
    static	counter MIB_ipcounter[MIB_ipMAXCTR+1];
#endif
    int i;

    if (header_ip(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *	Get the IP statistics from the kernel...
     */
#ifdef IPSTAT_SYMBOL
    auto_nlist(IPSTAT_SYMBOL, (char *)&ipstat, sizeof (ipstat));
#endif
#ifdef MIB_IPCOUNTER_SYMBOL
    auto_nlist(MIB_IPCOUNTER_SYMBOL, (char *)&MIB_ipcounter,
               (MIB_ipMAXCTR+1)*sizeof (counter));
#endif

    long_return = 0;
    switch (vp->magic){
	case IPFORWARDING:
#ifndef sparc	  
            auto_nlist(IP_FORWARDING_SYMBOL,(char *) &i, sizeof(i));
	    if (i) {
		long_return = 1;		/* GATEWAY */
	    } else {
		long_return = 2;	    /* HOST    */
	    }
#else /* sparc */
#if NO_DUMMY_VALUES
	    return NULL;
#endif
#endif /* sparc */

	    return (u_char *) &long_return;
	case IPDEFAULTTTL:
	    /*
	     *	Allow for a kernel w/o TCP.
	     */
	    if (!auto_nlist(TCP_TTL_SYMBOL, (char *) &long_return,
                            sizeof(long_return)))
#if NO_DUMMY_VALUES
	      return NULL;
#else
              long_return = 60;	    /* XXX */
#endif
#ifdef hpux
	    long_return = (u_char)long_return;
#endif
	    return (u_char *) &long_return;
	case IPINRECEIVES:
          long_return = ipstat.ips_total;
          return (u_char *) &long_return;
	case IPINHDRERRORS:
	    long_return = ipstat.ips_badsum + ipstat.ips_tooshort +
			  ipstat.ips_toosmall + ipstat.ips_badhlen +
			  ipstat.ips_badlen;
	    return (u_char *) &long_return;
	case IPINADDRERRORS:
          long_return = ipstat.ips_cantforward;
          return (u_char *) &long_return;

	case IPFORWDATAGRAMS:
          long_return = ipstat.ips_forward;
          return (u_char *) &long_return;

	case IPINUNKNOWNPROTOS:
#ifdef MIB_IPCOUNTER_SYMBOL
	    long_return = MIB_ipcounter[7];
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
#endif
	    return (u_char *) &long_return;
	case IPINDISCARDS:
#ifdef MIB_IPCOUNTER_SYMBOL
	    long_return = MIB_ipcounter[8];
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
#endif
	    return (u_char *) &long_return;
	case IPINDELIVERS:

	    long_return = ipstat.ips_total -
			 (ipstat.ips_badsum + ipstat.ips_tooshort +
			  ipstat.ips_toosmall + ipstat.ips_badhlen +
			  ipstat.ips_badlen);
	    return (u_char *) &long_return;

	case IPOUTREQUESTS:
#ifdef MIB_IPCOUNTER_SYMBOL
	    long_return = MIB_ipcounter[10];
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
#endif
	    return (u_char *) &long_return;
	case IPOUTDISCARDS:
#ifdef MIB_IPCOUNTER_SYMBOL
	    long_return = MIB_ipcounter[11];
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
#endif
	    return (u_char *) &long_return;
	case IPOUTNOROUTES:
          long_return = ipstat.ips_cantforward;
          return (u_char *) &long_return;

	case IPREASMTIMEOUT:
	    long_return = IPFRAGTTL;
	    return (u_char *) &long_return;
	case IPREASMREQDS:
          long_return = ipstat.ips_fragments;
          return (u_char *) &long_return;

	case IPREASMOKS:
#ifdef MIB_IPCOUNTER_SYMBOL
	    long_return = MIB_ipcounter[15];
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = ipstat.ips_fragments;		/* XXX */
		/*
		 * NB: This is the count of fragments received, rather than
		 *	"the number of IP datagrams successfully reassembled"
		 */
#endif
	    return (u_char *) &long_return;

	case IPREASMFAILS:
	    long_return = ipstat.ips_fragdropped + ipstat.ips_fragtimeout;
	    return (u_char *) &long_return;

	case IPFRAGOKS:
#ifdef MIB_IPCOUNTER_SYMBOL
	    long_return = MIB_ipcounter[17];
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
#endif
	    return (u_char *) &long_return;
	case IPFRAGFAILS:
#ifdef MIB_IPCOUNTER_SYMBOL
	    long_return = MIB_ipcounter[18];
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
#endif
	    return (u_char *) &long_return;
	case IPFRAGCREATES:
#ifdef MIB_IPCOUNTER_SYMBOL
	    long_return = MIB_ipcounter[19];
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
#endif
	    return (u_char *) &long_return;
	case IPROUTEDISCARDS:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    return (u_char *) &long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ip\n", vp->magic));
    }
    return NULL;
}

#else /* HAVE_SYS_TCPIPSTATS_H */

u_char *
var_ip(struct variable *vp,
       oid *name,
       size_t *length,
       int exact,
       size_t *var_len,
       WriteMethod **write_method)
{
    static struct kna tcpipstats;
    int i;

    if (header_ip(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *	Get the IP statistics from the kernel...
     */
    if (sysmp (MP_SAGET, MPSA_TCPIPSTATS, &tcpipstats, sizeof tcpipstats) == -1) {
	snmp_log_perror ("sysmp(MP_SAGET)(MPSA_TCPIPSTATS)");
    }
#define ipstat tcpipstats.ipstat

    long_return = 0;
    switch (vp->magic){
	case IPFORWARDING:
#if defined(HAVE_SYS_SYSCTL_H) && defined(CTL_NET)
	  {
	    int name[] = { CTL_NET, PF_INET, IPPROTO_IP, IPCTL_FORWARDING };
	    int result;
	    size_t result_size = sizeof (int);

	    if (sysctl (name, sizeof (name) / sizeof (int),
			&result, &result_size,
			0, 0) == -1)
	      {
	 snmp_log(LOG_ERR, "sysctl(CTL_NET,PF_NET,IPPROTO_IP,IPCTL_FORWARDING)\n");
	      }
	    else
	      {
		if (result) {
		  long_return = 1;		/* GATEWAY */
		} else {
		  long_return = 2;	    /* HOST    */
		}
	      }
	  }
#else /* not (HAVE_SYS_SYSCTL_H && CTL_NET) */
#ifndef sparc	  
            auto_nlist(IP_FORWARDING_SYMBOL,(char *) &i, sizeof(i));
	    if (i) {
		long_return = 1;		/* GATEWAY */
	    } else {
		long_return = 2;	    /* HOST    */
	    }
#endif /* sparc */
#endif /* not (HAVE_SYS_SYSCTL_H && CTL_NET) */

	    return (u_char *) &long_return;
	case IPDEFAULTTTL:
	    /*
	     *	Allow for a kernel w/o TCP.
	     */
	    if (!auto_nlist(TCP_TTL_SYMBOL,(char *) &long_return,
                            sizeof(long_return)))
#if NO_DUMMY_VALUES
	      return NULL;
#else
              long_return = 60;	    /* XXX */
#endif
	    return (u_char *) &long_return;
	case IPINRECEIVES:
          long_return = ipstat.ips_total;
          return (u_char *) &long_return;
	case IPINHDRERRORS:
	    long_return = ipstat.ips_badsum + ipstat.ips_tooshort +
			  ipstat.ips_toosmall + ipstat.ips_badhlen +
			  ipstat.ips_badlen;
	    return (u_char *) &long_return;
	case IPINADDRERRORS:
          long_return = ipstat.ips_cantforward;
          return (u_char *) &long_return;
	case IPFORWDATAGRAMS:
          long_return = ipstat.ips_forward;
          return (u_char *) &long_return;
	case IPINUNKNOWNPROTOS:
          long_return = ipstat.ips_noproto;
          return (u_char *) &long_return;
	case IPINDISCARDS:
          long_return = ipstat.ips_fragdropped;
          return (u_char *) &long_return;
	case IPINDELIVERS:
          long_return = ipstat.ips_delivered;
          return (u_char *) &long_return;
	case IPOUTREQUESTS:
          long_return = ipstat.ips_localout;
          return (u_char *) &long_return;
	case IPOUTDISCARDS:
          long_return = ipstat.ips_odropped;
          return (u_char *) &long_return;
	case IPOUTNOROUTES:
          long_return = ipstat.ips_noroute;
          return (u_char *) &long_return;
	case IPREASMTIMEOUT:
          long_return = ipstat.ips_fragtimeout;
          return (u_char *) &long_return;
	case IPREASMREQDS:
          long_return = ipstat.ips_fragments;
          return (u_char *) &long_return;
	case IPREASMOKS:
          long_return = ipstat.ips_reassembled;
          return (u_char *) &long_return;
	case IPREASMFAILS:
	    long_return = ipstat.ips_fragdropped + ipstat.ips_fragtimeout;
	    return (u_char *) &long_return;
	case IPFRAGOKS:
	    long_return = ipstat.ips_fragments
	      - (ipstat.ips_fragdropped + ipstat.ips_fragtimeout);
	    return (u_char *) &long_return;
	case IPFRAGFAILS:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    return (u_char *) &long_return;
	case IPFRAGCREATES:
          long_return = ipstat.ips_ofragments;
          return (u_char *) &long_return;
	case IPROUTEDISCARDS:
          long_return = ipstat.ips_noroute;
          return (u_char *) &long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ip\n", vp->magic));
    }
}

#endif /* HAVE_SYS_TCPIPSTATS_H */

#else /* linux */    

u_char *
var_ip(struct variable *vp,
       oid *name,
       size_t *length,
       int exact,
       size_t *var_len,
       WriteMethod **write_method)
{
    static struct ip_mib ipstat;

    if (header_ip(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    linux_read_ip_stat (&ipstat);

    switch (vp->magic){
	case IPFORWARDING: 
		/* valid values are 1 == yup, 2 == nope:
		 * a 0 is forbidden, so patch: */
		if (! ipstat.IpForwarding)
			ipstat.IpForwarding = 2;
		return (u_char *) &ipstat.IpForwarding;
	case IPDEFAULTTTL: return (u_char *) &ipstat.IpDefaultTTL;
	case IPINRECEIVES: return (u_char *) &ipstat.IpInReceives;
	case IPINHDRERRORS: return (u_char *) &ipstat.IpInHdrErrors;
	case IPINADDRERRORS: return (u_char *) &ipstat.IpInAddrErrors;
	case IPFORWDATAGRAMS: return (u_char *) &ipstat.IpForwDatagrams;
	case IPINUNKNOWNPROTOS: return (u_char *) &ipstat.IpInUnknownProtos;
	case IPINDISCARDS: return (u_char *) &ipstat.IpInDiscards;
	case IPINDELIVERS: return (u_char *) &ipstat.IpInDelivers;
	case IPOUTREQUESTS: return (u_char *) &ipstat.IpOutRequests;
	case IPOUTDISCARDS: return (u_char *) &ipstat.IpOutDiscards;
	case IPOUTNOROUTES: return (u_char *) &ipstat.IpOutNoRoutes;
	case IPREASMTIMEOUT: return (u_char *) &ipstat.IpReasmTimeout;
	case IPREASMREQDS: return (u_char *) &ipstat.IpReasmReqds;
	case IPREASMOKS: return (u_char *) &ipstat.IpReasmOKs;
	case IPREASMFAILS: return (u_char *) &ipstat.IpReasmFails;
	case IPFRAGOKS: return (u_char *) &ipstat.IpFragOKs;
	case IPFRAGFAILS: return (u_char *) &ipstat.IpFragFails;
	case IPFRAGCREATES: return (u_char *) &ipstat.IpFragCreates;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ip\n", vp->magic));
    }
    return NULL;
}
#endif /* linux */


#ifdef freebsd2
static void Address_Scan_Init (void);
static int Address_Scan_Next (short *, struct in_ifaddr *);
#endif


/*
  var_ipAddrEntry(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/

u_char *
var_ipAddrEntry(struct variable *vp,
		oid *name,
		size_t *length,
		int exact,
		size_t *var_len,
		WriteMethod **write_method)
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.20.1.?.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */
    oid			    lowest[14];
    oid			    current[14], *op;
    u_char		    *cp;
    int			    lowinterface=0;
    short                   interface;
    static struct in_ifaddr in_ifaddr;
#if !defined(linux) && !defined(sunV3)
    static struct in_ifaddr lowin_ifaddr;
#else
    static struct ifnet lowin_ifnet;
#endif
    static struct ifnet ifnet;

    /* fill in object part of name for current (less sizeof instance part) */

    memcpy( (char *)current,(char *)vp->name, (int)vp->namelen * sizeof(oid));

#ifndef freebsd2
    Interface_Scan_Init();
#else
    Address_Scan_Init();
#endif
    for (;;) {

#ifndef freebsd2
	if (Interface_Scan_Next(&interface, NULL, &ifnet, &in_ifaddr) == 0)
	    break;
#ifdef STRUCT_IFNET_HAS_IF_ADDRLIST
	if ( ifnet.if_addrlist == 0 )
	    continue;                   /* No address found for interface */
#endif
#else
	if (Address_Scan_Next(&interface, &in_ifaddr) == 0)
	    break;
#endif /* freebsd2 */
#if defined(linux) || defined(sunV3)
	cp = (u_char *)&(((struct sockaddr_in *) &(ifnet.if_addr))->sin_addr.s_addr);
#else
	cp = (u_char *)&(((struct sockaddr_in *) &(in_ifaddr.ia_addr))->sin_addr.s_addr);
#endif

	op = current + 10;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	if (exact){
	    if (snmp_oid_compare(current, 14, name, *length) == 0){
		memcpy( (char *)lowest,(char *)current, 14 * sizeof(oid));
		lowinterface = interface;
#if defined(linux) || defined(sunV3)
		lowin_ifnet = ifnet;
#else
		lowin_ifaddr = in_ifaddr;
#endif
		break;	/* no need to search further */
	    }
	} else {
	    if ((snmp_oid_compare(current, 14, name, *length) > 0) &&
		 (!lowinterface || (snmp_oid_compare(current, 14, lowest, 14) < 0))){
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, save this one as the "next" one.
		 */
		lowinterface = interface;
#if defined(linux) || defined(sunV3)
		lowin_ifnet = ifnet;
#else
		lowin_ifaddr = in_ifaddr;
#endif
		memcpy( (char *)lowest,(char *)current, 14 * sizeof(oid));
	    }
	}
    }

    if (!lowinterface) return(NULL);
    memcpy( (char *)name,(char *)lowest, 14 * sizeof(oid));
    *length = 14;
    *write_method = 0;
    *var_len = sizeof(long_return);
    switch(vp->magic){
	case IPADADDR:
#if defined(linux) || defined(sunV3)
            return(u_char *) &((struct sockaddr_in *) &lowin_ifnet.if_addr)->sin_addr.s_addr;
#else
	    return(u_char *) &((struct sockaddr_in *) &lowin_ifaddr.ia_addr)->sin_addr.s_addr;
#endif
	case IPADIFINDEX:
	    long_return = lowinterface;
	    return(u_char *) &long_return;
	case IPADNETMASK:
#ifndef sunV3
#ifdef linux
            return (u_char *)&((struct sockaddr_in *)&lowin_ifnet.ia_subnetmask)->sin_addr.s_addr;
#else
	    long_return = ntohl(lowin_ifaddr.ia_subnetmask);
	    return(u_char *) &long_return;
#endif
#endif
	case IPADBCASTADDR:
	    
#if defined(linux) || defined(sunV3)
	    long_return = ntohl(((struct sockaddr_in *) &lowin_ifnet.ifu_broadaddr)->sin_addr.s_addr) & 1;
#else
	    long_return = ntohl(((struct sockaddr_in *) &lowin_ifaddr.ia_broadaddr)->sin_addr.s_addr) & 1;
#endif
	    return(u_char *) &long_return;	   
	case IPADREASMMAX:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = -1;
	    return(u_char *) &long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ipAddrEntry\n", vp->magic));
    }
    return NULL;
}

#ifdef freebsd2
static struct in_ifaddr *in_ifaddraddr;

static void
Address_Scan_Init (void)
{
    auto_nlist(IFADDR_SYMBOL, (char *)&in_ifaddraddr, sizeof(in_ifaddraddr));
}

/* NB: Index is the number of the corresponding interface, not of the address */
static int Address_Scan_Next(Index, Retin_ifaddr)
short *Index;
struct in_ifaddr *Retin_ifaddr;
{
      struct in_ifaddr in_ifaddr;
      struct ifnet ifnet,*ifnetaddr;  /* NOTA: same name as another one */
      short iindex=1;

      while (in_ifaddraddr) {
          /*
           *      Get the "in_ifaddr" structure
           */
          klookup((unsigned long)in_ifaddraddr, (char *)&in_ifaddr, sizeof in_ifaddr);
          in_ifaddraddr = in_ifaddr.ia_next;

          if (Retin_ifaddr)
              *Retin_ifaddr = in_ifaddr;

	  /*
	   * Now, more difficult, find the index of the interface to which
	   * this address belongs
	   */

	  auto_nlist(IFNET_SYMBOL, (char *)&ifnetaddr, sizeof(ifnetaddr));
	  while (ifnetaddr && ifnetaddr != in_ifaddr.ia_ifp) {
	      klookup((unsigned long)ifnetaddr, (char *)&ifnet, sizeof ifnet);
	      ifnetaddr = ifnet.if_next;
	      iindex++;
	  }

	  /* XXX - might not find it? */

	  if (Index)
                  *Index = iindex;

          return(1);  /* DONE */
      }
      return(0);          /* EOF */
}

#endif /* freebsd2 */

#else /* solaris2 */

u_char *
var_ip(struct variable *vp,
		oid *name,
		size_t *length,
		int exact,
		size_t *var_len,
		WriteMethod **write_method)
{
    mib2_ip_t ipstat;
    u_char *ret = (u_char *)&long_return;	/* Successful completion */

    if (header_ip(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return(NULL);

    /*
     *	Get the IP statistics from the kernel...
     */
    if (getMibstat(MIB_IP, &ipstat, sizeof(mib2_ip_t), GET_FIRST, &Get_everything, NULL) < 0)
      return (NULL);		/* Things are ugly ... */
    
    switch (vp->magic){
	case IPFORWARDING:
	    long_return = ipstat.ipForwarding;
      	    break;
	case IPDEFAULTTTL:
	    long_return = ipstat.ipDefaultTTL;
      	    break;
	case IPINRECEIVES:
	    long_return = ipstat.ipInReceives;      
      	    break;
	case IPINHDRERRORS:
	    long_return = ipstat.ipInHdrErrors;	    
      	    break;
	case IPINADDRERRORS:
	    long_return = ipstat.ipInAddrErrors;	    
      	    break;
	case IPFORWDATAGRAMS:
	    long_return = ipstat.ipForwDatagrams;	    
      	    break;
	case IPINUNKNOWNPROTOS:
	    long_return = ipstat.ipInUnknownProtos;	    
      	    break;
	case IPINDISCARDS:
	    long_return = ipstat.ipInDiscards;	    
      	    break;
	case IPINDELIVERS:
	    long_return = ipstat.ipInDelivers;
      	    break;
	case IPOUTREQUESTS:
	    long_return = ipstat.ipOutRequests;	    
      	    break;
	case IPOUTDISCARDS:
	    long_return = ipstat.ipOutDiscards;	    
      	    break;
	case IPOUTNOROUTES:
	    long_return = ipstat.ipOutNoRoutes;	    
      	    break;
	case IPREASMTIMEOUT:
	    long_return = ipstat.ipReasmTimeout;	    
      	    break;
	case IPREASMREQDS:
	    long_return = ipstat.ipReasmReqds;	    
      	    break;
	case IPREASMOKS:
	    long_return = ipstat.ipReasmOKs;	    
      	    break;
	case IPREASMFAILS:
	    long_return = ipstat.ipReasmFails;	    
      	    break;
	case IPFRAGOKS:
	    long_return = ipstat.ipFragOKs;	    
      	    break;
	case IPFRAGFAILS:
	    long_return = ipstat.ipFragFails;	    
      	    break;
	case IPFRAGCREATES:
	    long_return = ipstat.ipFragCreates;	    
      	    break;
	default:
	    ret = NULL;		/* Failure */
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ip\n", vp->magic));
    }
    return (ret);
}


static int
IP_Cmp(void *addr, void *ep)
{
  if (((mib2_ipAddrEntry_t *)ep)->ipAdEntAddr ==
      *(IpAddress *)addr)
    return (0);
  else
    return (1);
}

u_char *
var_ipAddrEntry(struct variable *vp,
		oid *name,
		size_t *length,
		int exact,
		size_t *var_len,
		WriteMethod **write_method)
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.20.1.?.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */
#define IP_ADDRNAME_LENGTH	14
#define IP_ADDRINDEX_OFF	10
    oid			    lowest[IP_ADDRNAME_LENGTH];
    oid			    current[IP_ADDRNAME_LENGTH], *op;
    u_char		    *cp;
    IpAddress		    NextAddr;
    mib2_ipAddrEntry_t	    entry, Lowentry;
    int			    Found = 0;
    req_e		    req_type;
    
    /* fill in object part of name for current (less sizeof instance part) */

    DEBUGMSGTL(("mibII/ip", "var_ipAddrEntry: "));
    DEBUGMSGOID(("mibII/ip", name, *length));
    DEBUGMSG(("mibII/ip"," %d\n", exact));

    memset (&Lowentry, 0, sizeof (Lowentry));
    memcpy( (char *)current,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    if (*length == IP_ADDRNAME_LENGTH) /* Assume that the input name is the lowest */
      memcpy( (char *)lowest,(char *)name, IP_ADDRNAME_LENGTH * sizeof(oid));
    for (NextAddr = (u_long)-1, req_type = GET_FIRST;
	 ;
	 NextAddr = entry.ipAdEntAddr, req_type = GET_NEXT) {
      if (getMibstat(MIB_IP_ADDR, &entry, sizeof(mib2_ipAddrEntry_t),
		     req_type, &IP_Cmp, &NextAddr) != 0)
	break;
      COPY_IPADDR(cp, (u_char *)&entry.ipAdEntAddr, op, current + IP_ADDRINDEX_OFF);
      if (exact){
	if (snmp_oid_compare(current, IP_ADDRNAME_LENGTH, name, *length) == 0){
	  memcpy( (char *)lowest,(char *)current, IP_ADDRNAME_LENGTH * sizeof(oid));
	  Lowentry = entry;
	  Found++;
	  break;	/* no need to search further */
	}
      } else {
	if ((snmp_oid_compare(current, IP_ADDRNAME_LENGTH, name, *length) > 0) 
	    && (((NextAddr == (u_long)-1))
		|| (snmp_oid_compare(current, IP_ADDRNAME_LENGTH, lowest, IP_ADDRNAME_LENGTH) < 0)
		|| (snmp_oid_compare(name, *length, lowest, IP_ADDRNAME_LENGTH) == 0))){
	  /*
	   * if new one is greater than input and closer to input than
	   * previous lowest, and is not equal to it, save this one as the "next" one.
	   */
	  Lowentry = entry;
	  Found++;
	  memcpy( (char *)lowest,(char *)current, IP_ADDRNAME_LENGTH * sizeof(oid));
	}
      }
    }
    DEBUGMSGTL(("mibII/ip", "... Found = %d\n", Found));
    if (Found == 0)
      return(NULL);
    memcpy( (char *)name,(char *)lowest, IP_ADDRNAME_LENGTH * sizeof(oid));
    *length = IP_ADDRNAME_LENGTH;
    *write_method = 0;
    *var_len = sizeof(long_return);
    switch(vp->magic){
	case IPADADDR:
      	    long_return = Lowentry.ipAdEntAddr;
	    return(u_char *) &long_return;
	case IPADIFINDEX:
	    long_return = Interface_Index_By_Name(Lowentry.ipAdEntIfIndex.o_bytes,
						  Lowentry.ipAdEntIfIndex.o_length);
	    return(u_char *) &long_return;
	case IPADNETMASK:
	    long_return = Lowentry.ipAdEntNetMask;
	    return(u_char *) &long_return;
	case IPADBCASTADDR:
	    long_return = Lowentry.ipAdEntBcastAddr;
	    return(u_char *) &long_return;	   
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ipAddrEntry\n", vp->magic));
    }
    return NULL;
}

#endif /* solaris2 */



	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/



#ifdef linux
/*
 * lucky days. since 1.1.16 the ip statistics are avail by the proc
 * file-system.
 */

static void
linux_read_ip_stat (struct ip_mib *ipstat)
{
  FILE *in = fopen ("/proc/net/snmp", "r");
  char line [1024];

  memset ((char *) ipstat,(0), sizeof (*ipstat));

  if (! in)
    return;

  while (line == fgets (line, sizeof(line), in))
    {
      if (19 == sscanf (line,   
"Ip: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
     &ipstat->IpForwarding, &ipstat->IpDefaultTTL, &ipstat->IpInReceives, 
     &ipstat->IpInHdrErrors, &ipstat->IpInAddrErrors, &ipstat->IpForwDatagrams, 
     &ipstat->IpInUnknownProtos, &ipstat->IpInDiscards, &ipstat->IpInDelivers, 
     &ipstat->IpOutRequests, &ipstat->IpOutDiscards, &ipstat->IpOutNoRoutes, 
     &ipstat->IpReasmTimeout, &ipstat->IpReasmReqds, &ipstat->IpReasmOKs, 
     &ipstat->IpReasmFails, &ipstat->IpFragOKs, &ipstat->IpFragFails, 
     &ipstat->IpFragCreates))
	break;
    }
  fclose (in);
} /* end of linux_read_ip_stat */
#endif /* linux */

#else /* CAN_USE_SYSCTL && IPCTL_STATS */

u_char *
var_ip(struct variable *vp,
       oid *name,
       size_t *length,
       int exact,
       size_t *var_len,
       WriteMethod **write_method)
{
	struct ipstat ipstat;
	int i;
	size_t len;
	static int sname[4] = { CTL_NET, PF_INET, IPPROTO_IP, 0 };

	if (header_ip(vp, name, length, exact, var_len, write_method)
	    == MATCH_FAILED)
		return NULL;

	/*
	 *	Get the IP statistics from the kernel...
	 */
	if (!(vp->magic == IPFORWARDING || vp->magic == IPDEFAULTTTL)) {
		len = sizeof ipstat;
		sname[3] = IPCTL_STATS;
		if (sysctl(sname, 4, &ipstat, &len, 0, 0) < 0)
			return NULL;
	}

	switch (vp->magic) {
	case IPFORWARDING:
		len = sizeof i;
		sname[3] = IPCTL_FORWARDING;
		if (sysctl(sname, 4, &i, &len, 0, 0) < 0)
			return NULL;
		if (i) {
			long_return = 1; /* GATEWAY */
		} else {
			long_return = 2; /* HOST    */
		}
		return (u_char *) &long_return;

	case IPDEFAULTTTL:
		len = sizeof i;
		sname[3] = IPCTL_DEFTTL;
		if (sysctl(sname, 4, &i, &len, 0, 0) < 0)
			return NULL;
		long_return = i;
		return (u_char *) &long_return;

	case IPINRECEIVES:
		long_return = ipstat.ips_total;
		return (u_char *) &long_return;

	case IPINHDRERRORS:
		long_return = ipstat.ips_badsum + ipstat.ips_tooshort +
			ipstat.ips_toosmall + ipstat.ips_badhlen +
			ipstat.ips_badlen;
		return (u_char *) &long_return;

	case IPINADDRERRORS:
		long_return = ipstat.ips_cantforward;
		return (u_char *) &long_return;

	case IPFORWDATAGRAMS:
		long_return = ipstat.ips_forward;
		return (u_char *) &long_return;

	case IPINUNKNOWNPROTOS:
		long_return = ipstat.ips_noproto;
		return (u_char *) &long_return;

	case IPINDISCARDS:
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = 0;
		return (u_char *) &long_return;

	case IPINDELIVERS:
		long_return = ipstat.ips_delivered;
		return (u_char *) &long_return;

	case IPOUTREQUESTS:
		long_return = ipstat.ips_localout;
		return (u_char *) &long_return;

	case IPOUTDISCARDS:
		long_return = ipstat.ips_odropped;
		return (u_char *) &long_return;

	case IPOUTNOROUTES:
		long_return = ipstat.ips_cantforward;
		return (u_char *) &long_return;

	case IPREASMTIMEOUT:
		long_return = IPFRAGTTL;
		return (u_char *) &long_return;

	case IPREASMREQDS:
		long_return = ipstat.ips_fragments;
		return (u_char *) &long_return;

	case IPREASMOKS:
		long_return = ipstat.ips_reassembled;
		return (u_char *) &long_return;

	case IPREASMFAILS:
		long_return = ipstat.ips_fragdropped + ipstat.ips_fragtimeout;
		return (u_char *) &long_return;

	case IPFRAGOKS:
		long_return = ipstat.ips_fragmented;
		return (u_char *) &long_return;

	case IPFRAGFAILS:
		long_return = ipstat.ips_cantfrag;
		return (u_char *) &long_return;

	case IPFRAGCREATES:
		long_return = ipstat.ips_ofragments;
		return (u_char *) &long_return;

	case IPROUTEDISCARDS:
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = 0;
		return (u_char *) &long_return;

	default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ip\n", vp->magic));
	}
	return NULL;
}

/*
 * Ideally, this would be combined with the code in interfaces.c.
 * Even separate, it's still better than what went before.
 */
struct iflist {
	int flags;
	int index;
	struct in_addr addr;
	struct in_addr mask;
	struct in_addr bcast;
};
static struct iflist *ifs;
static int nifs;

static void
get_iflist(void)
{
	int naddrs, bit;
	static int mib[6] 
		= { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_IFLIST, 0 };
	char *cp, *ifbuf;
	size_t len;
	struct rt_msghdr *rtm;
	struct if_msghdr *ifm;
	struct ifa_msghdr *ifam;
	struct sockaddr *sa;
	int flags;

	naddrs = 0;
	if (ifs)
		free(ifs);
	ifs = 0;
	nifs = 0;
	len = 0;
	if (sysctl(mib, 6, 0, &len, 0, 0) < 0)
		return;

	ifbuf = malloc(len);
	if (ifbuf == 0)
		return;
	if (sysctl(mib, 6, ifbuf, &len, 0, 0) < 0) {
		syslog(LOG_WARNING, "sysctl net-route-iflist: %m");
		free(ifbuf);
		return;
	}

loop:
	cp = ifbuf;
	while (cp < &ifbuf[len]) {
		int gotaddr;

		gotaddr = 0;
		rtm = (struct rt_msghdr *)cp;
		if (rtm->rtm_version != RTM_VERSION 
		    || rtm->rtm_type != RTM_IFINFO) {
			free(ifs);
			ifs = 0;
			nifs = 0;
			free(ifbuf);
			return;
		}
		ifm = (struct if_msghdr *)rtm;
		flags = ifm->ifm_flags;
		cp += ifm->ifm_msglen;
		rtm = (struct rt_msghdr *)cp;
		while (cp < &ifbuf[len] && rtm->rtm_type == RTM_NEWADDR) {
			ifam = (struct ifa_msghdr *)rtm;
			cp += sizeof(*ifam);
/* from route.c */
#define ROUND(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
			for (bit = 1; bit && cp < &ifbuf[len]; bit <<= 1) {
				if (!(ifam->ifam_addrs & bit))
					continue;
				sa = (struct sockaddr *)cp;
				cp += ROUND(sa->sa_len);
				
				/*
				 * Netmasks are returned as bit
				 * strings of type AF_UNSPEC.  The
				 * others are pretty ok.
				 */
				if (bit == RTA_IFA) {
#define satosin(sa) ((struct sockaddr_in *)(sa))
					if (ifs) {
						ifs[naddrs].addr 
							=satosin(sa)->sin_addr;
						ifs[naddrs].index
							= ifam->ifam_index;
						ifs[naddrs].flags = flags;
					}
					gotaddr = 1;
				} else if (bit == RTA_NETMASK) {
					if (ifs)
						ifs[naddrs].mask 
							=satosin(sa)->sin_addr;
				} else if (bit == RTA_BRD) {
					if (ifs)
						ifs[naddrs].bcast 
							=satosin(sa)->sin_addr;
				}
			}
			if (gotaddr)
				naddrs++;
			cp = (char *)rtm + rtm->rtm_msglen;
			rtm = (struct rt_msghdr *)cp;
		}
	}
	if (ifs) {
		nifs = naddrs;
		free(ifbuf);
		return;
	}
	ifs = malloc(naddrs * sizeof(*ifs));
	if (ifs == 0) {
		free(ifbuf);
		return;
	}
	naddrs = 0;
	goto loop;
}

u_char *
var_ipAddrEntry(struct variable *vp,
		oid *name,
		size_t *length,
		int exact,
		size_t *var_len,
		WriteMethod **write_method)
{
	/*
	 * object identifier is of form:
	 * 1.3.6.1.2.1.4.20.1.?.A.B.C.D,  where A.B.C.D is IP address.
	 * IPADDR starts at offset 10.
	 */
	oid lowest[14];
	oid current[14], *op;
	u_char *cp;
	int lowinterface = -1;
	int i, interface;

	/* fill in object part of name for current (less sizeof instance part) */
	memcpy(current, vp->name, (int)vp->namelen * sizeof(oid));

	/*
	 * Get interface table from kernel.
	 */
	get_iflist();

	for (i = 0; i < nifs; i++) {
		op = &current[10];
		cp = (u_char *)&ifs[i].addr;
		*op++ = *cp++;
		*op++ = *cp++;
		*op++ = *cp++;
		*op++ = *cp++;
		if (exact) {
			if (snmp_oid_compare(current, 14, name, *length) == 0) {
				memcpy(lowest, current, 14 * sizeof(oid));
				lowinterface = i;
				break;	/* no need to search further */
			}
		} else {
			if ((snmp_oid_compare(current, 14, name, *length) > 0) &&
			    (lowinterface < 0 
			     || (snmp_oid_compare(current, 14, lowest, 14) < 0))) {
				/*
				 * if new one is greater than input
				 * and closer to input than previous
				 * lowest, save this one as the "next"
				 * one.  
				 */
				lowinterface = i;
				memcpy(lowest, current, 14 * sizeof(oid));
			}
		}
	}

	if (lowinterface < 0)
		return NULL;
	i = lowinterface;
	memcpy(name, lowest, 14 * sizeof(oid));
	*length = 14;
	*write_method = 0;
	*var_len = sizeof(long_return);
	switch (vp->magic) {
	case IPADADDR:
		long_return = ifs[i].addr.s_addr;
		return (u_char *)&long_return;

	case IPADIFINDEX:
		long_return = ifs[i].index;
		return (u_char *)&long_return;

	case IPADNETMASK:
		long_return = ifs[i].mask.s_addr;
		return (u_char *)&long_return;

	case IPADBCASTADDR:
		long_return = ntohl(ifs[i].bcast.s_addr) & 1;
		return (u_char *)&long_return;	   

	case IPADREASMMAX:
#if NO_DUMMY_VALUES
		return NULL;
#endif
		long_return = -1;
		return (u_char *)&long_return;

	default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ipAddrEntry\n", vp->magic));
	}
	return NULL;
}

#endif /* CAN_USE_SYSCTL && IPCTL_STATS */
