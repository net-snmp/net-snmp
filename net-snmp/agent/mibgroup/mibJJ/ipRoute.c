/*
 * ipRoute.c - handle the IP Routing table
 *
 *
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University
	Copyright 1989	TGV, Incorporated

		      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU and TGV not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU AND TGV DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU OR TGV BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/
/*
 * additions, fixes and enhancements for Linux by Erik Schoenfelder
 * (schoenfr@ibr.cs.tu-bs.de) 1994/1995.
 * Linux additions taken from CMU to UCD stack by Jennifer Bray of Origin
 * (jbray@origin-at.co.uk) 1997
 * Support for system({CTL_NET,PF_ROUTE,...) by Simon Leinen
 * (simon@switch.ch) 1997
 */

#include <config.h>
#include "mibincl.h"
#define GATEWAY			/* MultiNet is always configured this way! */
#include <stdio.h>
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/socket.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif
#if HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#if HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif
#include <net/if.h>
#ifdef HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
#if HAVE_SYS_HASHING_H
#include <sys/hashing.h>
#endif
#if HAVE_NETINET_IN_VAR_H
#include <netinet/in_var.h>
#endif
#define KERNEL		/* to get routehash and RTHASHSIZ */
#if HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#include <net/route.h>
#undef	KERNEL

#ifndef NULL
#define NULL 0
#endif
#if HAVE_KVM_OPENFILES
#include <fcntl.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif

#if HAVE_NLIST_H
#include <nlist.h>
#endif
#include "auto_nlist.h"
#if solaris2
#include "kernel_sunos5.h"
#endif
#ifdef hpux
#include <sys/mib.h>
#include "kernel_hpux.h"
#endif
 
#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif



#include "ipRoute.h"
#include "kernel.h"
#include "interfaces.h"
#include "struct.h"
#include "util_funcs.h"

#ifndef  MIN
#define  MIN(a,b)                     (((a) < (b)) ? (a) : (b))
#endif

#ifndef ROUTE_CACHE_TIMEOUT
#define ROUTE_CACHE_TIMEOUT MIB_STATS_CACHE_TIMEOUT
#endif

mib_table_t route_table;

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef hpux
#define ROUTE_TYPE	mib_ipRouteEnt
#define RT_ADDRESS_FIELD	Dest
#define RT_GATEWAY_FIELD	NextHop
#define RT_NETMASK_FIELD	Mask
#define RT_INDEX_FIELD		IfIndex

#define USES_SNMP_DESIGNED_ROUTE_STRUCT
#undef  SOCKADDR
#define SOCKADDR(x)	x
#endif

#ifdef CAN_USE_SYSCTL
struct snmprt {
    struct rt_msghdr	hdr;
    struct in_addr	rt_dst;
    struct in_addr	rt_gateway;
    struct in_addr	rt_genmask;
    int			index;
    struct in_addr	ifa;
};
#define ROUTE_TYPE	struct snmprt
#define RT_ADDRESS_FIELD	rt_dst
#define RT_GATEWAY_FIELD	rt_gateway
#define RT_NETMASK_FIELD	rt_genmask
#define RT_FLAGS_FIELD		hdr.rtm_flags
#define RT_INDEX_FIELD		index
#endif

#ifdef linux
#define ROUTE_TYPE	struct rtentry
#define RT_ADDRESS_FIELD	rt_dst
#define RT_GATEWAY_FIELD	rt_gateway
#define RT_FLAGS_FIELD		rt_flags
#define RT_NETMASK_FIELD	rt_genmask
#define RT_INDEX_FIELD		rt_window	/* nick unused field */
#endif

#ifndef ROUTE_TYPE
#define ROUTE_TYPE	struct rtentry
#ifndef STRUCT_RTENTRY_HAS_RT_DST
#define rt_dst rt_nodes->rn_key
#endif
#define RT_ADDRESS_FIELD	rt_dst
#define RT_GATEWAY_FIELD	rt_gateway
#define RT_FLAGS_FIELD		rt_flags
#define RT_NETMASK_FIELD	rt_subnetmask
#define RT_INDEX_FIELD		rt_use		/* nick unused field */
#endif

/* extern WriteMethod *write_rte; */
int Route_Scan_Reload ( mib_table_t );
int IP_Cmp_Route(const void *, const void *);
ROUTE_TYPE* search_route(oid* idx, int idx_len, int exact);

	/*********************
	 *
	 *  Initialisation
	 *
	 *********************/

struct variable2 ipRoute_variables[] = {
    {IPROUTEDEST,  ASN_IPADDRESS, RONLY, var_ipRouteEntry, 1, {1}},
    {IPROUTEIFINDEX, ASN_INTEGER, RONLY, var_ipRouteEntry, 1, {2}},
    {IPROUTEMETRIC1, ASN_INTEGER, RONLY, var_ipRouteEntry, 1, {3}},
    {IPROUTEMETRIC2, ASN_INTEGER, RONLY, var_ipRouteEntry, 1, {4}},
    {IPROUTEMETRIC3, ASN_INTEGER, RONLY, var_ipRouteEntry, 1, {5}},
    {IPROUTEMETRIC4, ASN_INTEGER, RONLY, var_ipRouteEntry, 1, {6}},
    {IPROUTENEXTHOP, ASN_IPADDRESS, RONLY, var_ipRouteEntry, 1, {7}},
    {IPROUTETYPE,    ASN_INTEGER, RONLY, var_ipRouteEntry, 1, {8}},
    {IPROUTEPROTO,   ASN_INTEGER, RONLY, var_ipRouteEntry, 1, {9}},
    {IPROUTEAGE,     ASN_INTEGER, RONLY, var_ipRouteEntry, 1, {10}},
    {IPROUTEMASK,  ASN_IPADDRESS, RONLY, var_ipRouteEntry, 1, {11}},
    {IPROUTEMETRIC5, ASN_INTEGER, RONLY, var_ipRouteEntry, 1, {12}},
    {IPROUTEINFO,  ASN_OBJECT_ID, RONLY, var_ipRouteEntry, 1, {13}}
};
oid ipRoute_variables_oid[] = { SNMP_OID_MIB2,4,21,1 };

void init_ipRoute( void )
{
    REGISTER_MIB("mibII/ipRoute", ipRoute_variables, variable2, ipRoute_variables_oid);
    route_table = Initialise_Table( sizeof( ROUTE_TYPE ),
			ROUTE_CACHE_TIMEOUT,
			Route_Scan_Reload, IP_Cmp_Route);
}

	/*********************
	 *
	 *  Main variable handling routines
	 *
	 *********************/




/*
  var_ipRouteEntry(...
  Arguments:
  vp	        IN      - pointer to variable entry that points here
  name          IN/OUT  - IN/name requested, OUT/name found
  length        IN/OUT  - length of IN/OUT oid's 
  exact         IN      - TRUE if an exact match was requested
  var_len       OUT     - length of variable or 0 if function returned
  write_method  out     - pointer to function to set variable, otherwise 0
*/
u_char *
var_ipRouteEntry(struct variable *vp,
		 oid *name,
		 size_t *length,
		 int exact,
		 size_t *var_len,
		 WriteMethod **write_method)
{
    int i, idx;
    oid newname[MAX_OID_LEN], *op;
    u_char *cp;
    ROUTE_TYPE* routeEntry;

		/*
		 * Check the name given in the request,
		 *  and indentify the index part of it
		 */
    switch (snmp_oid_compare(name, MIN(*length, vp->namelen),
			     vp->name, vp->namelen)) {

	case -1:	/* name given is earlier than this table */
		if ( exact )
		    return NULL;
		op = NULL;
		i = 0;
		break;

	case 0:		/* name given matches this table */
		op = &name[vp->namelen];
		i  = *length - vp->namelen;
		break;

	case 1:		/* name given is later than this table */
		return NULL;

	default:	/* Can't happen */
		return NULL;
    }
    

		/*
		 *  Search for the relevant route entry,
		 *   either the index just identified,
		 *   or the next one, depending on whether
		 *   this is an exact match or not.
		 */
    routeEntry = search_route( op, i, exact );
    if ( !routeEntry )
	return NULL;

		/*
		 * We've found something we can use.
		 *  Update the 'newname' with the relevant index
		 */
    memcpy((char *)newname, (char *)vp->name, (int)vp->namelen * sizeof(oid));
    cp = (u_char *)&(SOCKADDR(routeEntry->RT_ADDRESS_FIELD));
    op = newname + vp->namelen;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
   

    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 4) * sizeof(oid));
    *length = vp->namelen + 4;
    /**write_method = write_rte;*/
    *var_len = sizeof(long_return);


    switch(vp->magic){
	case IPROUTEDEST:
	    return (u_char *)&(SOCKADDR(routeEntry->RT_ADDRESS_FIELD));

	case IPROUTEIFINDEX:
	    long_return = routeEntry->RT_INDEX_FIELD;
	    return (u_char *)&long_return;

	case IPROUTEMETRIC1:
#ifdef USES_SNMP_DESIGNED_ROUTE_STRUCT
	    long_return = routeEntry->Metric1;
#else
	    long_return = (routeEntry->RT_FLAGS_FIELD & RTF_GATEWAY) ? 1 : 0;
#endif
	    return (u_char *)&long_return;

	case IPROUTEMETRIC2:
#ifdef USES_SNMP_DESIGNED_ROUTE_STRUCT
	    long_return = routeEntry->Metric2;
#else
	    long_return = -1;		/* the defined 'unused' value */
#endif
	    return (u_char *)&long_return;

	case IPROUTEMETRIC3:
#ifdef USES_SNMP_DESIGNED_ROUTE_STRUCT
	    long_return = routeEntry->Metric3;
#else
	    long_return = -1;		/* the defined 'unused' value */
#endif
	    return (u_char *)&long_return;

	case IPROUTEMETRIC4:
#ifdef USES_SNMP_DESIGNED_ROUTE_STRUCT
	    long_return = routeEntry->Metric4;
#else
	    long_return = -1;		/* the defined 'unused' value */
#endif
	    return (u_char *)&long_return;

	case IPROUTEMETRIC5:
	    long_return = -1;		/* the defined 'unused' value */
	    return (u_char *)&long_return;
	    
	case IPROUTENEXTHOP:
	    return (u_char *)&(SOCKADDR(routeEntry->RT_GATEWAY_FIELD));

	case IPROUTETYPE:
#ifdef USES_SNMP_DESIGNED_ROUTE_STRUCT
	    long_return = routeEntry->Type;
#else
	    long_return = (routeEntry->RT_FLAGS_FIELD & RTF_GATEWAY)
	      ? 4		/* indirect */
	      : 3;		/*   direct */
#endif
	    return (u_char *)&long_return;

	case IPROUTEPROTO:
#ifdef USES_SNMP_DESIGNED_ROUTE_STRUCT
	    long_return = routeEntry->Proto;
#else
	    long_return = (routeEntry->RT_FLAGS_FIELD & RTF_DYNAMIC)
	      ? 4		/*  ICMP */
	      : 2;		/* local */
#endif
	    return (u_char *)&long_return;

	case IPROUTEAGE:
#ifdef USES_SNMP_DESIGNED_ROUTE_STRUCT
	    long_return = routeEntry->Age;
	    return (u_char *)&long_return;
#else
	    return NULL;
#endif

	case IPROUTEMASK:
	    return (u_char *)&(SOCKADDR(routeEntry->RT_NETMASK_FIELD));

	case IPROUTEINFO:
	    *var_len = nullOidLen;
	    return (u_char *) nullOid;

	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ipRouteEntry\n",
					vp->magic));
    }
    return NULL;
}


	/*********************
	 *
	 *  System-independent implementation functions
	 *
	 *********************/



	/*
	 *  Search the list of route entries and return
	 *    the appropriate one for this query
	 */

ROUTE_TYPE* search_route(oid* idx, int idx_len, int exact)
{
    static ROUTE_TYPE entry;
    char *cp;
    oid  *op;

    if ( exact && idx_len != 4 )
	return NULL;

    if ( idx_len < 4 ) {
		/* XXX - not correct */
	satosin(entry.RT_ADDRESS_FIELD)->sin_port = 0;
	SOCKADDR(entry.RT_ADDRESS_FIELD) = 0;
    }
    else {
        cp = (char *)&(SOCKADDR(entry.RT_ADDRESS_FIELD));
	op = idx;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
    }

    if ( Search_Table( route_table, (void*)&entry, exact ) == 0 )
	return &entry;
    else
	return NULL;
}

	/*
	 *  Compare two route entries
	 */
int
IP_Cmp_Route(const void* first, const void* second)
{
    const ROUTE_TYPE *rt1 = (const ROUTE_TYPE *) first;
    const ROUTE_TYPE *rt2 = (const ROUTE_TYPE *) second;
    int res;


    res =  (SOCKADDR(rt1->RT_ADDRESS_FIELD) - 
	    SOCKADDR(rt2->RT_ADDRESS_FIELD));

    if ( res == 0 && SOCKADDR(rt1->RT_ADDRESS_FIELD) == 0 )
	res = ( satosin(rt1->RT_ADDRESS_FIELD)->sin_port -
		satosin(rt2->RT_ADDRESS_FIELD)->sin_port);

    return res;
}


	/*********************
	 *
	 *  System-specific functions to read
	 *   in the list of routing entries
	 *
	 *********************/

#ifdef  solaris2
#define ROUTE_SCAN_RELOAD
int Route_Scan_Reload( mib_table_t t )
{
	/* Do something clever with 'getMibstat' */
}
#endif

#ifdef  hpux
#define ROUTE_SCAN_RELOAD
int Route_Scan_Reload( mib_table_t t )
{
    int numEntries, size, i;
    mib_ipRouteEnt *entries;

   if (hpux_read_stat((char *)&numEntries, sizeof(int), ID_ipRouteNumEnt) == -1)
	return -1;

    size = numEntries*sizeof(mib_ipRouteEnt);
    if ( (entries=(mib_ipRouteEnt *)malloc ( size )) == NULL )
	return -1;

    if (hpux_read_stat((char *)entries, size, ID_ipRouteTable) == -1) {
	free( entries );
	return -1;
    }

		/* XXX - Need to check (& correct?) ifIndex values */

				/* Or add all in one go ? */
    for ( i = 0 ; i<numEntries ; i++ )
	if ( Add_Entry( t, (void*)&(entries[i])) < 0 )
	    break;
    free( entries );
    return 0;
}
#endif

#ifdef  linux
#define ROUTE_SCAN_RELOAD
int Route_Scan_Reload( mib_table_t t )
{
    FILE *in;
    char line [256], name[32];
    struct rtentry rtent;
    int refcnt, flags, metric;
    unsigned use;

    if (! (in = fopen ("/proc/net/route", "r"))) {
	snmp_log(LOG_ERR, "snmpd: cannot open /proc/net/route ...\n");
	return -1;
    }

    while (fgets (line, sizeof(line), in)) {

	    /*
	     * as with 1.99.14:
	     * Iface Dest GW Flags RefCnt Use Metric Mask MTU Win IRTT
	     * eth0 0A0A0A0A 00000000 05 0 0 0 FFFFFFFF 1500 0 0 
	     */
	if (8 != sscanf (line, "%s %x %x %x %u %d %d %x %*d %*d %*d\n",
			     name,
			     &(((struct sockaddr_in *) &(rtent.rt_dst))->sin_addr.s_addr),
			     &(((struct sockaddr_in *) &(rtent.rt_gateway))->sin_addr.s_addr),
/* XXX: fix type of the args */
			     &flags, &refcnt, &use, &metric,
			     &(((struct sockaddr_in *) &(rtent.rt_genmask))->sin_addr.s_addr)))
	      continue;
	    
	satosin(rtent.rt_dst)->sin_port = 1;	/* Hack! */
	rtent.rt_flags  = flags;
#ifdef NOT_USED
	rtent.rt_refcnt = refcnt;		/* Not used */
	rtent.rt_use    = use;			/* Not used */
	rtent.rt_metric = metric;		/* Not used */
#endif
	rtent.rt_window = Interface_Index_By_Name( name );

	if (Add_Entry( t, (void *)&rtent) < 0 )
	    break;
    }

    fclose (in);
    return 0;
}
#endif /* linux */

#ifdef  CAN_USE_SYSCTL
#define ROUTE_SCAN_RELOAD
int Route_Scan_Reload( mib_table_t t )
{
    size_t size = 0;
    int name[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_DUMP, 0 };
    char *all_routes, *cp;
    struct snmprt entry;
    struct rt_msghdr *rtp;
    struct sockaddr *sa;
    int bit;

    if (sysctl (name, sizeof (name) / sizeof (int), 0, &size, 0, 0) == -1) {
	snmp_log(LOG_ERR,"sysctl size fail\n");
	return -1;
    }
    if ((all_routes = malloc (size)) == NULL) {
	snmp_log(LOG_ERR,"out of memory allocating route table\n");
	return -1;
    }
    if (sysctl (name, sizeof (name) / sizeof (int), all_routes, &size, 0, 0) == -1) {
	snmp_log(LOG_ERR,"sysctl get fail\n");
	return -1;
    }


    for ( cp = all_routes; cp < all_routes+size; cp += rtp->rtm_msglen) {
	rtp = (struct rt_msghdr *) cp;

		/*
		 * Check for a valid route entry
		 */
	if (rtp->rtm_type == 0)
	    break;
	if (rtp->rtm_version != RTM_VERSION) {
	    snmp_log(LOG_ERR, "routing socket message version mismatch (%d instead of %d)\n",
			rtp->rtm_version, RTM_VERSION);
	    break;
	}
	if (rtp->rtm_type != RTM_GET) {
	    snmp_log(LOG_ERR, "routing socket returned message other than GET (%d)\n", rtp->rtm_type);
	    continue;
	}
	if (!(rtp->rtm_addrs & RTA_DST))	/* Need a destination address! */
	    continue;

		/*
		 *  Set up the entry and add it to the list
		 */
	memcpy( &entry.hdr, rtp, sizeof( struct rt_msghdr ));
	entry.index = rtp->rtm_index;
	entry.rt_dst.s_addr     = 0; 
	entry.rt_gateway.s_addr = 0; 
	entry.rt_genmask.s_addr = 0; 
	entry.ifa.s_addr        = 0; 
	
	sa = (struct sockaddr *)(rtp + 1);
	for ( bit = 1;
	      bit && ((char *)sa < (char *)rtp + rtp->rtm_msglen);
	      bit <<= 1) {
		if (( rtp->rtm_addrs & bit ) == 0 )
		    continue;
		switch ( bit ) {
		    case RTA_DST:
				entry.rt_dst = satosin(*sa)->sin_addr;
				break;
		    case RTA_GATEWAY:
				if ( sa->sa_family == AF_INET )
				    entry.rt_gateway = satosin(*sa)->sin_addr;
				break;
		    case RTA_NETMASK:
				entry.rt_genmask = satosin(*sa)->sin_addr;
				break;
		    case RTA_IFA:
				if ( sa->sa_family == AF_INET )
				    entry.ifa = satosin(*sa)->sin_addr;
				break;
		}
/* from 'rtsock.c' */
#define ROUNDUP(a) \
		((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
		sa = (struct sockaddr *)((char *)sa + ROUNDUP(sa->sa_len));
	}

	if (Add_Entry( t, (void *)&entry) < 0 )
	    break;
    }
    free( all_routes );
    return 0;
}
#endif


#ifdef  ROUTE_SCAN_RELOAD
#undef  RTENTRY_4_4		/* already been handled */
#endif
#ifdef  RTENTRY_4_4
#define ROUTE_SCAN_RELOAD
void load_rtentries(struct radix_node *pt, mib_table_t t);	/* see below */

int Route_Scan_Reload( mib_table_t t )
{
    struct radix_node_head head, *rt_table[AF_MAX+1];
    int i;

    auto_nlist(RTTABLES_SYMBOL, (char *) rt_table, sizeof(rt_table));
    for(i=0; i <= AF_MAX; i++) {
	if(rt_table[i] == 0)
	    continue;
	if (!klookup((unsigned long)rt_table[i], (char *) &head, sizeof(head)))
	    continue;

	load_rtentries(head.rnh_treetop, t );
    }
    return 0;
}
#endif


#ifndef ROUTE_SCAN_RELOAD
#define NUM_ROUTE_SYMBOLS 2
char*  route_symbols[] = {
    RTHOST_SYMBOL,
    RTNET_SYMBOL
};

int Route_Scan_Reload( mib_table_t t )
{
    RTENTRY **routehash, *m, rt;
    struct ifnet ifnet;
    int i, table, hashsize;
    char name[16], *cp;

    auto_nlist(RTHASHSIZE_SYMBOL, (char *)&hashsize, sizeof(hashsize));
    routehash = (RTENTRY **)malloc(hashsize * sizeof(struct mbuf *));

    for (table=0; table<NUM_ROUTE_SYMBOLS; table++) {
	auto_nlist(route_symbols[table], (char *)routehash,
					hashsize * sizeof(struct mbuf *));

		/* Walk through the hash table of routes */
	for (i = 0; i < hashsize; i++) {
	    if (routehash[i] == 0)
		continue;
	    m = routehash[i];
	    while (m) {
			/* Dig the route out of the kernel */
		klookup(m , (char *)&rt, sizeof (rt));
		m = rt.rt_next;
		if (rt.rt_ifp != 0) {
				/* Find the I/F name, and hence the index */
		    klookup( rt.rt_ifp, (char *)&ifnet, sizeof (ifnet));
		    klookup( ifnet.if_name, name, 16);
		    name[15] = '\0';
		    cp = (char *) strchr(name, '\0');
		    string_append_int (cp, ifnet.if_unit);

		    rt.RT_INDEX_FIELD = Interface_Index_By_Name( name );
		}
		(void)Add_Entry( t, (void *)&rt);
	    }
	}
    }
    free( routehash );
    return 0;
}
#endif


	/*****************
	 *
	 *  Additional routines
	 *
	 *****************/

#ifdef RTENTRY_4_4
void
load_rtentries(struct radix_node *pt, mib_table_t t)
{
    struct radix_node node;
    RTENTRY rt;
    struct ifnet ifnet;
    char name[16], temp[16];
#if !STRUCT_IFNET_HAS_IF_XNAME
    register char *cp;
#endif
  
    if (!klookup((unsigned long)pt , (char *) &node , sizeof (struct radix_node))) {
	DEBUGMSGTL(("mibII/var_route", "Fail\n"));
	return;
    }
    if (node.rn_b >= 0) {
	load_rtentries(node.rn_r, t);
	load_rtentries(node.rn_l, t);
	return;
    }

    if (node.rn_flags & RNF_ROOT) {
	/* root node */
	if (node.rn_dupedkey)
            load_rtentries(node.rn_dupedkey, t);
	return;
    }

    /* get the route */
    klookup((unsigned long)pt, (char *) &rt, sizeof (RTENTRY));
      
    if (rt.rt_ifp != 0) {
			/*
			 * Find the I/F name, and hence the index
			 */
	klookup((unsigned long)rt.rt_ifp, (char *)&ifnet, sizeof (ifnet));
#if STRUCT_IFNET_HAS_IF_XNAME
#if defined(netbsd1) || defined(openbsd2)
	strncpy(name, ifnet.if_xname, sizeof name);
#else
	klookup((unsigned long)ifnet.if_xname, name, sizeof name);
#endif
	name[sizeof (name)-1] = '\0';
#else
	klookup((unsigned long)ifnet.if_name, name, sizeof name);
	name[sizeof (name) - 1] = '\0';
	cp = (char *) strchr(name, '\0');
	string_append_int (cp, ifnet.if_unit);
#endif
	rt.RT_INDEX_FIELD = Interface_Index_By_Name( name );
      
			/* Add this entry to our table */
#if CHECK_RT_FLAGS
	if (((rt.rt_flags & RTF_CLONING) != RTF_CLONING) &&
	    ((rt.rt_flags & RTF_LLINFO)  != RTF_LLINFO)) {
#endif
	    (void)Add_Entry( t, (void *)&rt);

#if CHECK_RT_FLAGS
	}
#endif

	if (node.rn_dupedkey)
	    load_rtentries(node.rn_dupedkey, t);
    }
}
#endif /* RTENTRY_4_4 */
