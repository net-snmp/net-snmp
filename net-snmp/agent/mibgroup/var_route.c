/*
 * snmp_var_route.c - return a pointer to the named variable.
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
 */

#include <config.h>

#define GATEWAY			/* MultiNet is always configured this way! */
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
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
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#include <net/route.h>
#undef	KERNEL
#ifdef RTENTRY_4_4
#define rt_unit rt_refcnt	       /* Reuse this field for device # */
#if defined(irix6) || defined(osf3) || defined(netbsd1) || defined(freebsd2) || defined(bsdi2)
#define rt_dst rt_nodes->rn_key
#endif
#else
#define rt_unit rt_refcnt	       /* Reuse this field for device # */
#endif
#ifndef linux
#include <nlist.h>
#endif
#ifndef NULL
#define NULL 0
#endif
#if HAVE_KVM_OPENFILES
#include <fcntl.h>
#if HAVE_KVM_H
#include <kvm.h>
#endif
#endif

#if STDC_HEADERS
#if HAVE_STRINGS_H
#include <strings.h>
#endif
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif

#if solaris2
#include "kernel_sunos5.h"
#endif

#define CACHE_TIME (120)	    /* Seconds */

#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "mib.h"
#include "snmp.h"
#include "../snmp_vars.h"
#include "ip.h"
#include "../kernel.h"
#include "interfaces.h"
#include "util_funcs.h"

#ifndef  MIN
#define  MIN(a,b)                     (((a) < (b)) ? (a) : (b))
#endif


#ifndef solaris2
static void Route_Scan_Reload __P((void));
static RTENTRY **rthead=0;
static int rtsize=0, rtallocate=0;
#endif

#if !(defined(linux) || defined(solaris2))
static struct nlist nl_var_route[] = {
#define N_RTHOST	0
#define N_RTNET		1
#define N_RTHASHSIZE	2
#define N_RTTABLES	3
#if defined(hpux)
	{ "rthost" },
	{ "rtnet" },
	{ "rthashsize" },
	{ "rt_table" },
#else 
	{ "_rthost" },
	{ "_rtnet" },
	{ "_rthashsize" },
#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2)
	{ "_rt_tables" },
#else
	{ "_rt_table" },
#endif
#endif
	{ 0 },
};
#endif

void	init_var_route( )
{
#if !(defined(solaris2) || defined(linux))
    init_nlist( nl_var_route );
#endif
}


extern int write_rte __P((int, u_char *, u_char, int, u_char *, oid *, int));

#ifndef solaris2

#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2)
static union {
    struct  sockaddr_in sin;
    u_short data[128];
} klgetsatmp;

struct sockaddr_in *
klgetsa(struct sockaddr_in *dst)
{
  klookup((u_long)dst, (char *)&klgetsatmp.sin, sizeof klgetsatmp.sin);
  if (klgetsatmp.sin.sin_len > sizeof (klgetsatmp.sin))
    klookup((u_long)dst, (char *)&klgetsatmp.sin, klgetsatmp.sin.sin_len);
  return(&klgetsatmp.sin);
}
#endif

u_char *
var_ipRouteEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output strings */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.21.1.1.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */
    register int Save_Valid, result, RtIndex;
    static int saveNameLen=0, saveExact=0, saveRtIndex=0;
    static oid saveName[14], Current[14];
    u_char *cp;
    oid *op;
#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2)
    struct sockaddr_in *sa;
#endif
#ifndef linux
    struct ifnet     rt_ifnet;
    struct in_ifaddr rt_ifnetaddr;
#endif
#ifdef linux
    /** 
     ** this optimisation fails, if there is only a single route avail.
     ** it is a very special case, but better leave it out ...
     **/
    if (rtsize <= 1)
      Save_Valid = 0;
    else
#endif
    /*
     *	OPTIMIZATION:
     *
     *	If the name was the same as the last name, with the possible
     *	exception of the [9]th token, then don't read the routing table
     *
     */

    if ((saveNameLen == *length) && (saveExact == exact)) {
	register int temp=name[9];
	name[9] = 0;
	Save_Valid = (compare(name, *length, saveName, saveNameLen) == 0);
	name[9] = temp;
    } else
	Save_Valid = 0;

    if (Save_Valid) {
	register int temp=name[9];    /* Fix up 'lowest' found entry */
	bcopy((char *) Current, (char *) name, 14 * sizeof(oid));
	name[9] = temp;
	*length = 14;
	RtIndex = saveRtIndex;
    } else {
	/* fill in object part of name for current (less sizeof instance part) */

	bcopy((char *)vp->name, (char *)Current, (int)(vp->namelen) * sizeof(oid));

#if 0
	/*
	 *  Only reload if this is the start of a wildcard
	 */
	if (*length < 14) {
	    Route_Scan_Reload();
	}
#else
        Route_Scan_Reload();
#endif
	for(RtIndex=0; RtIndex < rtsize; RtIndex++) {
#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2)
	    sa = klgetsa((struct sockaddr_in *) rthead[RtIndex]->rt_dst);
	    cp = (u_char *) &(sa->sin_addr.s_addr);
#else
#ifdef linux
	    cp = (u_char *) rthead[RtIndex]->rt_dst.sa_data;
#else
	    cp = (u_char *)&(((struct sockaddr_in *) &(rthead[RtIndex]->rt_dst))->sin_addr.s_addr);
#endif
#endif
	    op = Current + 10;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;

	    result = compare(name, *length, Current, 14);
	    if ((exact && (result == 0)) || (!exact && (result < 0)))
		break;
	}
	if (RtIndex >= rtsize)
	    return(NULL);
	/*
	 *  Save in the 'cache'
	 */
	bcopy((char *) name, (char *) saveName, *length * sizeof(oid));
	saveName[9] = 0;
	saveNameLen = *length;
	saveExact = exact;
	saveRtIndex = RtIndex;
	/*
	 *  Return the name
	 */
	bcopy((char *) Current, (char *) name, 14 * sizeof(oid));
	*length = 14;
    }

    *write_method = write_rte;
    *var_len = sizeof(long_return);

    switch(vp->magic){
	case IPROUTEDEST:
#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2)
	    sa = klgetsa((struct sockaddr_in *) rthead[RtIndex]->rt_dst);
	    return(u_char *) &(sa->sin_addr.s_addr);
#else
#ifdef linux
            return rthead[RtIndex]->rt_dst.sa_data;
#else
	    return(u_char *) &((struct sockaddr_in *) &rthead[RtIndex]->rt_dst)->sin_addr.s_addr;
#endif
#endif
	case IPROUTEIFINDEX:
	    long_return = (u_long)rthead[RtIndex]->rt_unit;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC1:
	    long_return = (rthead[RtIndex]->rt_flags & RTF_GATEWAY) ? 1 : 0;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC2:
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC3:
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC4:
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTEMETRIC5:
	    long_return = -1;
	    return (u_char *)&long_return;
	case IPROUTENEXTHOP:
#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2)
	    sa = klgetsa((struct sockaddr_in *) rthead[RtIndex]->rt_gateway);
	    return(u_char *) &(sa->sin_addr.s_addr);
#else
#ifdef linux
	    return(u_char *) rthead[RtIndex]->rt_gateway.sa_data;
#else
	    return(u_char *) &((struct sockaddr_in *) &rthead[RtIndex]->rt_gateway)->sin_addr.s_addr;
#endif /* linux */
#endif /* *bsd */
	case IPROUTETYPE:
	    long_return = (rthead[RtIndex]->rt_flags & RTF_GATEWAY) ? 4 : 3;
	    return (u_char *)&long_return;
	case IPROUTEPROTO:
	    long_return = (rthead[RtIndex]->rt_flags & RTF_DYNAMIC) ? 4 : 2;
	    return (u_char *)&long_return;
	case IPROUTEAGE:
	    long_return = 0;
	    return (u_char *)&long_return;
	case IPROUTEMASK:
#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2)
		/* XXX - Almost certainly not right
		    but I don't have a suitable system to test this on */
	    long_return = 0;
#else /*  defined(freebsd2) || defined(netbsd1) || defined(bsdi2) */
	    if ( ((struct sockaddr_in *) &rthead[RtIndex]->rt_dst)->sin_addr.s_addr == 0 )
		long_return = 0;	/* Default route */
	    else {
#ifndef linux
		klookup((unsigned long) rthead[RtIndex]->rt_ifp,
			(char *) &rt_ifnet, sizeof(rt_ifnet));
		klookup((unsigned long) rt_ifnet.if_addrlist,
			(char *) &rt_ifnetaddr, sizeof(rt_ifnetaddr));

		long_return = rt_ifnetaddr.ia_subnetmask;
#else /* linux */
                return (u_char *) rthead[RtIndex]->rt_genmask.sa_data;
#endif /* linux */
	    }
#endif /* defined(freebsd2) || defined(netbsd1) || defined(bsdi2) */
	    return (u_char *)&long_return;
	case IPROUTEINFO:
	    *var_len = nullOidLen;
	    return (u_char *)nullOid;
	default:
	    ERROR_MSG("");
   }
   return NULL;
}

#else /* solaris2 */

static int
IP_Cmp_Route(void *addr, void *ep)
{
  mib2_ipRouteEntry_t *Ep = ep, *Addr = addr;

  if (
      (Ep->ipRouteDest == Addr->ipRouteDest) &&
      (Ep->ipRouteNextHop == Addr->ipRouteNextHop) &&
      (Ep->ipRouteType == Addr->ipRouteType) &&
      (Ep->ipRouteProto == Addr->ipRouteProto) &&
      (Ep->ipRouteMask == Addr->ipRouteMask) &&
      (Ep->ipRouteInfo.re_max_frag == Addr->ipRouteInfo.re_max_frag) &&
      (Ep->ipRouteInfo.re_rtt == Addr->ipRouteInfo.re_rtt) &&
      (Ep->ipRouteInfo.re_ref == Addr->ipRouteInfo.re_ref) &&
      (Ep->ipRouteInfo.re_frag_flag == Addr->ipRouteInfo.re_frag_flag) &&
      (Ep->ipRouteInfo.re_src_addr == Addr->ipRouteInfo.re_src_addr) &&
      (Ep->ipRouteInfo.re_ire_type == Addr->ipRouteInfo.re_ire_type) &&
      (Ep->ipRouteInfo.re_obpkt == Addr->ipRouteInfo.re_obpkt) &&
      (Ep->ipRouteInfo.re_ibpkt == Addr->ipRouteInfo.re_ibpkt)
      )
    return (0);
  else
    return (1);		/* Not found */
}

u_char *
var_ipRouteEntry(vp, name, length, exact, var_len, write_method)
register struct variable *vp;   /* IN - pointer to variable entry that points here */
register oid	*name;	    /* IN/OUT - input name requested, output name found */
register int	*length;    /* IN/OUT - length of input and output strings */
int		exact;	    /* IN - TRUE if an exact match was requested. */
int		*var_len;   /* OUT - length of variable or 0 if function returned. */
int		(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
  /*
   * object identifier is of form:
   * 1.3.6.1.2.1.4.21.1.1.A.B.C.D,  where A.B.C.D is IP address.
   * IPADDR starts at offset 10.
   */
#define IP_ROUTENAME_LENGTH	14
#define	IP_ROUTEADDR_OFF	10
  oid 			current[IP_ROUTENAME_LENGTH], lowest[IP_ROUTENAME_LENGTH];
  u_char 		*cp;
  oid 			*op;
  mib2_ipRouteEntry_t	Lowentry, Nextentry, entry;
  int			Found = 0;
  req_e 		req_type;

  /* fill in object part of name for current (less sizeof instance part) */
  
  bcopy((char *)vp->name, (char *)current, (int)(vp->namelen) * sizeof(oid));
  if (*length == IP_ROUTENAME_LENGTH) /* Assume that the input name is the lowest */
    bcopy((char *)name, (char *)lowest, IP_ROUTENAME_LENGTH * sizeof(oid));
  else
    name[IP_ROUTEADDR_OFF] = -1; /* Grhhh: to prevent accidental comparison :-( */
  for (Nextentry.ipRouteDest = (u_long)-2, req_type = GET_FIRST;
       ;
       Nextentry = entry, req_type = GET_NEXT) {
    if (getMibstat(MIB_IP_ROUTE, &entry, sizeof(mib2_ipRouteEntry_t),
		   req_type, &IP_Cmp_Route, &Nextentry) != 0)
      break;
    COPY_IPADDR(cp, (u_char *)&entry.ipRouteDest, op, current + IP_ROUTEADDR_OFF);
    if (exact){
      if (compare(current, IP_ROUTENAME_LENGTH, name, *length) == 0){
	bcopy((char *)current, (char *)lowest, IP_ROUTENAME_LENGTH * sizeof(oid));
	Lowentry = entry;
	Found++;
	break;  /* no need to search further */
      }
    } else {
      if ((compare(current, IP_ROUTENAME_LENGTH, name, *length) > 0) &&
	  ((Nextentry.ipRouteDest == (u_long)-2)
	   || (compare(current, IP_ROUTENAME_LENGTH, lowest, IP_ROUTENAME_LENGTH) < 0)
	   || (compare(name, IP_ROUTENAME_LENGTH, lowest, IP_ROUTENAME_LENGTH) == 0))){

	/* if new one is greater than input and closer to input than
	 * previous lowest, and is not equal to it, save this one as the "next" one.
	 */
	bcopy((char *)current, (char *)lowest, IP_ROUTENAME_LENGTH * sizeof(oid));
	Lowentry = entry;
	Found++;
      }
    }
  }
  if (Found == 0)
    return(NULL);
  bcopy((char *)lowest, (char *) name, IP_ROUTENAME_LENGTH * sizeof(oid));
  *length = IP_ROUTENAME_LENGTH;
  *write_method = write_rte;
  *var_len = sizeof(long_return);

  switch(vp->magic){
  case IPROUTEDEST:
    long_return = Lowentry.ipRouteDest;
    return (u_char *)&long_return;
  case IPROUTEIFINDEX:
    long_return = Interface_Index_By_Name(Lowentry.ipRouteIfIndex.o_bytes,
					  Lowentry.ipRouteIfIndex.o_length);
    return (u_char *)&long_return;
  case IPROUTEMETRIC1:
    long_return = Lowentry.ipRouteMetric1;
    return (u_char *)&long_return;
  case IPROUTEMETRIC2:
    long_return = Lowentry.ipRouteMetric2;
    return (u_char *)&long_return;
  case IPROUTEMETRIC3:
    long_return = Lowentry.ipRouteMetric3;
    return (u_char *)&long_return;
  case IPROUTEMETRIC4:
    long_return = Lowentry.ipRouteMetric4;
    return (u_char *)&long_return;
  case IPROUTENEXTHOP:
    long_return = Lowentry.ipRouteNextHop;
    return (u_char *)&long_return;
  case IPROUTETYPE:
    long_return = Lowentry.ipRouteType;
    return (u_char *)&long_return;
  case IPROUTEPROTO:
    long_return = Lowentry.ipRouteProto;
    return (u_char *)&long_return;
  case IPROUTEAGE:
    long_return = Lowentry.ipRouteAge;
    return (u_char *)&long_return;
  case IPROUTEMASK:
    long_return = Lowentry.ipRouteMask;
    return (u_char *)&long_return;
  default:
    ERROR_MSG("");
  };
  return NULL;
}

#endif /* solaris2 - var_IProute */

#ifndef solaris2
static int qsort_compare __P((RTENTRY **, RTENTRY **));
#endif

#if defined(RTENTRY_4_4) || defined(RTENTRY_RT_NEXT)

#ifdef RTENTRY_4_4
void
load_rtentries(pt)
struct radix_node *pt;
{
  struct radix_node node;
  RTENTRY rt;
  struct ifnet ifnet;
  char name[16], temp[16];
#if !STRUCT_IFNET_HAS_IF_XNAME
  register char *cp;
#endif
  
  if (!klookup((unsigned long)pt , (char *) &node , sizeof (struct radix_node))) {
    DEBUGP("Fail\n");
    return;
  }
  if (node.rn_b >= 0) {
      load_rtentries(node.rn_r);
      load_rtentries(node.rn_l);
  } else {
    if (node.rn_flags & RNF_ROOT) {
      /* root node */
      if (node.rn_dupedkey)
        load_rtentries(node.rn_dupedkey);
      return;
    }
    /* get the route */
    klookup((unsigned long)pt, (char *) &rt, sizeof (RTENTRY));
      
    if (rt.rt_ifp != 0) {
      klookup((unsigned long)rt.rt_ifp, (char *)&ifnet, sizeof (ifnet));
#if STRUCT_IFNET_HAS_IF_XNAME
#ifdef netbsd1
      strncpy(name, ifnet.if_xname, sizeof name);
#else
      klookup((unsigned long)ifnet.if_xname, name, sizeof name);
#endif
      name[sizeof (name)-1] = '\0';
#else
      klookup( ifnet.if_name, name, sizeof name);
      name[sizeof (name) - 1] = '\0';
      cp = (char *) index(name, '\0');
      string_append_int (cp, ifnet.if_unit);
#endif
      Interface_Scan_Init();
      rt.rt_unit = 0;
      while (Interface_Scan_Next((short *) &(rt.rt_unit), temp, NULL, NULL) != 0) {
        if (strcmp(name, temp) == 0) break;
      }
    }
      
#if defined(freebsd2) || defined(bsdi2)
    if (((rt.rt_flags & RTF_CLONING) != RTF_CLONING)
        && ((rt.rt_flags & RTF_LLINFO) != RTF_LLINFO))
      {
#endif
        /* check for space and malloc */
        if (rtsize >= rtallocate) {
          rthead = (RTENTRY **) realloc((char *)rthead, 2 * rtallocate * sizeof(RTENTRY *));
          bzero((char *) &rthead[rtallocate], rtallocate * sizeof(RTENTRY *));
          
          rtallocate *= 2;
        }
        if (!rthead[rtsize])
          rthead[rtsize] = (RTENTRY *) malloc(sizeof(RTENTRY));
        /*
         *	Add this to the database
         */
        bcopy((char *) &rt, (char *)rthead[rtsize], sizeof(RTENTRY));
        rtsize++;
#if defined(freebsd2) || defined(bsdi2)
      }
#endif

    if (node.rn_dupedkey)
      load_rtentries(node.rn_dupedkey);
  }
}
#endif /* RTENTRY_4_4 */

static void Route_Scan_Reload()
{
#if defined(RTENTRY_4_4)
  struct radix_node_head head, *rt_table[AF_MAX+1];
  int i;
#else
  RTENTRY **routehash, mb;
  register RTENTRY *m;
  RTENTRY *rt;
  struct ifnet ifnet;
  int i, table;
  register char *cp;
  char name[16], temp[16];
  int hashsize;
#endif
  static int Time_Of_Last_Reload=0;
  struct timeval now;

  gettimeofday(&now, (struct timezone *)0);
  if (Time_Of_Last_Reload+CACHE_TIME > now.tv_sec)
    return;
  Time_Of_Last_Reload =  now.tv_sec;

  /*
	 *  Makes sure we have SOME space allocated for new routing entries
	 */
  if (!rthead) {
    rthead = (RTENTRY **) malloc(100 * sizeof(RTENTRY *));
    if (!rthead) {
      ERROR_MSG("malloc");
      return;
    }
    bzero((char *)rthead, 100 * sizeof(RTENTRY *));
    rtallocate = 100;
  }

  /* reset the routing table size to zero -- was a CMU memory leak */
  rtsize = 0;

#ifdef RTENTRY_4_4 
/* rtentry is a BSD 4.4 compat */

#if !defined(AF_UNSPEC)
#define AF_UNSPEC AF_INET 
#endif

  KNLookup(nl_var_route, N_RTTABLES, (char *) rt_table, sizeof(rt_table));
  for(i=0; i <= AF_MAX; i++) {
    if(rt_table[i] == 0)
      continue;
    if (klookup((unsigned long)rt_table[i], (char *) &head, sizeof(head))) {
      load_rtentries(head.rnh_treetop);
    }
  }
        
#else /* rtentry is a BSD 4.3 compat */
  for (table=N_RTHOST; table<=N_RTNET; table++) {

    KNLookup(nl_var_route, N_RTHASHSIZE, (char *)&hashsize, sizeof(hashsize));
    routehash = (RTENTRY **)malloc(hashsize * sizeof(struct mbuf *));
    KNLookup(nl_var_route,  table, (char *)routehash,
             hashsize * sizeof(struct mbuf *));
    for (i = 0; i < hashsize; i++) {
      if (routehash[i] == 0)
        continue;
      m = routehash[i];
      while (m) {
        /*
         *	Dig the route out of the kernel...
         */
        klookup(m , (char *)&mb, sizeof (mb));
        m = mb.rt_next;

        rt = &mb;
        if (rt->rt_ifp != 0) {
          klookup( rt->rt_ifp, (char *)&ifnet, sizeof (ifnet));
          klookup( ifnet.if_name, name, 16);
          name[15] = '\0';
          cp = (char *) index(name, '\0');
	  string_append_int (cp, ifnet.if_unit);

          Interface_Scan_Init();
          while (Interface_Scan_Next((short *)&rt->rt_unit, temp, NULL, NULL) != 0) {
            if (strcmp(name, temp) == 0) break;
          }
        }
        /*
         *	Allocate a block to hold it and add it to the database
         */
        if (rtsize >= rtallocate) {
          rthead = (RTENTRY **) realloc((char *)rthead, 2 * rtallocate * sizeof(RTENTRY *));
          bzero((char *) &rthead[rtallocate], rtallocate * sizeof(RTENTRY *));

          rtallocate *= 2;
        }
        if (!rthead[rtsize])
          rthead[rtsize] = (RTENTRY *) malloc(sizeof(RTENTRY));
        /*
         *	Add this to the database
         */
        bcopy((char *)rt, (char *)rthead[rtsize], sizeof(RTENTRY));
        rtsize++;
      }
    }
    free(routehash);
  }
#endif
  /*
   *  Sort it!
   */
  qsort((char *) rthead, rtsize, sizeof(rthead[0]), qsort_compare);
}

#else

#if HAVE_SYS_MBUF_H
static void Route_Scan_Reload()
{
	struct mbuf **routehash, mb;
	register struct mbuf *m;
	struct ifnet ifnet;
	RTENTRY *rt;
	int i, table;
	register char *cp;
	char name[16], temp[16];
	static int Time_Of_Last_Reload=0;
	struct timeval now;
	int hashsize;
	extern char *index(), *malloc();

	gettimeofday(&now, (struct timezone *)0);
	if (Time_Of_Last_Reload+CACHE_TIME > now.tv_sec)
	  return;
	Time_Of_Last_Reload =  now.tv_sec;
	
	/*
	 *  Makes sure we have SOME space allocated for new routing entries
	 */
	if (!rthead) {
          rthead = (RTENTRY **) malloc(100 * sizeof(RTENTRY *));
          if (!rthead) {
		ERROR_MSG("malloc");
		return;
	    }
          bzero((char *)rthead, 100 * sizeof(RTENTRY *));
          rtallocate = 100;
	}

        /* reset the routing table size to zero -- was a CMU memory leak */
        rtsize = 0;
        
	for (table=N_RTHOST; table<=N_RTNET; table++) {

#ifdef sunV3
	    hashsize = RTHASHSIZ;
#else
	    KNLookup(nl_var_route,  N_RTHASHSIZE, (char *)&hashsize, sizeof(hashsize));
#endif
	    routehash = (struct mbuf **)malloc(hashsize * sizeof(struct mbuf *));
	    KNLookup(nl_var_route,  table, (char *)routehash, hashsize * sizeof(struct mbuf *));
	    for (i = 0; i < hashsize; i++) {
		if (routehash[i] == 0)
			continue;
		m = routehash[i];
		while (m) {
		    /*
		     *	Dig the route out of the kernel...
		     */
		    klookup((unsigned long) m , (char *)&mb, sizeof (mb));
		    m = mb.m_next;
		    rt = mtod(&mb, RTENTRY *);
                    
		    if (rt->rt_ifp != 0) {

			klookup((unsigned long) rt->rt_ifp, (char *)&ifnet,
				sizeof (ifnet));
			klookup((unsigned long) ifnet.if_name, name, 16);
			name[15] = '\0';
			cp = (char *) index(name, '\0');
			string_append_int (cp, ifnet.if_unit);
			if (strcmp(name,"lo0") == 0) continue; 

			Interface_Scan_Init();
			while (Interface_Scan_Next((short *)&rt->rt_unit, temp, NULL, NULL) != 0) {
			    if (strcmp(name, temp) == 0) break;
			}
		    }
		    /*
		     *	Allocate a block to hold it and add it to the database
		     */
		    if (rtsize >= rtallocate) {
                      rthead = (RTENTRY **) realloc((char *)rthead, 2 * rtallocate * sizeof(RTENTRY *));
                      bzero((char *) &rthead[rtallocate], rtallocate * sizeof(RTENTRY *));

			rtallocate *= 2;
		    }
		    if (!rthead[rtsize])
                      rthead[rtsize] = (RTENTRY *) malloc(sizeof(RTENTRY));
                      /*
		     *	Add this to the database
		     */
		    bcopy((char *)rt, (char *)rthead[rtsize], sizeof(RTENTRY));
		    rtsize++;
		}
	    }
            free(routehash);
	}
	/*
	 *  Sort it!
	 */
	qsort((char *)rthead,rtsize,sizeof(rthead[0]),
	      (int (*)(const void *, const void *))qsort_compare);
}
#else
#ifdef linux
static void Route_Scan_Reload __P((void))
{
	FILE *in;
	char line [256];
	struct rtentry *rt;
	char name[16], temp[16];
	static int Time_Of_Last_Reload=0;
	struct timeval now;

	/* allow 20 seconds in cache: */
	gettimeofday(&now, (struct timezone *)0);
	if (Time_Of_Last_Reload + 20 > now.tv_sec)
	    return;
	Time_Of_Last_Reload =  now.tv_sec;

	/*
	 *  Makes sure we have SOME space allocated for new routing entries
	 */
	if (! rthead) {
	    rthead = (struct rtentry **) calloc(100, sizeof(struct rtentry *));
	    if (! rthead) {
		ERROR_MSG("malloc");
		return;
	    }
	    rtallocate = 100;
	}

	/*
	 * fetch routes from the proc file-system:
	 */

	rtsize = 0;

	if (! (in = fopen ("/proc/net/route", "r")))
	  {
	    fprintf (stderr, "cannot open /proc/net/route - burps\n");
	    return;
	  }

	while (fgets (line, sizeof line, in))
	  {
	    struct rtentry rtent;
	    char rtent_name [32];
	    int refcnt, flags, metric;
	    unsigned use;
	    
	    rt = &rtent;
	    bzero ((char *) rt, sizeof(*rt));
	    rt->rt_dev = rtent_name;

	    /*
	     * as with 1.99.14:
	     * Iface Dest GW Flags RefCnt Use Metric Mask MTU Win IRTT
	     * eth0 0A0A0A0A 00000000 05 0 0 0 FFFFFFFF 1500 0 0 
	     */
	    if (8 != sscanf (line, "%s %lx %lx %x %u %d %d %lx %*d %*d %*d\n",
			     rt->rt_dev,
			     (unsigned long *) rt->rt_dst.sa_data,
			     (unsigned long *) rt->rt_gateway.sa_data,
/* XXX: fix type of the args */
			     &flags, &refcnt, &use, &metric,
			     (unsigned long *) &rt->rt_genmask.sa_data))
	      continue;
	    
	    strcpy (name, rt->rt_dev);
	    /* linux says ``lo'', but the interface is stored as ``lo0'': */
	    if (! strcmp (name, "lo"))
	      strcat (name, "0");
	    
	    name[15] = '\0';

	    rt->rt_flags = flags, rt->rt_refcnt = refcnt;
	    rt->rt_use = use, rt->rt_metric = metric;

	    Interface_Scan_Init();
	    while (Interface_Scan_Next((short *)&rt->rt_unit, temp, NULL) != 0)
		if (strcmp(name, temp) == 0) break;

	    /*
	     *	Allocate a block to hold it and add it to the database
	     */
	    if (rtsize >= rtallocate) {
	      rthead = (struct rtentry **) realloc((char *)rthead, 
				   2 * rtallocate * sizeof(struct rtentry *));
	      bzero((char *) &rthead[rtallocate], rtallocate 
		    		   * sizeof(struct rtentry *));
	      rtallocate *= 2;
	    }
	    if (! rthead[rtsize])
	      rthead[rtsize] = (struct rtentry *) malloc(sizeof(struct rtentry));
	    /*
	     *	Add this to the database
	     */
	    bcopy((char *)rt, (char *)rthead[rtsize], sizeof(struct rtentry));
	    rtsize++;
	  }

	fclose (in);

	/*
	 *  Sort it!
	 */
	qsort((char *)rthead,rtsize,sizeof(rthead[0]),qsort_compare);
}
#endif
#endif
#endif


#ifndef solaris2
/*
 *	Create a host table
 */
static int qsort_compare(r1,r2)
RTENTRY **r1, **r2;
{
#if defined(freebsd2) || defined(bsdi2) || defined(netbsd1)
	register u_long dst1 = ntohl(klgetsa((struct sockaddr_in *)(*r1)->rt_dst)->sin_addr.s_addr);
	register u_long dst2 = ntohl(klgetsa((struct sockaddr_in *)(*r2)->rt_dst)->sin_addr.s_addr);
#else
#if !defined(linux)
	register u_long dst1 = ntohl(((struct sockaddr_in *) &((*r1)->rt_dst))->sin_addr.s_addr);
	register u_long dst2 = ntohl(((struct sockaddr_in *) &((*r2)->rt_dst))->sin_addr.s_addr);
#else
	register u_long dst1 = ntohl(*(unsigned long *)&(*r1)->rt_dst.sa_data);
	register u_long dst2 = ntohl(*(unsigned long *)&(*r2)->rt_dst.sa_data);
#endif!
#endif

	/*
	 *	Do the comparison
	 */
	if (dst1 == dst2) return(0);
	if (dst1 > dst2) return(1);
	return(-1);
}
#endif /* solaris2 */
