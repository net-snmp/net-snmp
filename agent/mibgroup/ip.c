/*
 *  IP MIB group implementation - ip.c
 *
 */

#include "../common_header.h"
#include "ip.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

static struct nlist ip_nl[] = {
#define N_IPSTAT	0
#define N_IPFORWARDING	1
#define N_TCP_TTL	2
#define N_HP_IPMIB	3
#if !defined(hpux) && !defined(solaris2)
	{ "_ipstat"},
#ifdef sun
	{ "_ip_forwarding" },
#else
	{ "_ipforwarding" },
#endif
	{ "_tcp_ttl"},
#else  /* hpux or solaris */
	{ "ipstat"},  
	{ "ipforwarding" },
#ifndef hpux
	{ "tcpDefaultTTL"},
#else
	{ "ipDefaultTTL"},
	{ "MIB_ipcounter" },
#endif
#endif
        { 0 },
};


#ifdef linux
static void linux_read_ip_stat ();
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

extern void init_routes __P((void));

void	init_ip( )
{
    init_nlist( ip_nl );
    init_routes();
}


#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

int
header_ip(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define IP_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_ip: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[IP_NAME_LENGTH] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
};


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/



#ifndef solaris2
#ifndef linux

u_char *
var_ip(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    static struct ipstat ipstat;
#ifdef hpux
    static	counter MIB_ipcounter[MIB_ipMAXCTR+1];
#endif
    int i;

    if (header_icmp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *	Get the IP statistics from the kernel...
     */
    KNLookup(ip_nl, N_IPSTAT, (char *)&ipstat, sizeof (ipstat));
#ifdef hpux
    KNLookup(ip_nl, N_HP_IPMIB, (char *)&MIB_ipcounter,
	(MIB_ipMAXCTR+1)*sizeof (counter));
#endif

    switch (vp->magic){
	case IPFORWARDING:
#ifndef sparc	  
	    KNLookup(ip_nl,  N_IPFORWARDING, (char *) &i, sizeof(i));
	    fflush(stderr);
	    if (i) {
		long_return = 1;		/* GATEWAY */
	    } else {
		long_return = 2;	    /* HOST    */
	    }
#else /* sparc */
	    long_return = 0;
#endif /* sparc */

	    return (u_char *) &long_return;
	case IPDEFAULTTTL:
	    /*
	     *	Allow for a kernel w/o TCP.
	     */
	    if (ip_nl[N_TCP_TTL].n_value) {
		KNLookup(ip_nl,  N_TCP_TTL, (char *) &long_return, sizeof(long_return));
	    } else long_return = 60;	    /* XXX */
	    return (u_char *) &long_return;
	case IPINRECEIVES:
	    return (u_char *) &ipstat.ips_total;
	case IPINHDRERRORS:
	    long_return = ipstat.ips_badsum + ipstat.ips_tooshort +
			  ipstat.ips_toosmall + ipstat.ips_badhlen +
			  ipstat.ips_badlen;
	    return (u_char *) &long_return;
	case IPINADDRERRORS:
	    return (u_char *) &ipstat.ips_cantforward;

	case IPFORWDATAGRAMS:
	    return (u_char *) &ipstat.ips_forward;

	case IPINUNKNOWNPROTOS:
#ifdef hpux
	    long_return = MIB_ipcounter[7];
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case IPINDISCARDS:
#ifdef hpux
	    long_return = MIB_ipcounter[8];
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case IPINDELIVERS:

	    long_return = ipstat.ips_total -
			 (ipstat.ips_badsum + ipstat.ips_tooshort +
			  ipstat.ips_toosmall + ipstat.ips_badhlen +
			  ipstat.ips_badlen);
	    return (u_char *) &long_return;

	case IPOUTREQUESTS:
#ifdef hpux
	    long_return = MIB_ipcounter[10];
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case IPOUTDISCARDS:
#ifdef hpux
	    long_return = MIB_ipcounter[11];
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case IPOUTNOROUTES:
	    return (u_char *) &ipstat.ips_cantforward;

	case IPREASMTIMEOUT:
	    long_return = IPFRAGTTL;
	    return (u_char *) &long_return;
	case IPREASMREQDS:
	    return (u_char *) &ipstat.ips_fragments;

	case IPREASMOKS:
#ifdef hpux
	    long_return = MIB_ipcounter[15];
#else
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
#ifdef hpux
	    long_return = MIB_ipcounter[17];
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case IPFRAGFAILS:
#ifdef hpux
	    long_return = MIB_ipcounter[18];
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case IPFRAGCREATES:
#ifdef hpux
	    long_return = MIB_ipcounter[19];
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case IPROUTEDISCARDS:
	    long_return = 0;
	    return (u_char *) &long_return;
	default:
	    ERROR("");
    }
}


#else /* linux */    

u_char *
var_ip(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    static struct ip_mib ipstat;

    if (header_icmp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
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
	    ERROR("");
    }
    return NULL;
}
#endif /* linux */



u_char *
var_ipAddrEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
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
#ifndef sunV3
    static struct in_ifaddr in_ifaddr, lowin_ifaddr;
#endif
    static struct ifnet ifnet, lowin_ifnet;

    /* fill in object part of name for current (less sizeof instance part) */

    bcopy((char *)vp->name, (char *)current, (int)vp->namelen * sizeof(oid));

#ifndef freebsd2
    Interface_Scan_Init();
#else
      Address_Scan_Init();
#endif
    for (;;) {

#ifdef sunV3
	if (Interface_Scan_Next(&interface, (char *)0, &ifnet) == 0) break;
	cp = (u_char *)&(((struct sockaddr_in *) &(ifnet.if_addr))->sin_addr.s_addr);
#else
#ifndef freebsd2
	if (Interface_Scan_Next(&interface, (char *)0, &ifnet, &in_ifaddr) == 0) break;
#else
      if (Address_Scan_Next(&interface, &in_ifaddr) == 0) break;
#endif
	cp = (u_char *)&(((struct sockaddr_in *) &(in_ifaddr.ia_addr))->sin_addr.s_addr);

#endif

#ifndef linux
      if ( ifnet.if_addrlist == 0 )
          continue;                   /* No address found for interface */
#endif /* linux */

	op = current + 10;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	if (exact){
	    if (compare(current, 14, name, *length) == 0){
		bcopy((char *)current, (char *)lowest, 14 * sizeof(oid));
		lowinterface = interface;
#ifdef sunV3
		lowin_ifnet = ifnet;
#else
		lowin_ifaddr = in_ifaddr;
#endif
		break;	/* no need to search further */
	    }
	} else {
	    if ((compare(current, 14, name, *length) > 0) &&
		 (!lowinterface || (compare(current, 14, lowest, 14) < 0))){
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, save this one as the "next" one.
		 */
		lowinterface = interface;
#ifdef sunV3
		lowin_ifnet = ifnet;
#else
		lowin_ifaddr = in_ifaddr;
#endif
		bcopy((char *)current, (char *)lowest, 14 * sizeof(oid));
	    }
	}
    }

    if (!lowinterface) return(NULL);
    bcopy((char *)lowest, (char *)name, 14 * sizeof(oid));
    *length = 14;
    *write_method = 0;
    *var_len = sizeof(long_return);
    switch(vp->magic){
	case IPADADDR:
#ifdef sunV3
            return(u_char *) &((struct sockaddr_in *) &lowin_ifnet.if_addr)->sin_addr.s_addr;
#else
	    return(u_char *) &((struct sockaddr_in *) &lowin_ifaddr.ia_addr)->sin_addr.s_addr;
#endif
	case IPADIFINDEX:
	    long_return = lowinterface;
	    return(u_char *) &long_return;
	case IPADNETMASK:
#ifndef sunV3
	    long_return = ntohl(lowin_ifaddr.ia_subnetmask);
#endif
	    return(u_char *) &long_return;
	case IPADBCASTADDR:
	    
#ifdef sunV3
	    long_return = ntohl(((struct sockaddr_in *) &lowin_ifnet.ifu_broadaddr)->sin_addr.s_addr) & 1;
#else
          long_return = ntohl(((struct sockaddr_in *) &lowin_ifaddr.ia_broadaddr)->sin_addr.s_addr) & 1;
#endif
	    return(u_char *) &long_return;	   
	case IPADREASMMAX:
	    long_return = -1;
	    return(u_char *) &long_return;
	default:
	    ERROR("");
    }
    return NULL;
}

#else /* solaris2 */

u_char *
var_ip(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
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
	    ERROR("");
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
var_ipAddrEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
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
#ifdef DODEBUG
    char		    c_oid[1024];
#endif
    
    /* fill in object part of name for current (less sizeof instance part) */

#ifdef DODEBUG
    sprint_objid (c_oid, name, *length);
    printf ("var_ipAddrEntry: %s %d\n", c_oid, exact);
#endif
    memset (&Lowentry, 0, sizeof (Lowentry));
    bcopy((char *)vp->name, (char *)current, (int)vp->namelen * sizeof(oid));
    if (*length == IP_ADDRNAME_LENGTH) /* Assume that the input name is the lowest */
      bcopy((char *)name, (char *)lowest, IP_ADDRNAME_LENGTH * sizeof(oid));
    for (NextAddr = (u_long)-1, req_type = GET_FIRST;
	 ;
	 NextAddr = entry.ipAdEntAddr, req_type = GET_NEXT) {
      if (getMibstat(MIB_IP_ADDR, &entry, sizeof(mib2_ipAddrEntry_t),
		     req_type, &IP_Cmp, &NextAddr) != 0)
	break;
      COPY_IPADDR(cp, (u_char *)&entry.ipAdEntAddr, op, current + IP_ADDRINDEX_OFF);
      if (exact){
	if (compare(current, IP_ADDRNAME_LENGTH, name, *length) == 0){
	  bcopy((char *)current, (char *)lowest, IP_ADDRNAME_LENGTH * sizeof(oid));
	  Lowentry = entry;
	  Found++;
	  break;	/* no need to search further */
	}
      } else {
	if ((compare(current, IP_ADDRNAME_LENGTH, name, *length) > 0) 
	    && (((NextAddr == (u_long)-1))
		|| (compare(current, IP_ADDRNAME_LENGTH, lowest, IP_ADDRNAME_LENGTH) < 0)
		|| (compare(name, *length, lowest, IP_ADDRNAME_LENGTH) == 0))){
	  /*
	   * if new one is greater than input and closer to input than
	   * previous lowest, and is not equal to it, save this one as the "next" one.
	   */
	  Lowentry = entry;
	  Found++;
	  bcopy((char *)current, (char *)lowest, IP_ADDRNAME_LENGTH * sizeof(oid));
	}
      }
    }
#ifdef DODEBUG
    printf ("... Found = %d\n", Found);
#endif
    if (Found == 0)
      return(NULL);
    bcopy((char *)lowest, (char *)name, IP_ADDRNAME_LENGTH * sizeof(oid));
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
	    ERROR("");
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
linux_read_ip_stat (ipstat)
struct ip_mib *ipstat;
{
  FILE *in = fopen ("/proc/net/snmp", "r");
  char line [1024];

  bzero ((char *) ipstat, sizeof (*ipstat));

  if (! in)
    return;

  while (line == fgets (line, 1024, in))
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
