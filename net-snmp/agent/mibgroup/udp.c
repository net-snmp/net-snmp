/*
 *  UDP MIB group implementation - udp.c
 *
 */

#include "../common_header.h"
#include "udp.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

static struct nlist udp_nl[] = {
#define N_UDPSTAT	0
#define N_UDB		1
#define N_HP_UDPMIB	2
#if !defined(hpux) && !defined(solaris2)
	{ "_udpstat" },
	{ "_udb" },
#else
	{ "udpstat" },
	{ "udb" },
#ifdef hpux
	{ "MIB_udpcounter" },
#endif
#endif
        { 0 },
};


static void UDP_Scan_Init __P((void));
static int UDP_Scan_Next __P((struct inpcb *));


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_udp( )
{
    init_nlist( udp_nl );
}


#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

int
header_udp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define UDP_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_udp: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[UDP_NAME_LENGTH] = 0;
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
#ifndef hpux 

u_char *
var_udp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#ifdef linux
    static struct udp_mib udpstat;
#else
    static struct udpstat udpstat;
#endif

    if (header_udp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *        Get the UDP statistics from the kernel...
     */

    KNLookup(udp_nl, N_UDPSTAT, (char *)&udpstat, sizeof (udpstat));

    switch (vp->magic){
	case UDPINDATAGRAMS:
#if defined(freebsd2) || defined(netbsd1)
	    long_return = udpstat.udps_ipackets;
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case UDPNOPORTS:
#if defined(freebsd2) || defined(netbsd1)
	    long_return = udpstat.udps_noport;
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case UDPOUTDATAGRAMS:
#if defined(freebsd2) || defined(netbsd1)
	    long_return = udpstat.udps_opackets;
#else
	    long_return = 0;
#endif
	    return (u_char *) &long_return;
	case UDPINERRORS:
#ifndef linux
	    long_return = udpstat.udps_hdrops + udpstat.udps_badsum +
#ifdef STRUCT_UDPSTAT_HAS_UDPS_DISCARD
                      + udpstat.udps_discard +
#endif
			  udpstat.udps_badlen;
	    return (u_char *) &long_return;
#else /* linux */
      	    return (u_char *) &udpstat.UdpInErrors;
#endif /* linux */

	default:
	    ERROR("");
    }
    return NULL;
}

#else /* hpux */

u_char *
var_udp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    static struct udpstat udpstat;
    static	counter MIB_udpcounter[MIB_udpMAXCTR+1];

    if (header_udp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *        Get the UDP statistics from the kernel...
     */

    KNLookup(udp_nl, N_UDPSTAT, (char *)&udpstat, sizeof (udpstat));
    KNLookup(udp_nl, N_HP_UDPMIB, (char *)&MIB_udpcounter,
	(MIB_udpMAXCTR+1)*sizeof (counter));

    switch (vp->magic){
	case UDPINDATAGRAMS:
	    long_return = MIB_udpcounter[1];
	    return (u_char *) &long_return;
	case UDPNOPORTS:
	    long_return = MIB_udpcounter[2];
	    return (u_char *) &long_return;
	case UDPOUTDATAGRAMS:
	    long_return = MIB_udpcounter[3];
	    return (u_char *) &long_return;
	case UDPINERRORS:
	    long_return = udpstat.udps_hdrops + udpstat.udps_badsum +
#ifdef STRUCT_UDPSTAT_HAS_UDPS_DISCARD
                      + udpstat.udps_discard +
#endif
			  udpstat.udps_badlen;
	    return (u_char *) &long_return;

	default:
	    ERROR("");
    }
    return NULL;
}

#endif /* hpux */



u_char *
var_udpEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    int i;
    oid newname[MAX_NAME_LEN], lowest[MAX_NAME_LEN], *op;
    u_char *cp;
    int LowState;
    static struct inpcb inpcb, Lowinpcb;

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
		/* find the "next" pseudo-connection */
Again:
LowState = -1;		/* UDP doesn't have 'State', but it's a useful flag */
	UDP_Scan_Init();
	for (;;) {
	    if ((i = UDP_Scan_Next(&inpcb)) < 0) goto Again;
	    if (i == 0) break;	    /* Done */
	    cp = (u_char *)&inpcb.inp_laddr.s_addr;
	    op = newname + 10;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    
	    newname[14] = ntohs(inpcb.inp_lport);

	    if (exact){
		if (compare(newname, 15, name, *length) == 0){
		    bcopy((char *)newname, (char *)lowest, 15 * sizeof(oid));
		    LowState = 0;
		    Lowinpcb = inpcb;
		    break;  /* no need to search further */
		}
	    } else {
		if ((compare(newname, 15, name, *length) > 0) &&
		     ((LowState < 0) || (compare(newname, 15, lowest, 15) < 0))){
		    /*
		     * if new one is greater than input and closer to input than
		     * previous lowest, save this one as the "next" one.
		     */
		    bcopy((char *)newname, (char *)lowest, 15 * sizeof(oid));
		    LowState = 0;
		    Lowinpcb = inpcb;
		}
	    }
	}
	if (LowState < 0) return(NULL);
	bcopy((char *)lowest, (char *)name, ((int)vp->namelen + 10) * sizeof(oid));
	*length = vp->namelen + 5;
	*write_method = 0;
	*var_len = sizeof(long);
	switch (vp->magic) {
	    case UDPLOCALADDRESS:
		return (u_char *) &Lowinpcb.inp_laddr.s_addr;
	    case UDPLOCALPORT:
		long_return = ntohs(Lowinpcb.inp_lport);
		return (u_char *) &long_return;
	    default:
		ERROR("");
	}
}

#else /* solaris2 - udp */

u_char *
var_udp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    mib2_udp_t udpstat;
    mib2_ip_t ipstat;
    u_char *ret = (u_char *)&long_return;	/* Successful completion */

    if (header_udp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;


    /*
     *	Get the UDP statistics from the kernel...
     */
    if (getMibstat(MIB_UDP, &udpstat, sizeof(mib2_udp_t), GET_FIRST, &Get_everything, NULL) < 0)
      return (NULL);		/* Things are ugly ... */

    switch (vp->magic){
	case UDPNOPORTS:
		if (getMibstat(MIB_IP, &ipstat, sizeof(mib2_ip_t), GET_FIRST, &Get_everything, NULL) < 0)
		  return (NULL);		/* Things are ugly ... */
		long_return = ipstat.udpNoPorts;
		break;
	case UDPINDATAGRAMS:
      		long_return = udpstat.udpInDatagrams;
      		break;
	case UDPOUTDATAGRAMS:
      		long_return = udpstat.udpOutDatagrams;
      		break;
	case UDPINERRORS:
      		long_return = udpstat.udpInErrors;
      		break;
	default:
		ret = NULL;
		ERROR("");
    }
    return (ret);
}

u_char *
var_udpEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    return NULL;
}
#endif /* solaris2 - udp */


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

static struct inpcb udp_inpcb, *udp_prev;
static void UDP_Scan_Init()
{
    KNLookup(udp_nl, N_UDB, (char *)&udp_inpcb, sizeof(udp_inpcb));
#if !(defined(freebsd2) || defined(netbsd1))
    udp_prev = (struct inpcb *) udp_nl[N_UDB].n_value;
#endif
}

static int UDP_Scan_Next(RetInPcb)
struct inpcb *RetInPcb;
{
	register struct inpcb *next;

#if defined(freebsd2) || defined(netbsd1)
	if ((udp_inpcb.inp_next == NULL) ||
	    (udp_inpcb.inp_next == (struct inpcb *) udp_nl[N_UDB].n_value)) {
#else
	if (udp_inpcb.inp_next == (struct inpcb *) udp_nl[N_UDB].n_value) {
#endif
	    return(0);	    /* "EOF" */
	}

	next = udp_inpcb.inp_next;

	klookup((unsigned long)next, (char *)&udp_inpcb, sizeof (udp_inpcb));
#if !(defined(netbsd1) || defined(freebsd2) || defined(linux))
	if (udp_inpcb.inp_prev != udp_prev)	   /* ??? */
          return(-1); /* "FAILURE" */
#endif
	*RetInPcb = udp_inpcb;
#if !(defined(netbsd1) || defined(freebsd2))
	udp_prev = next;
#endif
	return(1);	/* "OK" */
}
