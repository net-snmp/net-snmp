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

#ifndef linux
static struct nlist udp_nl[] = {
#define N_UDPSTAT	0
#define N_UDB		1
#define N_HP_UDPMIB	2
#if !defined(hpux) && !defined(solaris2)
	{ "_udpstat" },
#ifdef netbsd1
	{ "_udbtable" },
#else
	{ "_udb" },
#endif
#else
	{ "udpstat" },
	{ "udb" },
#ifdef hpux
	{ "MIB_udpcounter" },
#endif
#endif
        { 0 },
};
#endif

static int header_udp __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#ifndef solaris2
static void UDP_Scan_Init __P((void));
static int UDP_Scan_Next __P((struct inpcb *));
#endif
#ifdef linux
static void linux_read_udp_stat __P((struct udp_mib *));
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_udp( )
{
#ifndef linux
    init_nlist( udp_nl );
#endif
}


#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

static int
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
}

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

#ifndef linux
    KNLookup(udp_nl, N_UDPSTAT, (char *)&udpstat, sizeof (udpstat));
#else
    linux_read_udp_stat(&udpstat);
#endif

    switch (vp->magic){
	case UDPINDATAGRAMS:
#if defined(freebsd2) || defined(netbsd1)
	    long_return = udpstat.udps_ipackets;
#else
#if defined(linux)
	    long_return = udpstat.UdpInDatagrams;
#else
	    long_return = 0;
#endif
#endif
	    return (u_char *) &long_return;
	case UDPNOPORTS:
#if defined(freebsd2) || defined(netbsd1)
	    long_return = udpstat.udps_noport;
#else
#if defined(linux)
	    long_return = udpstat.UdpNoPorts;
#else
	    long_return = 0;
#endif
#endif
	    return (u_char *) &long_return;
	case UDPOUTDATAGRAMS:
#if defined(freebsd2) || defined(netbsd1)
	    long_return = udpstat.udps_opackets;
#else
#if defined(linux)
	    long_return = udpstat.UdpOutDatagrams;
#else
	    long_return = 0;
#endif
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
	    ERROR_MSG("");
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
	    ERROR_MSG("");
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
		ERROR_MSG("");
	}
    return  NULL;
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
		ERROR_MSG("");
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

#ifdef linux
static struct inpcb *udp_inpcb_list;
#endif

#ifndef solaris2
static struct inpcb udp_inpcb, *udp_prev;

static void UDP_Scan_Init()
{
#ifndef linux
    KNLookup(udp_nl, N_UDB, (char *)&udp_inpcb, sizeof(udp_inpcb));
#if !(defined(freebsd2) || defined(netbsd1))
    udp_prev = (struct inpcb *) udp_nl[N_UDB].n_value;
#endif
#else /* linux */
    FILE *in;
    char line [256];
    struct inpcb **pp;
    struct timeval now;
    static unsigned long Time_Of_Last_Reload = 0;

    /*
     * save some cpu-cycles, and reload after 5 secs...
     */
    gettimeofday (&now, (struct timezone *) 0);
    if (Time_Of_Last_Reload + 5 > now.tv_sec)
      {
	udp_prev = udp_inpcb_list;
	return;
      }
    Time_Of_Last_Reload = now.tv_sec;


    if (! (in = fopen ("/proc/net/udp", "r")))
      {
	fprintf (stderr, "snmpd: cannot open /proc/net/udp ...\n");
	udp_prev = 0;
	return;
      }

    /* free old chain: */
    while (udp_inpcb_list)
      {
	struct inpcb *p = udp_inpcb_list;
	udp_inpcb_list = udp_inpcb_list->inp_next;
	free (p);
      }

    /* scan proc-file and append: */

    pp = &udp_inpcb_list;
    
    while (line == fgets (line, 256, in))
      {
	struct inpcb pcb, *nnew;
	unsigned int state, lport;

	if (3 != sscanf (line, "%*d: %x:%x %*x:%*x %x", 
			 &pcb.inp_laddr.s_addr, &lport, &state))
	  continue;

	if (state != 7)		/* fix me:  UDP_LISTEN ??? */
	  continue;

	pcb.inp_lport = htons ((unsigned short) (lport));
	pcb.inp_fport = htons (pcb.inp_fport);

	nnew = (struct inpcb *) malloc (sizeof (struct inpcb));
	*nnew = pcb;
	nnew->inp_next = 0;

	*pp = nnew;
	pp = & nnew->inp_next;
      }

    fclose (in);

    /* first entry to go: */
    udp_prev = udp_inpcb_list;
#endif /*linux */
}

static int UDP_Scan_Next(RetInPcb)
struct inpcb *RetInPcb;
{
	register struct inpcb *next;

#ifndef linux
#if defined(freebsd2)
	if ((udp_inpcb.inp_list.le_next == NULL) ||
	    (udp_inpcb.inp_list.le_next ==
             (struct inpcb *) udp_nl[N_UDB].n_value)) {
#else
#if defined(netbsd1)
	if ((udp_inpcb.inp_queue.cqe_next == NULL) ||
	    (udp_inpcb.inp_queue.cqe_next == (struct inpcb *) udp_nl[N_UDB].n_value)) {
#else
	if (udp_inpcb.inp_next == (struct inpcb *) udp_nl[N_UDB].n_value) {
#endif
#endif
	    return(0);	    /* "EOF" */
	}

#ifdef netbsd1
	next = udp_inpcb.inp_queue.cqe_next;
#else
#ifdef freebsd2
	next = udp_inpcb.inp_list.le_next;
#else
        next = udp_inpcb.inp_next;
#endif
#endif

	klookup((unsigned long)next, (char *)&udp_inpcb, sizeof (udp_inpcb));
#if !(defined(netbsd1) || defined(freebsd2) || defined(linux))
	if (udp_inpcb.inp_prev != udp_prev)	   /* ??? */
          return(-1); /* "FAILURE" */
#endif
	*RetInPcb = udp_inpcb;
#if !(defined(netbsd1) || defined(freebsd2))
	udp_prev = next;
#endif
#else /* linux */
	if (!udp_prev) return 0;

	udp_inpcb = *udp_prev;
	next = udp_inpcb.inp_next;
	*RetInPcb = udp_inpcb;
	udp_prev = next;
#endif linux
	return(1);	/* "OK" */
}
#endif /* solaris2 */

#ifdef linux

static void
linux_read_udp_stat (udpstat)
struct udp_mib *udpstat;
{
  FILE *in = fopen ("/proc/net/snmp", "r");
  char line [1024];

  bzero ((char *) udpstat, sizeof (*udpstat));

  if (! in)
    return;

  while (line == fgets (line, 1024, in))
    {
      if (4 == sscanf (line, "Udp: %lu %lu %lu %lu\n",
			&udpstat->UdpInDatagrams, &udpstat->UdpNoPorts,
			&udpstat->UdpInErrors, &udpstat->UdpOutDatagrams))
	break;
    }
  fclose (in);
}

#endif /* linux */
