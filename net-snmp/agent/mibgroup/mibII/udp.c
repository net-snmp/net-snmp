/*
 *  UDP MIB group implementation - udp.c
 *
 */

#include "mib_module_config.h"

#include <config.h>
#if STDC_HEADERS
#include <string.h>
#include <stdlib.h>
#else
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#endif
#include <sys/types.h>
#include <sys/param.h>
#include <sys/socket.h>

#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
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

#ifdef HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

#include <netinet/in_systm.h>
#include <netinet/ip.h>
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif
#include <netinet/udp.h>
#if HAVE_NETINET_UDP_VAR_H
#include <netinet/udp_var.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#ifdef solaris2
#include "kernel_sunos5.h"
#else
#include "kernel.h"
#endif
#include "../../../snmplib/system.h"

#include "mibincl.h"
#include "auto_nlist.h"

#ifdef hpux
#include <sys/mib.h>
#include <netinet/mib_kern.h>
#endif /* hpux */

/* #include "../common_header.h" */
#ifdef linux
#include "tcp.h"
#endif
#include "udp.h"

#ifdef CAN_USE_SYSCTL
#include <sys/sysctl.h>
#endif

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifndef solaris2
static void UDP_Scan_Init (void);
static int UDP_Scan_Next (struct inpcb *);
#endif
#ifdef linux
static void linux_read_udp_stat (struct udp_mib *);
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

struct variable8 udp_variables[] = {
    {UDPINDATAGRAMS, ASN_COUNTER, RONLY, var_udp, 1, {1}},
    {UDPNOPORTS, ASN_COUNTER, RONLY, var_udp, 1, {2}},
    {UDPINERRORS, ASN_COUNTER, RONLY, var_udp, 1, {3}},
    {UDPOUTDATAGRAMS, ASN_COUNTER, RONLY, var_udp, 1, {4}},
    {UDPLOCALADDRESS, ASN_IPADDRESS, RONLY, var_udpEntry, 3, {5, 1, 1}},
    {UDPLOCALPORT, ASN_INTEGER, RONLY, var_udpEntry, 3, {5, 1, 2}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
oid udp_variables_oid[] = { 1,3,6,1,2,1,7 };

void init_udp()
{

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/udp", udp_variables, variable8, udp_variables_oid);

#ifdef UDPSTAT_SYMBOL
  auto_nlist( UDPSTAT_SYMBOL,0,0 );
#endif
#ifdef UDB_SYMBOL
  auto_nlist( UDB_SYMBOL,0,0 );
#endif
}


#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

/*
  header_udp(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/

static int
header_udp(struct variable *vp,
	   oid *name,
	   int *length,
	   int exact,
	   int *var_len,
	   int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
{
#define UDP_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGMSGTL(("mibII/udp", "var_udp: %s %d\n", c_oid, exact));
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[UDP_NAME_LENGTH] = 0;
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
#ifndef MIB_UDPCOUNTER_SYMBOL
#ifndef HAVE_SYS_TCPIPSTATS_H

u_char *
var_udp(struct variable *vp,
	oid *name,
	int *length,
	int exact,
	int *var_len,
	int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
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

#if !defined(CAN_USE_SYSCTL) || !defined(UDPCTL_STATS)
#ifndef linux
    auto_nlist(UDPSTAT_SYMBOL, (char *)&udpstat, sizeof (udpstat));
#else
    linux_read_udp_stat(&udpstat);
#endif
#else /* can use sysctl(3) and have net.inet.udp.stats */
    {
	    static int sname[] 
		    = { CTL_NET, PF_INET, IPPROTO_UDP, UDPCTL_STATS };
	    size_t len;

	    len = sizeof udpstat;
	    if (sysctl(sname, 4, &udpstat, &len, 0, 0) < 0)
		    return NULL;
    }
#endif

    switch (vp->magic) {
	case UDPINDATAGRAMS:
#if defined(freebsd2) || defined(netbsd1) || defined(openbsd2)
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
#if defined(freebsd2) || defined(netbsd1) || defined(openbsd2)
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
#if defined(freebsd2) || defined(netbsd1) || defined(openbsd2)
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

#else /* HAVE_SYS_TCPIPSTATS_H */


u_char *
var_udp(struct variable *vp,
	oid *name,
	int *length,
	int exact,
	int *var_len,
	int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
{
    static struct kna tcpipstats;

    if (header_udp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    if (sysmp (MP_SAGET, MPSA_TCPIPSTATS, &tcpipstats, sizeof tcpipstats) == -1) {
	perror ("sysmp(MP_SAGET)(MPSA_TCPIPSTATS)");
    }
#define udpstat tcpipstats.udpstat

    switch (vp->magic){
	case UDPINDATAGRAMS:
	    long_return = udpstat.udps_ipackets;
	    return (u_char *) &long_return;
	case UDPNOPORTS:
	    long_return = udpstat.udps_noport;
	    return (u_char *) &long_return;
	case UDPOUTDATAGRAMS:
	    long_return = udpstat.udps_opackets;
	    return (u_char *) &long_return;
	case UDPINERRORS:
	    long_return = udpstat.udps_hdrops + udpstat.udps_badsum +
	      udpstat.udps_badlen;
	    return (u_char *) &long_return;
	default:
	    ERROR_MSG("");
    }
    return NULL;
}

#endif /* HAVE_SYS_TCPIPSTATS_H */

#else /* hpux */

u_char *
var_udp(struct variable *vp,
	oid *name,
	int *length,
	int exact,
	int *var_len,
	int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
{
    static struct udpstat udpstat;
    static	counter MIB_udpcounter[MIB_udpMAXCTR+1];

    if (header_udp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *        Get the UDP statistics from the kernel...
     */

    auto_nlist(UDPSTAT_SYMBOL, (char *)&udpstat, sizeof (udpstat));
    auto_nlist(MIB_UDPCOUNTER_SYMBOL, (char *)&MIB_udpcounter,
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
var_udpEntry(struct variable *vp,
	     oid *name,
	     int *length,
	     int exact,
	     int *var_len,
	     int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
{
    int i;
    oid newname[MAX_NAME_LEN], lowest[MAX_NAME_LEN], *op;
    u_char *cp;
    int LowState;
    static struct inpcb inpcb, Lowinpcb;

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
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
		if (snmp_oid_compare(newname, 15, name, *length) == 0){
		    memcpy( (char *)lowest,(char *)newname, 15 * sizeof(oid));
		    LowState = 0;
		    Lowinpcb = inpcb;
		    break;  /* no need to search further */
		}
	    } else {
		if ((snmp_oid_compare(newname, 15, name, *length) > 0) &&
		     ((LowState < 0) || (snmp_oid_compare(newname, 15, lowest, 15) < 0))){
		    /*
		     * if new one is greater than input and closer to input than
		     * previous lowest, save this one as the "next" one.
		     */
		    memcpy( (char *)lowest,(char *)newname, 15 * sizeof(oid));
		    LowState = 0;
		    Lowinpcb = inpcb;
		}
	    }
	}
	if (LowState < 0) return(NULL);
	memcpy( (char *)name,(char *)lowest, ((int)vp->namelen + 10) * sizeof(oid));
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
var_udp(struct variable *vp,
	oid *name,
	int *length,
	int exact,
	int *var_len,
	int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
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
var_udpEntry(struct variable *vp,
	     oid *name,
	     int *length,
	     int exact,
	     int *var_len,
	     int (**write_method) (int, u_char *,u_char, int, u_char *,oid*, int))
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

static void UDP_Scan_Init(void)
{
#ifndef linux
    auto_nlist(UDB_SYMBOL, (char *)&udp_inpcb, sizeof(udp_inpcb));
#if !(defined(freebsd2) || defined(netbsd1) || defined(openbsd2))
    udp_prev = (struct inpcb *) auto_nlist_value(UDB_SYMBOL);
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

static int UDP_Scan_Next(struct inpcb *RetInPcb)
{
	register struct inpcb *next;

#ifndef linux
	if ((udp_inpcb.INP_NEXT_SYMBOL == NULL) ||
	    (udp_inpcb.INP_NEXT_SYMBOL ==
             (struct inpcb *) auto_nlist_value(UDB_SYMBOL))) {
	    return(0);	    /* "EOF" */
	}

        next = udp_inpcb.INP_NEXT_SYMBOL;

	klookup((unsigned long)next, (char *)&udp_inpcb, sizeof (udp_inpcb));
#if !(defined(netbsd1) || defined(freebsd2) || defined(linux) || defined(openbsd2))
	if (udp_inpcb.INP_PREV_SYMBOL != udp_prev)	   /* ??? */
          return(-1); /* "FAILURE" */
#endif
	*RetInPcb = udp_inpcb;
#if !(defined(netbsd1) || defined(freebsd2) || defined(openbsd2))
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
linux_read_udp_stat (struct udp_mib *udpstat)
{
  FILE *in = fopen ("/proc/net/snmp", "r");
  char line [1024];

  memset ((char *) udpstat,(0), sizeof (*udpstat));

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
