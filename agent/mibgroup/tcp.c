
/*
 *  TCP MIB group implementation - tcp.c
 *
 */

#include "../common_header.h"
#include "tcp.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

static struct nlist tcp_nl[] = {
#define N_TCPSTAT	0
#define N_TCB		1
#define N_HP_TCPMIB	2
#if !defined(hpux) && !defined(solaris2)
	{ "_tcpstat" },
#ifdef netbsd1
	{ "_tcbtable" },
#else
	{ "_tcb" },
#endif
#else
	{ "tcpstat" },
	{ "tcb" },
#ifdef hpux
	{ "MIB_tcpcounter" },
#endif
#endif
        { 0 },
};


#ifdef linux
static void linux_read_tcp_stat ();
#endif
static int TCP_Count_Connections __P((void));
static void TCP_Scan_Init __P((void));
static int TCP_Scan_Next __P((int *, struct inpcb *));


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_tcp( )
{
    init_nlist( tcp_nl );
}

#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

int
header_tcp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
#define TCP_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_tcp: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[TCP_NAME_LENGTH] = 0;
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

u_char *
var_tcp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
    static struct tcpstat tcpstat;
#ifdef hpux
    static	counter MIB_tcpcounter[MIB_tcpMAXCTR+1];
#endif

    /*
     *	Allow for a kernel w/o TCP
     */
#ifndef linux
    if (tcp_nl[N_TCPSTAT].n_value == 0) return(NULL);
#endif

	if (header_tcp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	    return NULL;

	/*
	 *  Get the TCP statistics from the kernel...
	 */

#ifndef linux
	KNLookup(tcp_nl, N_TCPSTAT, (char *)&tcpstat, sizeof (tcpstat));
#ifdef hpux
	KNLookup(tcp_nl, N_HP_TCPMIB, (char *)&MIB_tcpcounter,
	    (MIB_tcpMAXCTR+1)*sizeof (counter));
#endif
#else /* linux */
	linux_read_tcp_stat (&tcpstat);
#endif /* linux */
	switch (vp->magic){
	    case TCPRTOALGORITHM:
#ifndef linux
		long_return = 4;	/* Van Jacobsen's algorithm *//* XXX */
#else
                if (! tcpstat.TcpRtoAlgorithm) {
		    /* 0 is illegal: assume `other' algorithm: */
		    long_return = 1;
		    return (u_char *) &long_return;
                }
                return (u_char *) &tcpstat.TcpRtoAlgorithm;
#endif
		return (u_char *) &long_return;
	    case TCPRTOMIN:
#ifndef linux
		long_return = TCPTV_MIN / PR_SLOWHZ * 1000;
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpRtoMin;
#endif
	    case TCPRTOMAX:
#ifndef linux
		long_return = TCPTV_REXMTMAX / PR_SLOWHZ * 1000;
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpRtoMax;
#endif
	    case TCPMAXCONN:
#ifndef linux
		long_return = -1;
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpMaxConn;
#endif
	    case TCPACTIVEOPENS:
		return (u_char *) &tcpstat.tcps_connattempt;
	    case TCPPASSIVEOPENS:
		return (u_char *) &tcpstat.tcps_accepts;
	    case TCPATTEMPTFAILS:
#ifdef hpux
		long_return = MIB_tcpcounter[7];
#else
		long_return = tcpstat.tcps_conndrops;	/* XXX */
#endif
		return (u_char *) &long_return;
	    case TCPESTABRESETS:
#ifdef hpux
		long_return = MIB_tcpcounter[8];
#else
		long_return = tcpstat.tcps_drops;	/* XXX */
#endif
		return (u_char *) &long_return;
		/*
		 * NB:  tcps_drops is actually the sum of the two MIB
		 *	counters tcpAttemptFails and tcpEstabResets.
		 */
	    case TCPCURRESTAB:
#ifndef linux
		long_return = TCP_Count_Connections();
		return (u_char *) &long_return;
#else
		return (u_char *) &tcpstat.TcpCurrEstab;
#endif
	    case TCPINSEGS:
		return (u_char *) &tcpstat.tcps_rcvtotal;
	    case TCPOUTSEGS:
		long_return = tcpstat.tcps_sndtotal
			    - tcpstat.tcps_sndrexmitpack;
		/*
		 * RFC 1213 defines this as the number of segments sent
		 * "excluding those containing only retransmitted octets"
		 */
		return (u_char *) &long_return;
	    case TCPRETRANSSEGS:
		return (u_char *) &tcpstat.tcps_sndrexmitpack;
#ifndef linux
	    case TCPINERRS:
		long_return = tcpstat.tcps_rcvbadsum + tcpstat.tcps_rcvbadoff 
#ifdef STRUCT_TCPSTAT_HAS_TCPS_RCVMEMDROP
                  + tcpstat.tcps_rcvmemdrop
#endif
                  + tcpstat.tcps_rcvshort;
		return (u_char *) &long_return;
	    case TCPOUTRSTS:
		long_return = tcpstat.tcps_sndctrl - tcpstat.tcps_closed;
		return (u_char *) &long_return;
#endif linux
	    default:
		ERROR("");
	}
    return NULL;
}

u_char *
var_tcpEntry(vp, name, length, exact, var_len, write_method)
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
    int State, LowState;
    static struct inpcb inpcb, Lowinpcb;
    
    /*
     *	Allow for a kernel w/o TCP
     */
#ifndef linux
    if (tcp_nl[N_TCPSTAT].n_value == 0) return(NULL);
#endif

	bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
	/* find "next" connection */
Again:
LowState = -1;	    /* Don't have one yet */
	TCP_Scan_Init();
	for (;;) {
	    if ((i = TCP_Scan_Next(&State, &inpcb)) < 0) goto Again;
	    if (i == 0) break;	    /* Done */
	    cp = (u_char *)&inpcb.inp_laddr.s_addr;
	    op = newname + 10;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    
	    newname[14] = ntohs(inpcb.inp_lport);

	    cp = (u_char *)&inpcb.inp_faddr.s_addr;
	    op = newname + 15;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    
	    newname[19] = ntohs(inpcb.inp_fport);

	    if (exact){
		if (compare(newname, 20, name, *length) == 0){
		    bcopy((char *)newname, (char *)lowest, 20 * sizeof(oid));
		    LowState = State;
		    Lowinpcb = inpcb;
		    break;  /* no need to search further */
		}
	    } else {
		if ((compare(newname, 20, name, *length) > 0) &&
		     ((LowState < 0) || (compare(newname, 20, lowest, 20) < 0))){
		    /*
		     * if new one is greater than input and closer to input than
		     * previous lowest, save this one as the "next" one.
		     */
		    bcopy((char *)newname, (char *)lowest, 20 * sizeof(oid));
		    LowState = State;
		    Lowinpcb = inpcb;
		}
	    }
	}
	if (LowState < 0) return(NULL);
	bcopy((char *)lowest, (char *)name, ((int)vp->namelen + 10) * sizeof(oid));
	*length = vp->namelen + 10;
	*write_method = 0;
	*var_len = sizeof(long);
	switch (vp->magic) {
	    case TCPCONNSTATE: {
#ifndef hpux
		static int StateMap[]={1, 2, 3, 4, 5, 8, 6, 10, 9, 7, 11};
#else
              static int StateMap[]={1, 2, 3, -1, 4, 5, 8, 6, 10, 9, 7, 11};
#endif
		return (u_char *) &StateMap[LowState];
	    }
	    case TCPCONNLOCALADDRESS:
		return (u_char *) &Lowinpcb.inp_laddr.s_addr;
	    case TCPCONNLOCALPORT:
		long_return = ntohs(Lowinpcb.inp_lport);
		return (u_char *) &long_return;
	    case TCPCONNREMADDRESS:
		return (u_char *) &Lowinpcb.inp_faddr.s_addr;
	    case TCPCONNREMPORT:
		long_return = ntohs(Lowinpcb.inp_fport);
		return (u_char *) &long_return;
	}
    return NULL;
}

#else  /* solaris2 - tcp */


static int
TCP_Cmp(void *addr, void *ep)
{
  if (memcmp((mib2_tcpConnEntry_t *)ep,(mib2_tcpConnEntry_t *)addr,
	     sizeof(mib2_tcpConnEntry_t))  == 0)
    return (0);
  else
    return (1);
}

u_char *
var_tcp(vp, name, length, exact, var_len, write_method)
register struct variable *vp;
oid     *name;
int     *length;
int     exact;
int     *var_len;
int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
  mib2_tcp_t tcpstat;
  mib2_ip_t ipstat;

    if (header_tcp(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    /*
     *  Get the TCP statistics from the kernel...
     */
    if (getMibstat(MIB_TCP, &tcpstat, sizeof(mib2_tcp_t), GET_FIRST, &Get_everything, NULL) < 0)
      return (NULL);		/* Things are ugly ... */

    switch (vp->magic){
    case TCPRTOALGORITHM:
      long_return = tcpstat.tcpRtoAlgorithm;
      return(u_char *) &long_return;
    case TCPRTOMIN:
      long_return = tcpstat.tcpRtoMin;
      return(u_char *) &long_return;
    case TCPRTOMAX:
      long_return = tcpstat.tcpRtoMax;
      return(u_char *) &long_return;
    case TCPMAXCONN:
      long_return = tcpstat.tcpMaxConn;
      return(u_char *) &long_return;
    case TCPACTIVEOPENS:
      long_return = tcpstat.tcpActiveOpens;
      return(u_char *) &long_return;
    case TCPPASSIVEOPENS:
      long_return = tcpstat.tcpPassiveOpens;
      return(u_char *) &long_return;
    case TCPATTEMPTFAILS:
      long_return = tcpstat.tcpAttemptFails;
      return(u_char *) &long_return;
    case TCPESTABRESETS:
      long_return = tcpstat.tcpEstabResets;
      return(u_char *) &long_return;
    case TCPCURRESTAB:
      long_return = tcpstat.tcpCurrEstab;
      return(u_char *) &long_return;
    case TCPINSEGS:
      long_return = tcpstat.tcpInSegs;
      return(u_char *) &long_return;
    case TCPOUTSEGS:
      long_return = tcpstat.tcpOutSegs;
      return(u_char *) &long_return;
    case TCPRETRANSSEGS:
      long_return = tcpstat.tcpRetransSegs;
      return(u_char *) &long_return;
    case TCPINERRS:
      if (getMibstat(MIB_IP, &ipstat, sizeof(mib2_ip_t), GET_FIRST, &Get_everything, NULL) < 0)
	return (NULL);		/* Things are ugly ... */
      long_return = ipstat.tcpInErrs;
      return(u_char *) &long_return;
    default:
      ERROR("");
      return (NULL);
    }
}


u_char *
var_tcpEntry(vp, name, length, exact, var_len, write_method)
register struct variable *vp;
oid     *name;
int     *length;
int     exact;
int     *var_len;
int     (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
{
  oid newname[MAX_NAME_LEN], lowest[MAX_NAME_LEN], *op;
  u_char *cp;
  int State, LowState;

#define TCP_CONN_LENGTH	20
#define TCP_LOCADDR_OFF	10
#define TCP_LOCPORT_OFF	14
#define TCP_REMADDR_OFF	15
#define TCP_REMPORT_OFF	19
    mib2_tcpConnEntry_t	Lowentry, Nextentry, entry;
    req_e  		req_type;
    int			Found = 0;
    
    memset (&Lowentry, 0, sizeof (Lowentry));
    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    if (*length == TCP_CONN_LENGTH) /* Assume that the input name is the lowest */
      bcopy((char *)name, (char *)lowest, TCP_CONN_LENGTH * sizeof(oid));
    for (Nextentry.tcpConnLocalAddress = (u_long)-1, req_type = GET_FIRST;
	 ;
	 Nextentry = entry, req_type = GET_NEXT) {
      if (getMibstat(MIB_TCP_CONN, &entry, sizeof(mib2_tcpConnEntry_t),
		 req_type, &TCP_Cmp, &entry) != 0)
	break;
      COPY_IPADDR(cp, (u_char *)&entry.tcpConnLocalAddress, op, newname + TCP_LOCADDR_OFF);
      newname[TCP_LOCPORT_OFF] = entry.tcpConnLocalPort;
      COPY_IPADDR(cp, (u_char *)&entry.tcpConnRemAddress, op, newname + TCP_REMADDR_OFF);
      newname[TCP_REMPORT_OFF] = entry.tcpConnRemPort;

      if (exact){
	if (compare(newname, TCP_CONN_LENGTH, name, *length) == 0){
	  bcopy((char *)newname, (char *)lowest, TCP_CONN_LENGTH * sizeof(oid));
	  Lowentry = entry;
	  Found++;
	  break;  /* no need to search further */
	}
      } else {
	if ((compare(newname, TCP_CONN_LENGTH, name, *length) > 0) &&
	    ((Nextentry.tcpConnLocalAddress == (u_long)-1)
	     || (compare(newname, TCP_CONN_LENGTH, lowest, TCP_CONN_LENGTH) < 0)
	     || (compare(name, TCP_CONN_LENGTH, lowest, TCP_CONN_LENGTH) == 0))){

	  /* if new one is greater than input and closer to input than
	   * previous lowest, and is not equal to it, save this one as the "next" one.
	   */
	  bcopy((char *)newname, (char *)lowest, TCP_CONN_LENGTH * sizeof(oid));
	  Lowentry = entry;
	  Found++;
	}
      }
    }
    if (Found == 0)
      return(NULL);
    bcopy((char *)lowest, (char *)name,
	  ((int)vp->namelen + TCP_CONN_LENGTH - TCP_LOCADDR_OFF) * sizeof(oid));
    *length = vp->namelen + TCP_CONN_LENGTH - TCP_LOCADDR_OFF;
    *write_method = 0;
    *var_len = sizeof(long);
    switch (vp->magic) {
    case TCPCONNSTATE:
      long_return = Lowentry.tcpConnState;
      return(u_char *) &long_return;
    case TCPCONNLOCALADDRESS:
      long_return = Lowentry.tcpConnLocalAddress;
      return(u_char *) &long_return;
    case TCPCONNLOCALPORT:
      long_return = Lowentry.tcpConnLocalPort;
      return(u_char *) &long_return;
    case TCPCONNREMADDRESS:
      long_return = Lowentry.tcpConnRemAddress;
      return(u_char *) &long_return;
    case TCPCONNREMPORT:
      long_return = Lowentry.tcpConnRemPort;
      return(u_char *) &long_return;
    default:
      ERROR("");
      return (NULL);
    }
}

#endif /* solaris2 - tcp */


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/


#ifdef linux
/*
 * lucky days. since 1.1.16 the tcp statistics are avail by the proc
 * file-system.
 */

static void
linux_read_tcp_stat (tcpstat)
struct tcp_mib *tcpstat;
{
  FILE *in = fopen ("/proc/net/snmp", "r");
  char line [1024];

  bzero ((char *) tcpstat, sizeof (*tcpstat));

  if (! in)
    return;

  while (line == fgets (line, 1024, in))
    {
      if (12 == sscanf (line, "Tcp: %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
	&tcpstat->TcpRtoAlgorithm, &tcpstat->TcpRtoMin, &tcpstat->TcpRtoMax, 
	&tcpstat->TcpMaxConn, &tcpstat->TcpActiveOpens, &tcpstat->TcpPassiveOpens,
	&tcpstat->TcpAttemptFails, &tcpstat->TcpEstabResets, &tcpstat->TcpCurrEstab, 
	&tcpstat->TcpInSegs, &tcpstat->TcpOutSegs, &tcpstat->TcpRetransSegs))
	break;
    }
  fclose (in);
}

#endif /* linux */


#ifdef netbsd1
#define inp_next inp_queue.cqe_next
#define inp_prev inp_queue.cqe_prev
#endif

#ifdef freebsd2
#define inp_next inp_list.le_next
#define inp_prev inp_list.le_prev
#endif

#ifndef linux
/*
 *	Print INTERNET connections
 */

static int TCP_Count_Connections __P((void))
{
	int Established;
	struct inpcb cb;
	register struct inpcb *prev, *next;
	struct inpcb inpcb;
	struct tcpcb tcpcb;

Again:	/*
	 *	Prepare to scan the control blocks
	 */
	Established = 0;

	KNLookup(tcp_nl, N_TCB, (char *)&cb, sizeof(struct inpcb));
	inpcb = cb;
#if !(defined(freebsd2) || defined(netbsd1))
	prev = (struct inpcb *) tcp_nl[N_TCB].n_value;
#endif /*  !(defined(freebsd2) || defined(netbsd1)) */
	/*
	 *	Scan the control blocks
	 */
#if defined(freebsd2) || defined(netbsd1)
	while ((inpcb.inp_next != NULL) && (inpcb.inp_next != (struct inpcb *) tcp_nl[N_TCB].n_value)) {
#else /*  defined(freebsd2) || defined(netbsd1) */
	while (inpcb.inp_next != (struct inpcb *) tcp_nl[N_TCB].n_value) {
#endif /*  defined(freebsd2) || defined(netbsd1) */
		next = inpcb.inp_next;

		if((klookup((unsigned long)next, (char *)&inpcb, sizeof (inpcb)) == 0)) {
		    perror("TCP_Count_Connections - inpcb");
		}
#if !(defined(freebsd2) || defined(netbsd1))
		if (inpcb.inp_prev != prev) {	    /* ??? */
			sleep(1);
			goto Again;
		}
#endif /*  !(defined(freebsd2) || defined(netbsd1)) */
		if (inet_lnaof(inpcb.inp_laddr) == INADDR_ANY) {
#if !(defined(freebsd2) || defined(netbsd1))
			prev = next;
#endif /*  !(defined(freebsd2) || defined(netbsd1)) */
			continue;
		}
		if(klookup((unsigned long)inpcb.inp_ppcb, (char *)&tcpcb, sizeof (tcpcb)) == 0) {
		    perror("TCP_Count_Connections - tcpcb");
		    break;
		}

		if ((tcpcb.t_state == TCPS_ESTABLISHED) ||
		    (tcpcb.t_state == TCPS_CLOSE_WAIT))
		    Established++;
#if !(defined(freebsd2) || defined(netbsd1))
		prev = next;
#endif /*  !(defined(freebsd2) || defined(netbsd1)) */
	}
	return(Established);
}
#endif
static struct inpcb tcp_inpcb, *tcp_prev;


static void TCP_Scan_Init __P((void))
{
    KNLookup(tcp_nl, N_TCB, (char *)&tcp_inpcb, sizeof(tcp_inpcb));
#if !(defined(freebsd2) || defined(netbsd1))
    tcp_prev = (struct inpcb *) tcp_nl[N_TCB].n_value;
#endif
}

static int TCP_Scan_Next(State, RetInPcb)
int *State;
struct inpcb *RetInPcb;
{
	register struct inpcb *next;
#ifndef linux
	struct tcpcb tcpcb;

#if defined(freebsd2) || defined(netbsd1)
	if ((tcp_inpcb.inp_next == NULL) ||
	    (tcp_inpcb.inp_next == (struct inpcb *) tcp_nl[N_TCB].n_value)) {
#else
	if (tcp_inpcb.inp_next == (struct inpcb *) tcp_nl[N_TCB].n_value) {
#endif
	    return(0);	    /* "EOF" */
	}

	next = tcp_inpcb.inp_next;

	klookup((unsigned long)next, (char *)&tcp_inpcb, sizeof (tcp_inpcb));
#if !(defined(netbsd1) || defined(freebsd2))
	if (tcp_inpcb.inp_prev != tcp_prev)	   /* ??? */
          return(-1); /* "FAILURE" */
#endif /*  !(defined(netbsd1) || defined(freebsd2)) */
	klookup ( (int)tcp_inpcb.inp_ppcb, (char *)&tcpcb, sizeof (tcpcb));
	*State = tcpcb.t_state;
#else /* linux */
	if (! tcp_prev)
	  return 0;

	tcp_inpcb = *tcp_prev;
	*State = tcp_inpcb.inp_state;
	next = tcp_inpcb.inp_next;
#endif

	*RetInPcb = tcp_inpcb;
#if !(defined(netbsd1) || defined(freebsd2))
	tcp_prev = next;
#endif
	return(1);	/* "OK" */
}
