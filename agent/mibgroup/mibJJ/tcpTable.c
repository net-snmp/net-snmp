/*
 *  TCP MIB group Table implementation - tcpTable.c
 *
 */

#include <config.h>
#include "mibincl.h"

#include <unistd.h>

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_PROTOSW_H
#include <sys/protosw.h>
#endif

#if HAVE_SYS_SYSMP_H
#include <sys/sysmp.h>
#endif
#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#include <net/if.h>
#if HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
#ifdef _I_DEFINED_KERNEL
#undef _KERNEL
#endif
#if HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#if HAVE_NET_ROUTE_H
#include <net/route.h>
#endif
#if HAVE_NETINET_IN_SYSTM_H
#include <netinet/in_systm.h>
#endif
#include <netinet/ip.h>
#ifdef INET6
#include <netinet/ip6.h>
#endif
#if HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#endif
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif
#ifdef INET6
#if HAVE_NETINET6_IP6_VAR_H
#include <netinet6/ip6_var.h>
#endif
#endif
#if HAVE_SYS_SOCKETVAR_H
#include <sys/socketvar.h>
#endif
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#endif
#ifdef solaris2
#include "kernel_sunos5.h"
#else
#include "kernel.h"
#endif

#include "system.h"
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if defined(osf4) || defined(aix4) || defined(hpux10)
/* these are undefed to remove a stupid warning on osf compilers
   because they get redefined with a slightly different notation of the
   same value.  -- Wes */
#undef TCP_NODELAY
#undef TCP_MAXSEG
#endif
#include <netinet/tcp.h>
#if HAVE_NETINET_TCPIP_H
#include <netinet/tcpip.h>
#endif
#if HAVE_NETINET_TCP_TIMER_H
#include <netinet/tcp_timer.h>
#endif
#if HAVE_NETINET_TCP_VAR_H
#include <netinet/tcp_var.h>
#endif
#if HAVE_NETINET_TCP_FSM_H
#include <netinet/tcp_fsm.h>
#endif
#if HAVE_SYS_TCPIPSTATS_H
#include <sys/tcpipstats.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "auto_nlist.h"

#ifdef hpux
#include <sys/mib.h>
#include "kernel_hpux.h"
#endif /* hpux */

#include "tcp.h"
#include "tcpTable.h"
#include "util_funcs.h"

#ifndef TCP_TABLE_CACHE_TIMEOUT
#define TCP_TABLE_CACHE_TIMEOUT MIB_STATS_CACHE_TIMEOUT
#endif

mib_table_t tcp_table;

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef solaris2
#define TCP_CONNECT_ENTRY_TYPE	mib2_tcpConnEntry_t
#define	TCP_LOCALADDR_FIELD	tcpConnLocalAddress
#define	TCP_LOCALPORT_FIELD	tcpConnLocalPort
#define	TCP_REMOTEADDR_FIELD	tcpConnRemAddress
#define	TCP_REMOTEPORT_FIELD	tcpConnRemPort
#define	TCP_STATE_FIELD		tcpConnState
#endif

#ifdef hpux
#define TCP_CONNECT_ENTRY_TYPE	mib_tcpConnEnt
#define	TCP_LOCALADDR_FIELD	LocalAddress
#define	TCP_LOCALPORT_FIELD	LocalPort
#define	TCP_REMOTEADDR_FIELD	RemAddress
#define	TCP_REMOTEPORT_FIELD	RemPort
#define	TCP_STATE_FIELD		State
#endif


#ifndef TCP_CONNECT_ENTRY_TYPE
#define TCP_CONNECT_ENTRY_TYPE	struct inpcb
#define	TCP_LOCALADDR_FIELD	inp_laddr.s_addr
#define	TCP_LOCALPORT_FIELD	inp_lport
#define	TCP_REMOTEADDR_FIELD	inp_faddr.s_addr
#define	TCP_REMOTEPORT_FIELD	inp_fport
#ifdef linux
#define	TCP_STATE_FIELD		inp_state
#else
#define	TCP_STATE_FIELD		inp_flags	/* Re-use an unneeded field */
#endif
#endif

TCP_CONNECT_ENTRY_TYPE* search_tcp(oid*, int, int);

int load_tcp_list( mib_table_t );
int tcp_compare(const void*, const void *);

	/*********************
	 *
	 *  Initialisation
	 *
	 *********************/

struct variable2 tcpEntry_variables[] = {
    {TCPCONNSTATE,        ASN_INTEGER,   RONLY, var_tcpEntry, 1, {1}},
    {TCPCONNLOCALADDRESS, ASN_IPADDRESS, RONLY, var_tcpEntry, 1, {2}},
    {TCPCONNLOCALPORT,    ASN_INTEGER,   RONLY, var_tcpEntry, 1, {3}},
    {TCPCONNREMADDRESS,   ASN_IPADDRESS, RONLY, var_tcpEntry, 1, {4}},
    {TCPCONNREMPORT,      ASN_INTEGER,   RONLY, var_tcpEntry, 1, {5}}
};

oid tcpEntry_variables_oid[] = { SNMP_OID_MIB2,6,13,1 };
void
init_tcpTable( void )
{
    REGISTER_MIB("mibII/tcpTable", tcpEntry_variables, variable2, tcpEntry_variables_oid);
    tcp_table = Initialise_Table( sizeof(TCP_CONNECT_ENTRY_TYPE),
				  TCP_TABLE_CACHE_TIMEOUT,
				  load_tcp_list, tcp_compare );
}


	/*********************
	 *
	 *  Main variable handling routine
	 *
	 *********************/


u_char *
var_tcpEntry(struct variable *vp,
	     oid *name,
	     size_t *length,
	     int exact,
	     size_t *var_len,
	     WriteMethod **write_method)
{
    int i, state;
    oid newname[MAX_OID_LEN], *op;
    u_char *cp;
    TCP_CONNECT_ENTRY_TYPE *entry;

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
		 *  Search for the relevant TCP entry,
		 *   either the index just identified,
		 *   or the next one, depending on whether
		 *   this is an exact match or not.
		 */
    entry = search_tcp( op, i, exact );
    if ( !entry )
	return NULL;

		/*
		 * We've found something we can use.
		 *  Update the 'newname' with the relevant index
		 */
    memcpy((char *)newname, (char *)vp->name, (int)vp->namelen * sizeof(oid));
    op = newname + vp->namelen;
    cp = (u_char *)&(entry->TCP_LOCALADDR_FIELD);
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = entry->TCP_LOCALPORT_FIELD;
    cp = (u_char *)&(entry->TCP_REMOTEADDR_FIELD);
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = entry->TCP_REMOTEPORT_FIELD;
   
    memcpy( (char *)name,(char *)newname, (vp->namelen + 10) * sizeof(oid));
    *length = vp->namelen + 10;
    *write_method = 0;
    switch (vp->magic) {
	    case TCPCONNSTATE: {
		*var_len = sizeof(long);
		long_return = entry->TCP_STATE_FIELD;
		return (u_char *) &long_return;
	    }
	    case TCPCONNLOCALADDRESS:
		*var_len = sizeof(entry->TCP_LOCALADDR_FIELD);
		return (u_char *) &entry->TCP_LOCALADDR_FIELD;
	    case TCPCONNLOCALPORT:
		*var_len = sizeof(long);
		long_return = entry->TCP_LOCALPORT_FIELD;
		return (u_char *) &long_return;
	    case TCPCONNREMADDRESS:
		*var_len = sizeof(entry->TCP_REMOTEADDR_FIELD);
		return (u_char *) &entry->TCP_REMOTEADDR_FIELD;
	    case TCPCONNREMPORT:
		*var_len = sizeof(long);
		long_return = entry->TCP_REMOTEPORT_FIELD;
		return (u_char *) &long_return;
	    default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_tcpEntry\n", vp->magic));
	}
    return NULL;
}


	/*********************
	 *
	 *  System-independent implementation functions
	 *
	 *********************/

#if !( defined(solaris2) || defined( linux ) || defined(hpux) )
int tcp_established_connections=0;

int TCP_Count_Connections (void)
{
    return tcp_established_connections;
}
#endif

	/*
	 *  Search the list of TCP entries and return
	 *    the appropriate one for this query
	 */

TCP_CONNECT_ENTRY_TYPE* search_tcp(oid* idx, int idx_len, int exact)
{
    static TCP_CONNECT_ENTRY_TYPE entry;
    char *cp;
    oid  *op;

    if ( exact && idx_len != 10 )
	return NULL;

    if ( idx_len < 10 ) {
	entry.TCP_LOCALADDR_FIELD  = 0;
	entry.TCP_LOCALPORT_FIELD  = 0;
	entry.TCP_REMOTEADDR_FIELD = 0;
	entry.TCP_REMOTEPORT_FIELD = 0;
    }
    else {
        cp = (char *)&entry.TCP_LOCALADDR_FIELD;
	op = idx;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
	entry.TCP_LOCALPORT_FIELD = *op++;
        cp = (char *)&entry.TCP_REMOTEADDR_FIELD;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
	entry.TCP_REMOTEPORT_FIELD = *op++;
    }

    if ( Search_Table( tcp_table, (void*)&entry, exact ) == 0 )
	return &entry;
    else
	return NULL;
}

	/*
	 *  Compare two TCP entries
	 */
int
tcp_compare(const void* first, const void* second)
{
    const TCP_CONNECT_ENTRY_TYPE *tcp1 = (const TCP_CONNECT_ENTRY_TYPE *) first;
    const TCP_CONNECT_ENTRY_TYPE *tcp2 = (const TCP_CONNECT_ENTRY_TYPE *) second;
    int res;

    res = tcp1->TCP_LOCALADDR_FIELD - tcp2->TCP_LOCALADDR_FIELD;
    if ( res != 0 )
	return res;

    res = tcp1->TCP_LOCALPORT_FIELD - tcp2->TCP_LOCALPORT_FIELD;
    if ( res != 0 )
	return res;

    res = tcp1->TCP_REMOTEADDR_FIELD - tcp2->TCP_REMOTEADDR_FIELD;
    if ( res != 0 )
	return res;

    return (tcp1->TCP_LOCALADDR_FIELD - tcp2->TCP_LOCALADDR_FIELD);
}



	/*********************
	 *
	 *  System-specific functions to read
	 *   in the list of TCP entries
	 *
	 *********************/

#ifdef linux
static int StateMap[]={1, 5, 3,  4, 6, 7, 11,  1,  8, 9,  2, 10 };
#else
static int StateMap[]={1, 2, 3,  4, 5, 8,  6, 10,  9, 7, 11};
#endif

#define TRANSLATE_STATE( state )	\
	((state & 0xf) < sizeof(StateMap)/sizeof(int) ? 	\
				StateMap[state & 0xf] : 1 )

#ifdef  solaris2
#define LOAD_TCP_LIST
TCP_Cmp(void *addr, void *ep)
{
  if (memcmp((mib2_tcpConnEntry_t *)ep,(mib2_tcpConnEntry_t *)addr,
	     sizeof(mib2_tcpConnEntry_t))  == 0)
    return (0);
  else
    return (1);
}

int load_tcp_list( mib_table_t t )
{
    mib2_tcpConnEntry_t entry;
    req_e req_type;

    entry.tcpConnLocalAddress = (u_long)-1;
    req_type = GET_FIRST;

    while ( !getMibstat(MIB_TCP_CONN, &entry, sizeof(mib2_tcpConnEntry_t)
		req_type, &TCP_Cmp, &entry)) {

	if (Add_Entry( t, (void*)&entry ) < 0 )
	    break;
	req_type = GET_NEXT;
    }
    return 0;
}
#endif

#ifdef  hpux
#define LOAD_TCP_LIST
int load_tcp_list( mib_table_t t )
{
    int numEntries, size, i;
    mib_tcpConnEnt *entries;

   if (hpux_read_stat((char *)&numEntries, sizeof(int), ID_tcpConnNumEnt) == -1)
	return -1;

    size = numEntries*sizeof(mib_tcpConnEnt);
    if ( (entries=(mib_tcpConnEnt *)malloc ( size )) == NULL )
	return -1;

    if (hpux_read_stat((char *)entries, size, ID_tcpConnTable) == -1) {
	free( entries );
	return -1;
    }

				/* Or add all in one go ? */
    for ( i = 0 ; i<numEntries ; i++ )
	if ( Add_Entry( t, (void*)&(entries[i])) < 0 )
	    break;
    free( entries );
    return 0;
}
#endif

#ifdef  linux
#define LOAD_TCP_LIST
int load_tcp_list( mib_table_t t )
{
    FILE *in;
    char line [256];
    struct inpcb pcb;
    unsigned int state, lport, fport;

    if (! (in = fopen ("/proc/net/tcp", "r"))) {
 	snmp_log(LOG_ERR, "snmpd: cannot open /proc/net/tcp ...\n");
	return -1;
    }

    while (line == fgets (line, sizeof(line), in)) {
	if (5 != sscanf (line, "%*d: %x:%x %x:%x %x", 
			 &pcb.TCP_LOCALADDR_FIELD,  &lport,
			 &pcb.TCP_REMOTEADDR_FIELD, &fport, &state))
	  continue;

	pcb.TCP_LOCALPORT_FIELD  = lport;
	pcb.TCP_REMOTEPORT_FIELD = fport;
	pcb.TCP_STATE_FIELD      = TRANSLATE_STATE( state );

	if (Add_Entry( t, (void*)&pcb ) < 0 )
	    break;
    }

    fclose (in);
    return 0;
}
#endif

#if defined(CAN_USE_SYSCTL) && defined(TCPCTL_PCBLIST)
#define LOAD_TCP_LIST
int load_tcp_list( mib_table_t t )
{
    size_t len;
    int sname[] = { CTL_NET, PF_INET, IPPROTO_TCP, TCPCTL_PCBLIST };
    char *tcpcb_buf = NULL;
    struct xinpgen *xig = NULL;
#ifdef freebsd4
    struct inpcb pcb;
#else
    struct xinpcb pcb;	/* XXX For which platforms is this correct? ERD */
#endif
    int state;

    xig = NULL;

		/*
		 * The TCP table is stored as a sequence of
		 *  (variable-length) entries, end-to-end in memory
		 * Read in this buffer.
		 */
    len = 0;
    if (sysctl(sname, 4, 0, &len, 0, 0) < 0) {
	return -1;
    }
    if ((tcpcb_buf = malloc(len)) == NULL) {
	return -1;
    }
    if (sysctl(sname, 4, tcpcb_buf, &len, 0, 0) < 0) {
	free(tcpcb_buf);
	return -1;
    }

		/*
		 * Locate the first entry
		 */
    xig = (struct xinpgen *)tcpcb_buf;
    xig = (struct xinpgen *)((char *)xig + xig->xig_len);
    tcp_established_connections = 0;

		/*
		 * Build up a linked list of entries
		 *  (We're mostly interested in the 'struct xinpcb' bit)
		 */
    for ( ; xig ; xig = (struct xinpgen *)((char *)xig + xig->xig_len)) {
	if (xig->xig_len <= sizeof(struct xinpgen))
	    break;

	memcpy( &pcb, &((struct xinpcb *)xig)->xi_inp, sizeof (struct inpcb));
	state = ((struct xtcpcb *)xig)->xt_tp.t_state;
	pcb.TCP_STATE_FIELD = TRANSLATE_STATE( state );
	if (( state == TCPS_ESTABLISHED) || (state == TCPS_CLOSE_WAIT))
		tcp_established_connections++;
	pcb.inp_lport = htons(pcb.inp_lport);
	pcb.inp_fport = htons(pcb.inp_fport);

	if (Add_Entry( t, (void*)&pcb ) < 0 )
	    break;

	xig = (struct xinpgen *)((char *)xig + xig->xig_len);
    }

    free(tcpcb_buf);
    return 0;
}
#endif

#ifndef LOAD_TCP_LIST
int load_tcp_list( mib_table_t t )
{
#ifdef PCB_TABLE
    struct inpcbtable table;
#endif
    struct inpcb pcb;
    struct inpcb *kernel_head, *kernel_next;
    struct tcpcb tcpcb;
    int state;

		/*
		 * Locate the address of the first PCB entry
		 */
#ifdef PCB_TABLE
    auto_nlist(TCP_SYMBOL, (char *)&table, sizeof(table));
    memcpy(kernel_head, table.inpt_queue.cqh_first, sizeof (struct inpcb));
#else
    kernel_head = (struct inpcb*)auto_nlist_value (TCP_SYMBOL);
#endif

		/*
		 * Walk through the kernel values,
		 *  creating new entries and adding them to the list
		 */
    kernel_next = kernel_head;
    tcp_established_connections = 0;

    while ( kernel_next ) {

	klookup((unsigned long)kernel_next, (char *)&pcb, sizeof(struct inpcb));
	klookup ( (int)pcb.inp_ppcb, (char *)&tcpcb, sizeof (tcpcb));
	state = tcpcb.t_state ;

	pcb.TCP_STATE_FIELD = TRANSLATE_STATE( state );
	if (( state == TCPS_ESTABLISHED) ||
	    (tcpcb.t_state == TCPS_CLOSE_WAIT))
		tcp_established_connections++;

	if (Add_Entry( t, (void*)&pcb ) < 0 )
	    break;

	kernel_next = pcb.INP_NEXT_SYMBOL;
	if ( kernel_next == kernel_head )
	    break;
    }
    return 0;
}
#endif
