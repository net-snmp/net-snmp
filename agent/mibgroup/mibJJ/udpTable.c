/*
 *  UDP MIB group Table implementation - udpTable.c
 *
 */

#include <config.h>
#include "mibincl.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/socket.h>

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
#if HAVE_SYS_QUEUE_H
#include <sys/queue.h>
#endif
#if HAVE_SYS_SOCKETVAR_H
#include <sys/socketvar.h>
#endif
#if HAVE_NETINET_IP_VAR_H
#include <netinet/ip_var.h>
#endif
#ifdef INET6
#if HAVE_NETINET6_IP6_VAR_H
#include <netinet6/ip6_var.h>
#endif
#endif
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#include <netinet/udp.h>
#if HAVE_NETINET_UDP_VAR_H
#include <netinet/udp_var.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif


#ifdef solaris2
#include "kernel_sunos5.h"
#else
#include "kernel.h"
#endif

#include "system.h"
#include "asn1.h"
#include "snmp_debug.h"

#include "auto_nlist.h"
#include "tools.h"
#include "util_funcs.h"

#ifdef hpux
#include <sys/mib.h>
#include "kernel_hpux.h"
#endif /* hpux */

#ifdef linux
#include "tcpTable.h"
#endif
#include "udp.h"
#include "udpTable.h"
#include "sysORTable.h"

#ifdef CAN_USE_SYSCTL
#include <sys/sysctl.h>
#endif

#ifndef UDP_TABLE_CACHE_TIMEOUT
#define UDP_TABLE_CACHE_TIMEOUT	MIB_STATS_CACHE_TIMEOUT
#endif

mib_table_t udp_table;

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef solaris2
#define UDP_ENTRY_TYPE	mib2_udpEntry_t
#define UDP_ADDRESS_FIELD	udpLocalAddress
#define UDP_PORT_FIELD		udpLocalPort
#endif

#ifdef hpux
#define UDP_ENTRY_TYPE	mib_udpLsnEnt
#define UDP_ADDRESS_FIELD	LocalAddress
#define UDP_PORT_FIELD		LocalPort
#endif

#ifndef UDP_ENTRY_TYPE
#define UDP_ENTRY_TYPE	struct inpcb
#define UDP_ADDRESS_FIELD	inp_laddr.s_addr
#define UDP_PORT_FIELD		inp_lport
#endif


UDP_ENTRY_TYPE *search_udp(oid*, int, int);

int load_udp_list( mib_table_t );
int udp_compare(const void*, const void *);

	/*********************
	 *
	 *  Initialisation
	 *
	 *********************/

struct variable2 udpEntry_variables[] = {
    {UDPLOCALADDRESS, ASN_IPADDRESS, RONLY, var_udpEntry, 1, {1}},
    {UDPLOCALPORT,    ASN_INTEGER,   RONLY, var_udpEntry, 1, {2}}
};

oid udpEntry_variables_oid[] = { SNMP_OID_MIB2,7,5,1 };

void
init_udpTable( void )
{
    REGISTER_MIB("mibII/udpTable", udpEntry_variables, variable2, udpEntry_variables_oid);
    udp_table = Initialise_Table( sizeof(UDP_ENTRY_TYPE),
				  UDP_TABLE_CACHE_TIMEOUT,
				  load_udp_list, udp_compare );
#ifdef UDB_SYMBOL
  auto_nlist( UDB_SYMBOL,0,0 );
#endif
}


	/*********************
	 *
	 *  Main variable handling routine
	 *
	 *********************/


u_char *
var_udpEntry(struct variable *vp,
	     oid *name,
	     size_t *length,
	     int exact,
	     size_t *var_len,
	     WriteMethod **write_method)
{
    int i;
    oid newname[MAX_OID_LEN], *op;
    u_char *cp;
    UDP_ENTRY_TYPE* udpEntry;

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
		 *  Search for the relevant UDP entry,
		 *   either the index just identified,
		 *   or the next one, depending on whether
		 *   this is an exact match or not.
		 */
    udpEntry = search_udp( op, i, exact );
    if ( !udpEntry )
	return NULL;

		/*
		 * We've found something we can use.
		 *  Update the 'newname' with the relevant index
		 */
    memcpy((char *)newname, (char *)vp->name, (int)vp->namelen * sizeof(oid));
    cp = (u_char *)&(udpEntry->UDP_ADDRESS_FIELD);
    op = newname + vp->namelen;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = udpEntry->UDP_PORT_FIELD;
   

    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 5) * sizeof(oid));
    *length = vp->namelen + 5;
    *write_method = 0;
    switch (vp->magic) {

	    case UDPLOCALADDRESS:
		*var_len = sizeof(udpEntry->UDP_ADDRESS_FIELD);
		long_return = udpEntry->UDP_ADDRESS_FIELD;
		return (u_char *) &long_return;
	    case UDPLOCALPORT:
		*var_len = sizeof(long);
		long_return = udpEntry->UDP_PORT_FIELD;
		return (u_char *) &long_return;
	    default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_udpEntry\n", vp->magic));
    }
    return  NULL;
}



	/*********************
	 *
	 *  System-independent implementation functions
	 *
	 *********************/


	/*
	 *  Search the list of UDP entries and return
	 *    the appropriate one for this query
	 */

UDP_ENTRY_TYPE* search_udp(oid* idx, int idx_len, int exact)
{
    static UDP_ENTRY_TYPE entry;
    char *cp;
    oid  *op;

    if ( exact && idx_len != 5 )
	return NULL;

    if ( idx_len < 5 ) {
		/* XXX - Not correct */
	entry.UDP_ADDRESS_FIELD = 0;
	entry.UDP_PORT_FIELD    = 0;
    }
    else {
        cp = (u_char *)&entry.UDP_ADDRESS_FIELD;
	op = idx;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
	entry.UDP_PORT_FIELD = *op++;
    }

    if ( Search_Table( udp_table, (void*)&entry, exact ) == 0 )
	return &entry;
    else
	return NULL;
}

	/*
	 *  Compare two UDP entries
	 */
int
udp_compare(const void* first, const void* second)
{
    const UDP_ENTRY_TYPE *udp1 = (const UDP_ENTRY_TYPE *) first;
    const UDP_ENTRY_TYPE *udp2 = (const UDP_ENTRY_TYPE *) second;

    if (udp1->UDP_ADDRESS_FIELD == udp2->UDP_ADDRESS_FIELD)
	return (udp1->UDP_PORT_FIELD - udp2->UDP_PORT_FIELD);

    return (udp1->UDP_ADDRESS_FIELD - udp2->UDP_ADDRESS_FIELD);
}


	/*********************
	 *
	 *  System-specific functions to read
	 *   in the list of UDP entries
	 *
	 *********************/

#ifdef  solaris2
#define LOAD_UDP_LIST
int load_udp_list( mib_table_t t )
{
     return -1;
}
#endif

#ifdef  hpux
#define LOAD_UDP_LIST
int load_udp_list( mib_table_t t )
{
    int numEntries, size, i;
    mib_udpLsnEnt *entries;

   if (hpux_read_stat((char *)&numEntries, sizeof(int), ID_udpLsnNumEnt) == -1)
	return -1;

    size = numEntries*sizeof(mib_udpLsnEnt);
    if ( (entries=(mib_udpLsnEnt *)malloc ( size )) == NULL )
	return -1;

    if (hpux_read_stat((char *)entries, size, ID_udpLsnTable) == -1) {
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

#ifdef linux
#define LOAD_UDP_LIST
int load_udp_list( mib_table_t t )
{
    FILE *in;
    char line [256];
    struct inpcb pcb;
    unsigned int state, lport;

    if (! (in = fopen ("/proc/net/udp", "r"))) {
 	snmp_log(LOG_ERR, "snmpd: cannot open /proc/net/udp ...\n");
	return -1;
    }

    while (line == fgets (line, sizeof(line), in)) {
	if (3 != sscanf (line, "%*d: %x:%x %*x:%*x %x", 
			 &pcb.inp_laddr.s_addr, &lport, &state))
	  continue;

	if (state != 7)		/* fix me:  UDP_LISTEN ??? */
	  continue;

	pcb.inp_lport = lport;
	if (Add_Entry( t, (void*)&pcb ) < 0 )
	    break;
    }
    return 0;
}
#endif

#if defined(CAN_USE_SYSCTL) && defined(UDPCTL_PCBLIST)
#define LOAD_UDP_LIST
int load_udp_list( mib_table_t t )
{
    size_t len;
    int sname[] = { CTL_NET, PF_INET, IPPROTO_UDP, UDPCTL_PCBLIST };
    char *udpcb_buf = NULL;
    struct xinpgen *xig = NULL;
    struct xinpcb *xpcb;

    xig = NULL;

		/*
		 * The UDP table is stored as a sequence of
		 *  (variable-length) entries, end-to-end in memory
		 * Read in this buffer.
		 */
    len = 0;
    if (sysctl(sname, 4, 0, &len, 0, 0) < 0) {
	return -1;
    }
    if ((udpcb_buf = malloc(len)) == NULL) {
	return -1;
    }
    if (sysctl(sname, 4, udpcb_buf, &len, 0, 0) < 0) {
	free(udpcb_buf);
	return -1;
    }

		/*
		 * Locate the first entry
		 */
    xig = (struct xinpgen *)udpcb_buf;
    xig = (struct xinpgen *)((char *)xig + xig->xig_len);

		/*
		 * Build up a linked list of entries
		 *  (We're only interested in the 'struct xinpcb' bit)
		 */
    for ( ; xig ; xig = (struct xinpgen *)((char *)xig + xig->xig_len)) {
	if (xig->xig_len <= sizeof(struct xinpgen))
	    break;

	xpcb = (struct xinpcb *)xig;
	xpcb->xi_inp.inp_lport = htons(xpcb->xi_inp.inp_lport);

	if (Add_Entry( t, (void*)&((struct xinpcb *)xig)->xi_inp ) < 0 )
	    break;
    }

    return 0;
}
#endif

#ifndef LOAD_UDP_LIST
int load_udp_list( mib_table_t t )
{
#ifdef PCB_TABLE
    struct inpcbtable table;
#endif
    struct inpcb entry;
    struct inpcb *kernel_head, *kernel_next;

		/*
		 * Locate the address of the first PCB entry
		 */
#ifdef PCB_TABLE
    auto_nlist(UDB_SYMBOL, (char *)&table, sizeof(table));
    memcpy(kernel_head, table.inpt_queue.cqh_first, sizeof (struct inpcb));
#else
    kernel_head = (struct inpcb*)auto_nlist_value (UDB_SYMBOL);
#endif

		/*
		 * Walk through the kernel values,
		 *  creating new entries and adding them to the list
		 */
    kernel_next = kernel_head;

    while ( kernel_next ) {
	klookup((unsigned long)kernel_next, (char *)&entry, sizeof(struct inpcb));

	if (Add_Entry( t, (void*)&entry ) < 0 )
	    break;
    }
    return 0;
}
#endif


