/*
 *  IP MIB group implementation - ip.c
 *
 */

#include <config.h>
#include "mibincl.h"

#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/socket.h>

#if HAVE_STRING_H
#include <string.h>
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

#ifdef solaris2
#include "kernel_sunos5.h"
#else
#include "kernel.h"
#endif

#include "system.h"
#include "auto_nlist.h"

#ifdef MIB_IPCOUNTER_SYMBOL
#include <sys/mib.h>
#include <netinet/mib_kern.h>
#endif /* MIB_IPCOUNTER_SYMBOL */

#include "util_funcs.h"
#include "ipAddr.h"
#include "interfaces.h"

#ifndef IPADDR_TABLE_CACHE_TIMEOUT
#define IPADDR_TABLE_CACHE_TIMEOUT MIB_STATS_CACHE_TIMEOUT
#endif

       mib_table_t ipAddr_table;
extern mib_table_t interface_table;


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


#include "if_fields.h"

IFADDR_TYPE* search_ipAddr(oid*, int, int, int *);
int load_ipAddr_table( mib_table_t );
int ipAddr_compare(const void*, const void *);



	/*********************
	 *
	 *  Initialisation
	 *
	 *********************/

struct variable2 ipAddr_variables[] = {
    {IPADADDR,      ASN_IPADDRESS, RONLY, var_ipAddrEntry, 1, {1}},
    {IPADIFINDEX,   ASN_INTEGER,   RONLY, var_ipAddrEntry, 1, {2}},
    {IPADNETMASK,   ASN_IPADDRESS, RONLY, var_ipAddrEntry, 1, {3}},
    {IPADBCASTADDR, ASN_INTEGER,   RONLY, var_ipAddrEntry, 1, {4}},
    {IPADREASMMAX,  ASN_INTEGER,   RONLY, var_ipAddrEntry, 1, {5}},
};
oid ipAddr_variables_oid[] = { SNMP_OID_MIB2,4,20,1 };

void
init_ipAddr( void )
{
    REGISTER_MIB("mibII/ipAddr", ipAddr_variables, variable2, ipAddr_variables_oid);
    ipAddr_table = Initialise_Table( sizeof( struct if_entry* ),
				     IPADDR_TABLE_CACHE_TIMEOUT,
				     load_ipAddr_table, ipAddr_compare );
}

	/*********************
	 *
	 *   Main variable handling routine
	 *
	 *********************/

u_char *
var_ipAddrEntry(struct variable *vp,
	     oid *name,
	     size_t *length,
	     int exact,
	     size_t *var_len,
	     WriteMethod **write_method)
{
    int i, idx;
    oid newname[MAX_OID_LEN], *op;
    u_char *cp;
    IFADDR_TYPE* ipAddrEntry;

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
		 *  Search for the relevant IP address entry,
		 *   either the index just identified,
		 *   or the next one, depending on whether
		 *   this is an exact match or not.
		 */
    ipAddrEntry = search_ipAddr( op, i, exact, &idx );
    if ( !ipAddrEntry )
	return NULL;

		/*
		 * We've found something we can use.
		 *  Update the 'newname' with the relevant index
		 */
    memcpy((char *)newname, (char *)vp->name, (int)vp->namelen * sizeof(oid));
    cp = (u_char *)&(SOCKADDR(ipAddrEntry->IPADDR_ADDRESS_FIELD));
    op = newname + vp->namelen;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
   

    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 4) * sizeof(oid));
    *length = vp->namelen + 4;
    *write_method = 0;
    *var_len = sizeof(long_return);

    switch (vp->magic) {

	case IPADADDR:
	    long_return = SOCKADDR(ipAddrEntry->IPADDR_ADDRESS_FIELD);
	    return(u_char *) &long_return;

	case IPADIFINDEX:
	    long_return = idx;
	    return(u_char *) &long_return;

	case IPADNETMASK:
	    long_return = SOCKADDR(ipAddrEntry->IPADDR_NETMASK_FIELD);
	    return(u_char *) &long_return;

	case IPADBCASTADDR:
	    long_return = SOCKADDR(ipAddrEntry->IPADDR_BCAST_FIELD) & 1;
	    return(u_char *) &long_return;

	case IPADREASMMAX:
	    return NULL;

	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ipAddrEntry\n", vp->magic));
    }
    return  NULL;
}


	/*********************
	 *
	 *  System-independent implementation functions
	 *    (N.B: the system-specifics are
	 *	handled by the interface group)
	 *
	 *********************/

		/*
		 *  The list of IP Address entries is simply
		 *    a list of pointers to the various
		 *    interface entries, sorted by Address.
		 */
int
load_ipAddr_table( mib_table_t t )
{
    int max_idx, i;
    struct if_entry *ifTable, *pentry;

    ifTable = Retrieve_Table_Data( interface_table, &max_idx );
    if ( ifTable == NULL )
	return -1;

    for ( i = 1 ; i <= max_idx ; i++ ) {
	pentry = &(ifTable[i]);
	if (Add_Entry( t, (void*)&pentry) < 0 )
	    break;
    }

    return 0;
}


		/*
		 *  Search the list of IP Address entries and return
		 *    the appropriate one for this query
		 */

IFADDR_TYPE* search_ipAddr(oid* idx, int idx_len, int exact, int *ret_idx)
{
    static struct if_entry entry, *pentry;
    IFADDR_TYPE ipaddr;
    int i, max_i;
    char *cp;
    oid  *op;

    if ( exact && idx_len != 4 )
	return NULL;

    entry.ifaddr = &ipaddr;
    SOCKADDR(entry.ifaddr->IPADDR_ADDRESS_FIELD) = 0;

    max_i = SNMP_MIN( idx_len, 4 );
    cp = (u_char *)&(SOCKADDR(entry.ifaddr->IPADDR_ADDRESS_FIELD));
    op = idx;
    for ( i = 0 ; i< max_i ; i++ )
	*cp++ = *op++;

    pentry = &entry;
    if ( Search_Table( ipAddr_table, (void*)&pentry, exact ) == 0 ) {
	*ret_idx = pentry->index;
	return (pentry->ifaddr);
    }
    else
	return NULL;
}

		/*
		 *  Compare two Interface entries by IP Address
		 */
int
ipAddr_compare(const void* first, const void* second)
{
    const struct if_entry *if1 = *(const struct if_entry **) first;
    const struct if_entry *if2 = *(const struct if_entry **) second;

    if ( if1 == NULL || if1->ifaddr == NULL)
	return 1;
    if ( if2 == NULL || if2->ifaddr == NULL)
	return -1;
    return (SOCKADDR(if1->ifaddr->IPADDR_ADDRESS_FIELD) -
	    SOCKADDR(if2->ifaddr->IPADDR_ADDRESS_FIELD));
}

