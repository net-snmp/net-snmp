/*
 *  IP Net->Media translation MIB group implementation - ipMedia.c
 *
 */

#include <config.h>
#include "mibincl.h"

#if HAVE_STRING_H
#include <string.h>
#endif
#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#if HAVE_NET_IF_VAR_H
#include <net/if_var.h>
#endif
#ifdef _I_DEFINED_KERNEL
#undef _KERNEL
#endif

#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif
#if HAVE_SYS_STREAM_H
#include <sys/stream.h>
#endif
#if HAVE_NET_ROUTE_H
#include <net/route.h>
#endif

#ifdef solaris2
#include "kernel_sunos5.h"
#endif

#ifdef hpux
#include <sys/mib.h>
#include "kernel_hpux.h"
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "ipMedia.h"
#include "interfaces.h"
#include "if_fields.h"
#include "auto_nlist.h"
#include "system.h"
#include "util_funcs.h"

#if defined(HAVE_SYS_SYSCTL_H) && !defined(CAN_USE_SYSCTL)
# if defined(RTF_LLINFO) && !defined(irix6)
#  define CAN_USE_SYSCTL 1
# endif
#endif

#ifndef MEDIA_CACHE_TIMEOUT
#define MEDIA_CACHE_TIMEOUT MIB_STATS_CACHE_TIMEOUT
#endif

mib_table_t media_table;

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef solaris2
#define MEDIA_TYPE	mib2_ipNetToMediaEntry_t
#define AT_INDEX_FIELD		ipNetToMediaIfIndex
#define AT_PHYSADDR_FIELD	ipNetToMediaPhysAddress
#define AT_ADDRESS_FIELD	ipNetToMediaNetAddress
#define AT_TYPE_FIELD		ipNetToMediaType
#define PHYSADDR_LEN(x)		sizeof(x)
#endif

#ifdef hpux
#define MEDIA_TYPE	mib_ipNetToMediaEnt
#define AT_INDEX_FIELD		IfIndex
#define AT_PHYSADDR_FIELD	PhysAddr
#define AT_ADDRESS_FIELD	NetAddr
#define AT_TYPE_FIELD		Type
#undef STRUCT_ARPHD_HAS_AT_NEXT
#undef  SOCKADDR
#define SOCKADDR(x)	x
#define PHYSADDR_LEN(x)	6
#endif

#ifdef freebsd4
struct dummy_arptab {
    int			index;
    char		at_enaddr[6];
    struct sockaddr_in	at_iaddr;	/* XXX */
    int			at_flags;
};
#define MEDIA_TYPE	struct dummy_arptab
#define AT_INDEX_FIELD		index
#define AT_PHYSADDR_FIELD	at_enaddr
#define AT_ADDRESS_FIELD	at_iaddr
#define AT_FLAGS_FIELD		at_flags
#define PHYSADDR_LEN(x)		sizeof(x)
#endif

#ifndef MEDIA_TYPE
#define MEDIA_TYPE	struct arptab
#define AT_INDEX_FIELD		at_state	/* unused field */
#define AT_PHYSADDR_FIELD	at_enaddr
#define AT_ADDRESS_FIELD	at_iaddr
#define AT_FLAGS_FIELD		at_flags
#define PHYSADDR_LEN(x)		sizeof(x)
#endif

int Arp_Scan_Reload ( mib_table_t );
int Arp_Compare(const void *, const void *);
MEDIA_TYPE* search_arp(oid* idx, int idx_len, int exact, int is_atQuery);



	/*********************
	 *
	 *  Initialisation
	 *
	 *********************/

/* define the structures we're going to ask the agent to register our
   information at */
struct variable2 at_variables[] = {
    {ATIFINDEX,     ASN_INTEGER,   RONLY, var_atEntry, 1, {1}},
    {ATPHYSADDRESS, ASN_OCTET_STR, RONLY, var_atEntry, 1, {2}},
    {ATNETADDRESS,  ASN_IPADDRESS, RONLY, var_atEntry, 1, {3}}
};
struct variable2 ipMedia_variables[] = {
    {ATIFINDEX,     ASN_INTEGER,   RONLY, var_atEntry, 1, {1}},
    {ATPHYSADDRESS, ASN_OCTET_STR, RONLY, var_atEntry, 1, {2}},
    {ATNETADDRESS,  ASN_IPADDRESS, RONLY, var_atEntry, 1, {3}},
    {IPMEDIATYPE,   ASN_INTEGER,   RONLY, var_atEntry, 1, {4}}
};

/* Define the OID pointers to the top of the mib trees that we're
   registering underneath */
oid at_variables_oid[]      = { SNMP_OID_MIB2,3,1,1 };
oid ipMedia_variables_oid[] = { SNMP_OID_MIB2,4,22,1 };

void init_ipMedia(void)
{
    /* register ourselves with the agent to handle our mib tree */
    REGISTER_MIB("mibII/ipMedia", at_variables,      variable2, at_variables_oid);
    REGISTER_MIB("mibII/ipMedia", ipMedia_variables, variable2, ipMedia_variables_oid);

    media_table = Initialise_Table( sizeof( MEDIA_TYPE ),
			MEDIA_CACHE_TIMEOUT,
			Arp_Scan_Reload, Arp_Compare);
}


	/*********************
	 *
	 *  Main variable handling routines
	 *
	 *********************/

/*
  var_atEntry(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/

u_char *
var_atEntry(struct variable *vp,
	    oid *name,
	    size_t *length,
	    int exact,
	    size_t *var_len,
	    WriteMethod **write_method)
{
    /*
     * Address Translation table object identifier is of form:
     * 1.3.6.1.2.1.3.1.1.1.interface.1.A.B.C.D,  where A.B.C.D is IP address.
     * Interface is at offset 10,
     * IPADDR starts at offset 12.
     *
     * IP Net to Media table object identifier is of form:
     * 1.3.6.1.2.1.4.22.1.1.1.interface.A.B.C.D,  where A.B.C.D is IP address.
     * Interface is at offset 10,
     * IPADDR starts at offset 11.
     */

    int i, idx;
    oid newname[MAX_OID_LEN], *op;
    u_char *cp;
    MEDIA_TYPE *atEntry;
    int is_atQuery;

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
    is_atQuery = ( vp->name[6] == 3 );
    

		/*
		 *  Search for the relevant ARP entry,
		 *   either the index just identified,
		 *   or the next one, depending on whether
		 *   this is an exact match or not.
		 */
    atEntry = search_arp( op, i, exact, is_atQuery );
    if ( !atEntry )
	return NULL;

		/*
		 * We've found something we can use.
		 *  Update the 'newname' with the relevant index
		 */
    memcpy((char *)newname, (char *)vp->name, (int)vp->namelen * sizeof(oid));
    cp = (u_char *)&(SOCKADDR(atEntry->AT_ADDRESS_FIELD));
    op = newname + vp->namelen;
    *op++ = atEntry->AT_INDEX_FIELD;
    if ( is_atQuery )
	*op++ = 1;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
    *op++ = *cp++;
   
    if ( is_atQuery )
	*length = vp->namelen + 6;
    else
	*length = vp->namelen + 5;
    memcpy( (char *)name,(char *)newname, (*length) * sizeof(oid));
    *write_method = 0;
    *var_len = sizeof(long_return);


    switch(vp->magic){
	case ATIFINDEX:
	    long_return = atEntry->AT_INDEX_FIELD;
	    return (u_char *)&long_return;

	case ATPHYSADDRESS:
	    *var_len = sizeof(atEntry->AT_PHYSADDR_FIELD);
	    return (u_char *)atEntry->AT_PHYSADDR_FIELD;

	case ATNETADDRESS:
	    long_return = SOCKADDR(atEntry->AT_ADDRESS_FIELD);
	    return (u_char *)&long_return;

	case IPMEDIATYPE:
#ifdef AT_TYPE_FIELD
	    long_return = atEntry->AT_TYPE_FIELD;
	    return (u_char *)&long_return;
#else
#ifdef AT_FLAGS_FIELD
	    long_return = (atEntry->AT_FLAGS_FIELD & ATF_PERM
		 ? 4	/* static */
		 : 3);	/* dynamic */
	    return (u_char *)&long_return;
#else
	    return NULL;
#endif
#endif

	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_atEntry\n", vp->magic));
   }
   return NULL;
}


	/*********************
	 *
	 *  System-independent implementation functions
	 *
	 *********************/


	/*
	 *  Search the list of ARP entries and return
	 *    the appropriate one for this query
	 */

MEDIA_TYPE* search_arp(oid* idx, int idx_len, int exact, int is_atQuery)
{
    static MEDIA_TYPE entry;
    char *cp;
    oid  *op;
    int desired_len = ( is_atQuery ? 6 : 5);

    if ( exact && idx_len != desired_len )
	return NULL;

    if ( idx_len < desired_len ) {
	SOCKADDR(entry.AT_ADDRESS_FIELD) = 0;
	entry.AT_INDEX_FIELD   = 0;
    }
    else {
        cp = (u_char *)&SOCKADDR(entry.AT_ADDRESS_FIELD);
	op = idx;
	entry.AT_INDEX_FIELD   = *op++;
	if ( is_atQuery )
	    op++;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
	*cp++ = *op++;
    }

    if ( Search_Table( media_table, (void*)&entry, exact ) == 0 )
	return &entry;
    else
	return NULL;
}

	/*
	 *  Compare two ARP entries
	 */
int
Arp_Compare(const void* first, const void* second)
{
    const MEDIA_TYPE *at1 = (const MEDIA_TYPE *) first;
    const MEDIA_TYPE *at2 = (const MEDIA_TYPE *) second;

    if (at1->AT_INDEX_FIELD == at2->AT_INDEX_FIELD)
	return (ntohl(SOCKADDR(at1->AT_ADDRESS_FIELD)) -
	        ntohl(SOCKADDR(at2->AT_ADDRESS_FIELD)));

    return (at1->AT_INDEX_FIELD - at2->AT_INDEX_FIELD);
}


	/*********************
	 *
	 *  System-specific functions to read in the ARP table
	 *
	 *********************/

#ifdef  hpux
#define ARP_SCAN_RELOAD
int Arp_Scan_Reload( mib_table_t t )
{
    int numEntries, size, i;
    mib_ipNetToMediaEnt *entries;

   if (hpux_read_stat((char *)&numEntries, sizeof(int), ID_ipNetToMediaTableNum) == -1)
	return -1;

    size = numEntries*sizeof(mib_ipNetToMediaEnt);
    if ( (entries=(mib_ipNetToMediaEnt *)malloc ( size )) == NULL )
	return -1;

    if (hpux_read_stat((char *)entries, size, ID_ipNetToMediaTable) == -1) {
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

#ifdef linux
#define ARP_SCAN_RELOAD
int Arp_Scan_Reload( mib_table_t t )
{
    FILE *in;
    char line [256], name[32];
    struct arptab entry;
    int za, zb, zc, zd, ze, zf, zg, zh, zi, zj;

    if (! (in = fopen ("/proc/net/arp", "r"))) {
	snmp_log(LOG_ERR, "snmpd: cannot open /proc/net/arp ...\n");
	return -1;
    }

    while (fgets (line, sizeof(line), in)) {
	if ( 12 != sscanf (line, "%d.%d.%d.%d 0x%*x 0x%x %x:%x:%x:%x:%x:%x %*s %s",
			&za, &zb, &zc, &zd, &entry.at_flags,
			&ze, &zf, &zg, &zh, &zi, &zj, name))
			continue;
	entry.at_enaddr[0] = ze;
	entry.at_enaddr[1] = zf;
	entry.at_enaddr[2] = zg;
	entry.at_enaddr[3] = zh;
	entry.at_enaddr[4] = zi;
	entry.at_enaddr[5] = zj;
	SOCKADDR(entry.at_iaddr) = (zd << 24) | (zc << 16) | (zb << 8) | za;

	entry.AT_INDEX_FIELD = Interface_Index_By_Name(name);
	if (Add_Entry( t, (void *)&entry) < 0 )
	    break;
    }
    fclose( in );
    return 0;
}
#endif

#ifdef CAN_USE_SYSCTL
#define ARP_SCAN_RELOAD
#define ROUNDUP(a) \
	((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
int Arp_Scan_Reload( mib_table_t t )
{
    size_t size = 0;
    int name[] = { CTL_NET, PF_ROUTE, 0, AF_INET, NET_RT_FLAGS, RTF_LLINFO };
    char *arpbuf, *lim, *next;
    struct rt_msghdr *rtm;
    struct sockaddr_inarp *sin;
    struct sockaddr_dl *sdl;
    MEDIA_TYPE at_entry;

    if (sysctl (name, sizeof (name) / sizeof (int), 0, &size, 0, 0) == -1) {
	snmp_log(LOG_ERR,"sysctl size fail\n");
	return -1;
    }
    if (size == 0)
	return -1;
    if ((arpbuf = malloc (size)) == NULL) {
	snmp_log(LOG_ERR,"out of memory allocating arp table\n");
	return -1;
    }
    if (sysctl (name, sizeof (name) / sizeof (int), arpbuf, &size, 0, 0) == -1) {
	snmp_log(LOG_ERR,"sysctl get fail\n");
	free(arpbuf);
	return -1;
    }

    lim = arpbuf + size;
    for ( next = arpbuf; next<lim; next += rtm->rtm_msglen) {
	rtm = (struct rt_msghdr *)next;
	sin = (struct sockaddr_inarp *)(rtm + 1);
	(char *)sdl = (char *)sin + ROUNDUP(sin->sin_len);

	if ( sdl->sdl_alen ) {
	    memset(&at_entry, 0, sizeof(at_entry));
	    at_entry.index = sdl->sdl_index;
	    memcpy(at_entry.at_enaddr, sdl->sdl_data, sizeof(at_entry.at_enaddr));
	    at_entry.at_iaddr.sin_addr = sin->sin_addr;
	    at_entry.at_flags = 0;			/* XXX */

	    if (Add_Entry( t, (void *)&at_entry) < 0 )
		break;
	}
    }
    free( arpbuf );
    return 0;
}
#endif

#ifdef solaris2
#define ARP_SCAN_RELOAD
int Arp_Scan_Reload( mib_table_t t )
{
		/* Do something clever with 'getMibstat() */
    return 0;
}
#endif

#ifdef STRUCT_ARPHD_HAS_AT_NEXT
#define ARP_SCAN_RELOAD
int Arp_Scan_Reload( mib_table_t t )
{
    int arptab_size, arptab_current;
    struct arphd *at;
    struct arptab *at_ptr, at_entry;
    struct arpcom  at_com;
    char name[32];

    auto_nlist(ARPTAB_SIZE_SYMBOL, (char *)&arptab_size, sizeof arptab_size);
    at = (struct arphd  *) malloc(arptab_size * sizeof(struct arphd));
    auto_nlist(ARPTAB_SYMBOL, (char *)at, arptab_size * sizeof(struct arphd));
    at_ptr = at[0].at_next;
    arptab_current = 0;

    while (arptab_current < arptab_size) {
		/*
		 * The arp table is an array of linked lists
		 * of arptab entries.  Unused slots have
		 * pointers back to the array entry itself
		 */
	if ( at_ptr == (auto_nlist_value(ARPTAB_SYMBOL) +
		arptab_current*sizeof(struct arphd))) {
			/* Unused */
	    arptab_current++;
	    at_ptr = at[arptab_current].at_next;
	    continue;
	}

	klookup( at_ptr, (char *)&at_entry, sizeof(struct arptab));
	if (!( at_entry.at_flags & ATF_COM ))
	    continue;

	klookup( at_entry.at_ac, (char *)&at_com, sizeof(struct arpcom));
	sprintf(name, "%s%d", at_com.ac_if.if_name, at_com.ac_if.if_unit);
	at_entry.AT_INDEX_FIELD = Interface_Index_By_Name(name);

	if (Add_Entry( t, (void *)&at_entry) < 0 )
	    break;

	at_ptr = at_entry.at_next;
	
    }
    free( at );
    return 0;
}
#endif

#ifndef ARP_SCAN_RELOAD			/* i.e. 'other' */
int Arp_Scan_Reload( mib_table_t t )
{
    int arptab_size, arptab_current;
    struct arptab *at, at_ptr;
    char name[32];

    auto_nlist(ARPTAB_SIZE_SYMBOL, (char *)&arptab_size, sizeof arptab_size);
    at = (struct arptab  *) malloc(arptab_size * sizeof(struct arptab));
    auto_nlist(ARPTAB_SYMBOL, (char *)at, arptab_size * sizeof(struct arptab));
    arptab_current = 0;

    while (arptab_current < arptab_size) {

	at_ptr = at[ arptab_current++ ];
	if (!( at_ptr->at_flags & ATF_COM ))
	    continue;
/*	at_ptr->AT_INDEX_FIELD = Interface_Index_By_Name(name);		*/

	if (Add_Entry( t, (void *)at_ptr) < 0 )
	    break;
    }
    free( at );
    return 0;
}
#endif
