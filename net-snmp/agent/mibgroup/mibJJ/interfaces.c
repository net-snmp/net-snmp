/*
 *  Interfaces MIB group implementation - interfaces.c
 *
 */

#include <config.h>
#include "mibincl.h"


#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <sys/types.h>

#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL) && defined(IFNET_NEEDS_KERNEL_LATE)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#include <sys/socket.h>

#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
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
#if HAVE_SYS_HASHING_H
#include <sys/hashing.h>
#endif
#if HAVE_NETINET_IN_VAR_H
#include <netinet/in_var.h>
#endif
#include <netinet/ip.h>
#ifdef INET6
#if HAVE_NETINET_IP6_H
#include <netinet/ip6.h>
#endif
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
#if HAVE_NETINET_IN_PCB_H
#include <netinet/in_pcb.h>
#endif
#if HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif
#if HAVE_NET_IF_TYPES_H
#include <net/if_types.h>
#endif
#if HAVE_NET_IF_DL_H
#include <net/if_dl.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_IOCTLS_H
#include <ioctls.h>
#endif
#include <ctype.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif


#ifdef solaris2
#include "kernel_sunos5.h"
#else
#include "kernel.h"
#endif

#ifdef hpux
#include <sys/mib.h>
#include "kernel_hpux.h"
#endif /* hpux */

#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>

#ifdef freebsd3
#    define USE_SYSCTL_IFLIST
#else
# if defined(CTL_NET) && !defined(freebsd2)
#  ifdef PF_ROUTE
#   ifdef NET_RT_IFLIST
#    ifndef netbsd1
#     define USE_SYSCTL_IFLIST
#    endif
#   endif
#  endif
# endif
#endif /* defined(freebsd3) */
#endif /* HAVE_SYS_SYSCTL_H */

#include "system.h"
#include "snmp_logging.h"

#if HAVE_OSRELDATE_H
#include <osreldate.h>
#endif
#ifdef CAN_USE_SYSCTL
#include <sys/sysctl.h>
#endif
#include "interfaces.h"
#include "struct.h"
#include "util_funcs.h"
#include "auto_nlist.h"
#include "sysORTable.h"

#ifndef INTERFACE_CACHE_TIMEOUT
#define INTERFACE_CACHE_TIMEOUT	MIB_STATS_CACHE_TIMEOUT
#endif

mib_table_t interface_table;

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


#include "if_fields.h"

int Interface_Scan_Get_Count( void );
int Load_Interface_List( mib_table_t );

void Init_Interface_Speeds( void );
int  Interface_Speed_From_Type( int type );
int  Interface_Speed_From_Name( const char *name );
int  Interface_Type_From_Name( const char *name );


	/*********************
	 *
	 *  Initialisation
	 *
	 *********************/


struct variable4 interfaces_variables[] = {
    {IFNUMBER,        ASN_INTEGER, RONLY, var_interfaces, 1, {1}},
    {IFINDEX,         ASN_INTEGER, RONLY, var_ifEntry, 3, {2, 1, 1}},
    {IFDESCR,       ASN_OCTET_STR, RONLY, var_ifEntry, 3, {2, 1, 2}},
    {IFTYPE,          ASN_INTEGER, RONLY, var_ifEntry, 3, {2, 1, 3}},
    {IFMTU,           ASN_INTEGER, RONLY, var_ifEntry, 3, {2, 1, 4}},
    {IFSPEED,           ASN_GAUGE, RONLY, var_ifEntry, 3, {2, 1, 5}},
    {IFPHYSADDRESS, ASN_OCTET_STR, RONLY, var_ifEntry, 3, {2, 1, 6}},
    {IFADMINSTATUS,   ASN_INTEGER, RWRITE, var_ifEntry, 3, {2, 1, 7}},
    {IFOPERSTATUS,    ASN_INTEGER, RONLY, var_ifEntry, 3, {2, 1, 8}},
    {IFLASTCHANGE,  ASN_TIMETICKS, RONLY, var_ifEntry, 3, {2, 1, 9}},
    {IFINOCTETS,      ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 10}},
    {IFINUCASTPKTS,   ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 11}},
    {IFINNUCASTPKTS,  ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 12}},
    {IFINDISCARDS,    ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 13}},
    {IFINERRORS,      ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 14}},
    {IFINUNKNOWNPROTOS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 15}},
    {IFOUTOCTETS,     ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 16}},
    {IFOUTUCASTPKTS,  ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 17}},
    {IFOUTNUCASTPKTS, ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 18}},
    {IFOUTDISCARDS,   ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 19}},
    {IFOUTERRORS,     ASN_COUNTER, RONLY, var_ifEntry, 3, {2, 1, 20}},
    {IFOUTQLEN,         ASN_GAUGE, RONLY, var_ifEntry, 3, {2, 1, 21}},
    {IFSPECIFIC,    ASN_OBJECT_ID, RONLY, var_ifEntry, 3, {2, 1, 22}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath, and the OID of the MIB module */
oid interfaces_variables_oid[] = { SNMP_OID_MIB2,2 };
oid interfaces_module_oid[]    = { SNMP_OID_MIB2,31 };

void init_interfaces(void)
{
    /* register ourselves with the agent to handle our mib tree */
    REGISTER_MIB("mibII/interfaces", interfaces_variables, variable4, \
               interfaces_variables_oid);
    REGISTER_SYSOR_ENTRY(interfaces_module_oid,
	"The MIB module to describe generic objects for network interface sub-layers");
  
    interface_table = Initialise_Table( sizeof(struct if_entry),
				  INTERFACE_CACHE_TIMEOUT,
				  Load_Interface_List, NULL );
    Init_Interface_Speeds();
}


	/*********************
	 *
	 *  Main variable handling routines
	 *
	 *********************/


u_char *
var_interfaces(struct variable *vp,
	       oid *name,
	       size_t *length,
	       int exact,
	       size_t *var_len,
	       WriteMethod **write_method)
{
    if (header_generic(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    switch (vp->magic) {
	case IFNUMBER:
	    long_return = Interface_Scan_Get_Count ();
	    return (u_char *)&long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_interfaces\n", vp->magic));
    }
    return NULL;
}


u_char *
var_ifEntry(struct variable *vp,
	       oid *name,
	       size_t *length,
	       int exact,
	       size_t *var_len,
	       WriteMethod **write_method)
{
    int max_idx, idx;
    struct if_entry *ifTable;
    IFENTRY_TYPE *ifstat;

		/*
		 *  We can treat this as a 'simple' table,
		 *   once we know the maximimum index.
		 *
		 *  Note that this is *not* necessarily
		 *   the same as 'Interface_Scan_Get_Count()'
		 *   as the interface table can potentially
		 *   be "sparse".
		 */
    ifTable = Retrieve_Table_Data( interface_table, &max_idx );
    if ( ifTable == NULL )
	return NULL;

    if (header_simple_table(vp, name, length, exact, var_len,
		write_method, max_idx) == MATCH_FAILED )
	return NULL;


		/*
		 * If the suggested index is not currently being used,
		 *   amend it (if appropriate)
		 */
    idx = name[ vp->namelen ];
    if ( ifTable[idx].ifstat == NULL ) {
	if ( exact )
	    return NULL;

	while ( idx++ < max_idx ) {
	    if ( ifTable[idx].ifstat != NULL ) 
		break;		/* found one */
	}
	if ( idx == max_idx )
	    return NULL;
	name[ vp->namelen ] = idx;
    }
    ifstat = ifTable[ idx ].ifstat;


    switch (vp->magic){
	case IFINDEX:
		long_return = idx;
		return (u_char *) &long_return;
	case IFDESCR:
		*var_len = strlen( ifTable[ idx ].name );
		return (u_char *) ifTable[ idx ].name;

	case IFTYPE:
#ifdef IFENTRY_FIELD_TYPE
	    long_return = (u_long)ifstat->IFENTRY_FIELD_TYPE;
#else
	    long_return = Interface_Type_From_Name( ifTable[ idx ].name );
#endif
	    return (u_char *) &long_return;

	case IFMTU:
	    long_return = (u_long)ifstat->IFENTRY_FIELD_MTU;
	    return (u_char *) &long_return;

	case IFSPEED:
#ifdef IFENTRY_FIELD_SPEED
	    long_return = (u_long)ifstat->IFENTRY_FIELD_SPEED;
#else
#ifdef IFENTRY_FIELD_TYPE
	    long_return = Interface_Speed_From_Type(ifstat->IFENTRY_FIELD_TYPE);
#else
	    long_return = Interface_Speed_From_Name( ifTable[ idx ].name );
#endif
#endif
	    return (u_char *) &long_return;

	case IFPHYSADDRESS:
#ifdef IFENTRY_FIELD_PHYSADDR
	    *var_len = IFENTRY_STRING_SIZE(ifstat->IFENTRY_FIELD_PHYSADDR);
	    (void)memcpy(return_buf,
		IFENTRY_STRING_VALUE(ifstat->IFENTRY_FIELD_PHYSADDR), *var_len);
	    return (u_char *)return_buf;
#else
#ifdef IFENTRY_CALCULATE_PHYSADDR
	    if (Interface_Get_Ether_By_Index (idx, return_buf, var_len)) {
		return (u_char *)return_buf;
	    }
#endif
	    return NULL;
#endif

	case IFADMINSTATUS:
#ifdef IFENTRY_FIELD_ADMIN
	    long_return = (u_long)ifstat->IFENTRY_FIELD_ADMIN;
	    return (u_char *) &long_return;
#else
#ifdef IFENTRY_CALCULATE_STATUS
	    long_return = ifstat->IFENTRY_FIELD_FLAGS & IFF_RUNNING ? 1 : 2;
	    return (u_char *) &long_return;
#endif
#endif
	    return NULL;

	case IFOPERSTATUS:
#ifdef IFENTRY_FIELD_OPER
	    long_return = (u_long)ifstat->IFENTRY_FIELD_OPER;
	    return (u_char *) &long_return;
#else
#ifdef IFENTRY_CALCULATE_STATUS
	    long_return = ifstat->IFENTRY_FIELD_FLAGS & IFF_UP ? 1 : 2;
	    return (u_char *) &long_return;
#endif
#endif
	    return NULL;

	case IFLASTCHANGE:
#ifdef IFENTRY_FIELD_LASTCH
#ifndef IFENTRY_CALCULATE_LASTCH
	    long_return = (u_long)ifstat->IFENTRY_FIELD_LASTCH;
	    return (u_char *) &long_return;
#else
	    long_return = marker_ttime( &ifstat->IFENTRY_FIELD_LASTCH )
	    return (u_char *) &long_return;
#endif
#else
	    return NULL;
#endif

	case IFINOCTETS:
#ifdef IFENTRY_FIELD_INOCTETS
	      if ( ifstat->IFENTRY_FIELD_INOCTETS == 0 )
		return NULL;
	      long_return = (u_long)ifstat->IFENTRY_FIELD_INOCTETS;
	      return (u_char *) &long_return;
#else
	      return NULL;
#endif

	case IFINUCASTPKTS:
	      long_return  = (u_long)ifstat->IFENTRY_FIELD_INPKTS;
#ifdef IFENTRY_FIX_UNICAST
	      long_return -= (u_long)ifstat->IFENTRY_FIELD_INMCASTS;
#endif
	      return (u_char *) &long_return;

	case IFINNUCASTPKTS:
#ifdef IFENTRY_FIELD_INMCASTS
	      long_return = (u_long)ifstat->IFENTRY_FIELD_INMCASTS;
	      return (u_char *) &long_return;
#else
	      return NULL;
#endif

	case IFINDISCARDS:
#ifdef IFENTRY_FIELD_INDISCARDS
	      long_return = (u_long)ifstat->IFENTRY_FIELD_INDISCARDS;
	      return (u_char *) &long_return;
#else
	      return NULL;
#endif

	case IFINERRORS:
	      long_return = (u_long)ifstat->IFENTRY_FIELD_INERRORS;
	      return (u_char *) &long_return;

	case IFINUNKNOWNPROTOS:
#ifdef IFENTRY_FIELD_UNKNOWN
	      long_return = (u_long)ifstat->IFENTRY_FIELD_UNKNOWN;
	      return (u_char *) &long_return;
#else
	      return NULL;
#endif

	case IFOUTOCTETS:
#ifdef IFENTRY_FIELD_OUTOCTETS
	      if ( ifstat->IFENTRY_FIELD_OUTOCTETS == 0 )
		return NULL;
	      long_return = (u_long)ifstat->IFENTRY_FIELD_OUTOCTETS;
	      return (u_char *) &long_return;
#else
	      return NULL;
#endif

	case IFOUTUCASTPKTS:
	      long_return  = (u_long)ifstat->IFENTRY_FIELD_OUTPKTS;
#ifdef IFENTRY_FIX_UNICAST
	      long_return -= (u_long)ifstat->IFENTRY_FIELD_OUTMCASTS;
#endif
	      return (u_char *) &long_return;

	case IFOUTNUCASTPKTS:
#ifdef IFENTRY_FIELD_OUTMCASTS
	      long_return = (u_long)ifstat->IFENTRY_FIELD_OUTMCASTS;
	      return (u_char *) &long_return;
#else
	      return NULL;
#endif

	case IFOUTDISCARDS:
#ifdef IFENTRY_FIELD_OUTDISCARDS
	      long_return = (u_long)ifstat->IFENTRY_FIELD_OUTDISCARDS;
	      return (u_char *) &long_return;
#else
	      return NULL;
#endif

	case IFOUTERRORS:
	      long_return = (u_long)ifstat->IFENTRY_FIELD_OUTERRORS;
	      return (u_char *) &long_return;

	case IFOUTQLEN:
#ifdef IFENTRY_FIELD_QLEN
	      long_return = (u_long)ifstat->IFENTRY_FIELD_QLEN;
	      return (u_char *) &long_return;
#else
	      return NULL;
#endif

	case IFSPECIFIC:
	      return NULL;

	default:
		DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_ifEntry\n",
				vp->magic));
	}
    return NULL;
}




	/*********************
	 *
	 *  System-independent internal implementation functions
	 *
	 *********************/

typedef struct _match_if {
	int mi_type;
	const char *mi_name;
} match_if;

static match_if lmatch_if[] = {
	{ 24, "lo" },		/* loopback */
	{  6, "eth" },		/* ethernet */
	{  6, "le" },		/* Lance ethernet */
	{  6, "qe" },		/* Quad ethernet */
	{  6, "hme" },
	{  9, "tr" },		/* Token Ring */
	{ 23, "ppp" },		/* Point-to-Point */
	{ 28, "sl" },
	{ 37, "lane" },		/* LAN Emulation (ATM) */
	{ 37, "fa" },		/* Fore ATM */
	{ 37, "qa" },		/* Fore? ATM */
	{ 62, "qfe" },		/* Quad Fast ethernet */

	{  0, 0 }		/* end of list */
};

#define MAX_IF_TYPES 161		/* From IANAifType-MIB */
static int if_speeds[ MAX_IF_TYPES ];

void Init_Interface_Speeds( void )
{
    int i;

    for ( i = 0 ; i < MAX_IF_TYPES ; i++ )
	if_speeds[i] = 0;

#define MBIT 1000000

    if_speeds[  6 ] =  10 * MBIT;		/* traditional ethernet */
    if_speeds[  9 ] =   4 * MBIT;		/* Token Ring */
    if_speeds[ 37 ] = 155 * MBIT;		/* ATM */
    if_speeds[ 62 ] = 100 * MBIT;		/* fast ethernet */

			/* XXXX - Fill in the rest */
}

int Interface_Type_From_Name( const char *name )
{
    int len;
    match_if *pm;

    for ( pm = lmatch_if ; pm->mi_name!= NULL ; pm++ ) {
	len = strlen( pm->mi_name );
	if ( !strncmp( name, pm->mi_name, len ))
	    return (pm->mi_type);
    }
    return( 1 );	/* 'other' */
}

int Interface_Speed_From_Type( int type )
{
    if (( type < MAX_IF_TYPES ) && ( type >= 0 ))
	return if_speeds[ type ];
    else
	return 0;
}

int Interface_Speed_From_Name( const char *name )
{
    return ( Interface_Speed_From_Type( Interface_Type_From_Name( name )));
}


int Interface_Get_Ether_By_Index (int idx, char* buf, int *len) {
    int max_idx;
    struct if_entry *ifTable;

    ifTable = Retrieve_Table_Data( interface_table, &max_idx );

    if ( idx > max_idx )
	return -1;

		/* How do we do this ? */
    return -1;
}

int Interface_Scan_Get_Count (void) {
    int max_idx, i, count;
    struct if_entry *ifTable;

    ifTable = Retrieve_Table_Data( interface_table, &max_idx );

    count = 0;
    for ( i = 1 ; i <= max_idx ; i++ )
	if ( ifTable[i].ifstat )
	    count++;

    return count;
}

int Interface_Index_By_Name ( char *name) {

    int max_idx, i;
    struct if_entry *ifTable;

    ifTable = Retrieve_Table_Data( interface_table, &max_idx );

    for ( i = 1 ; i <= max_idx ; i++ )
	if ( !strcmp(ifTable[i].name, name ))
	    return ( ifTable[i].index );

    return -1;
}

void Clear_Interface_Table( mib_table_t t)
{
    int max_idx, i;
    struct if_entry *ifTable;

    ifTable = Retrieve_Table_Data( t, &max_idx );

    for ( i = 1 ; i <= max_idx ; i++ ) {
	if ( ifTable[i].ifstat ) {
	    free( ifTable[i].ifstat );
	    ifTable[i].ifstat=NULL;
	}
	if ( ifTable[i].ifaddr ) {
	    free( ifTable[i].ifaddr );
	    ifTable[i].ifaddr=NULL;
	}
    }
}


int Add_IF_Entry( mib_table_t t, struct if_entry *entry )
{
    int max_idx, i;
    struct if_entry *ifTable;

    ifTable = Retrieve_Table_Data( t, &max_idx );

		/* Look for an existing entry with this name */
    for ( i = 1 ; i <= max_idx ; i++ ) {
	if ( !strcmp(ifTable[i].name, entry->name )) {

	    if ( ifTable[i].ifstat )
		free( ifTable[i].ifstat );
	    ifTable[i].ifstat = entry->ifstat;
	    entry->ifstat = NULL;

	    if ( ifTable[i].ifaddr )
		free( ifTable[i].ifaddr );
	    ifTable[i].ifaddr = entry->ifaddr;
	    entry->ifaddr = NULL;

	    return 1;
	}
    }

		/* Otherwise, add it to the list */
    entry->index = i;
    return (Add_Entry( t, (void*)entry ));
}


static int if_scan_idx, if_scan_max_idx;
static struct if_entry *if_scan_Table;

void
Interface_Scan_Init( void )
{
    if_scan_idx  = 1;

    if_scan_Table = Retrieve_Table_Data( interface_table, &if_scan_max_idx );
}

int
Interface_Scan_Next(short *Index,
                        char *Name,
                        IFENTRY_TYPE *Retifnet,
                        IFADDR_TYPE  *Retifaddr)
{
    while ( if_scan_idx <= if_scan_max_idx ) {

	if ( if_scan_Table[if_scan_idx].ifstat == NULL ) {
	     if_scan_idx++;
	     continue;
	}

	*Index = if_scan_Table[if_scan_idx].index;
	if ( Name )
	    strcpy(Name, if_scan_Table[if_scan_idx].name);
	if ( Retifnet )
	    memcpy(Retifnet, if_scan_Table[if_scan_idx].ifstat, sizeof( IFENTRY_TYPE ));
	if ( Retifaddr )
	    memcpy(Retifaddr, if_scan_Table[if_scan_idx].ifaddr, sizeof( IFADDR_TYPE ));
	if_scan_idx++;
	return 0;
    }

    return -1;
}


	/*********************
	 *
	 *  System-specific functions to read
	 *   in the list of interfaces
	 *
	 *********************/

#ifdef  USE_SYSCTL_IFLIST
#define LOAD_INTERFACE_LIST
#define ROUNDUP(a) \
        ((a) > 0 ? (1 + (((a) - 1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

int Load_Interface_List( mib_table_t t )
{
    int name[] = {CTL_NET,PF_ROUTE,0,0,NET_RT_IFLIST,0};
    u_char *if_list, *if_list_end, *cp;
    struct if_msghdr *ifm;
    struct ifa_msghdr *ifam;
    size_t size;
    struct if_entry entry;
    struct sockaddr_dl *sdl;

    Clear_Interface_Table( t );

		/*
		 * Read in the data
		 */
    if (sysctl (name, sizeof(name)/sizeof(int), 0, &size, 0, 0) == -1) {
	snmp_log(LOG_ERR,"sysctl size fail\n");
	return -1;
    }
    if ( size == 0 )
	return -1;	/* No interfaces */
    if ((if_list = malloc (size)) == NULL) {
	snmp_log(LOG_ERR,"out of memory allocating interface table\n");
	return -1;
    }
    if (sysctl (name, sizeof(name)/sizeof(int), if_list, &size, 0, 0) == -1) {
	snmp_log(LOG_ERR,"sysctl get fail\n");
	free(if_list);
	return -1;
    }
    if_list_end = if_list + size;


		/*
		 * Step through this buffer,
		 *  adding entries to the table
		 */
    for (cp = if_list; cp < if_list_end; cp += ifm->ifm_msglen) {
	ifm = (struct if_msghdr *)cp;

	if (ifm->ifm_type == RTM_IFINFO) {
	    entry.ifstat = malloc(sizeof(*ifm));
	    if ( entry.ifstat == NULL )
		break;

	    sdl = (struct sockaddr_dl *)&ifm[1];
	    entry.index  = ifm->ifm_index;
	    entry.name   = strdup( sdl->sdl_data );
	    entry.name[sdl->sdl_nlen] = 0;
	    memcpy(entry.ifstat, ifm, sizeof(*ifm));

	    entry.ifaddr = malloc(sizeof(*entry.ifaddr));
	    entry.ifaddr->sifa_addr.s_addr = 0;		/* XXX */
	    entry.ifaddr->sifa_netmask.s_addr = 0;	/* XXX */
	    entry.ifaddr->sifa_broadcast.s_addr = 0;	/* XXX */

	    ifm = (struct if_msghdr *)(cp + ifm->ifm_msglen);
	    if (ifm->ifm_type == RTM_NEWADDR) {
		char *cp2, *cp2lim;
		int i;
		struct sockaddr_in *sin;

		cp = (char *)ifm;
		ifam = (struct ifa_msghdr *) ifm;
		cp2 = (char *)(ifam + 1);
		cp2lim =  ifam->ifam_msglen + (char *)ifam;
		for (i = 0; (i < RTAX_MAX) && (cp2 < cp2lim); i++) {
		    if ((ifam->ifam_addrs & (1 << i)) == 0)
			continue;
		    sin = (struct sockaddr_in *)cp2;
		    if (i == RTAX_IFA)
			entry.ifaddr->sifa_addr = sin->sin_addr;
		    if (i == RTAX_BRD)
			entry.ifaddr->sifa_netmask = sin->sin_addr;
		    if (i == RTAX_NETMASK)
			entry.ifaddr->sifa_broadcast = sin->sin_addr;
		    ADVANCE(cp2, (struct sockaddr *)sin);
		}
	    }

		/*
		 * Add this to the table
		 */
	        if ( Add_IF_Entry( t, &entry ) < 0 )
		    break;
	}

    }
    free( if_list );
    return 0;
}
#endif

#if defined(HAVE_NET_IF_MIB_H) && defined(IS_THIS_DIFFERENT_FROM_ABOVE)
#define LOAD_INTERFACE_LIST
int Load_Interface_List( mib_table_t t )
{
    int name[] = {CTL_NET,PF_ROUTE,0,AF_LINK,NET_RT_IFLIST,0};
    u_char *if_list, *if_list_end, *cp;
    size_t size;
    struct if_entry entry;

    Clear_Interface_Table( t );

		/*
		 * Read in the data
		 */
    if (sysctl (name, sizeof(name)/sizeof(int), 0, &size, 0, 0) == -1) {
	snmp_log(LOG_ERR,"sysctl size fail\n");
	return -1;
    }
    if ( size == 0 )
	return -1;	/* No interfaces */
    if ((if_list = malloc (size)) == NULL) {
	snmp_log(LOG_ERR,"out of memory allocating interface table\n");
	return -1;
    }
    if (sysctl (name, sizeof(name)/sizeof(int), if_list, &size, 0, 0) == -1) {
	snmp_log(LOG_ERR,"sysctl get fail\n");
	free(if_list);
	return -1;
    }
    if_list_end = if_list + size;


		/*
		 * Step through this buffer,
		 *  adding entries to the table
		 */
    for (cp = if_list; cp < if_list_end; cp += ifp->ifm_msglen) {

		/* XXXX - Set up 'entry'  */

		/*
		 * Add this to the table
		 */
	if ( Add_IF_Entry( t, &entry ) < 0 )
	    break;

    }
    free( if_list );
    return 0;
}
#endif

#ifdef  hpux
#define LOAD_INTERFACE_LIST

static int ifIndexMap[ 100 ]; 

int Load_Interface_List( mib_table_t t )
{
    int numIfEntries, numIpAddrEntries, size, i, j;
    struct if_entry entry;
    mib_ifEntry *ifEntries;
    mib_ipAdEnt *ipAddrEntries, ipaddr_p;
    char *cp;

    Clear_Interface_Table( t );

		/*
		 *  Read in interface table
		 */
    if (hpux_read_stat((char *)&numIfEntries, sizeof(int), ID_ifNumber) == -1)
	return -1;

    size = numIfEntries*sizeof(mib_ifEntry);
    if ( (ifEntries=(mib_ifEntry *)malloc ( size )) == NULL )
	return -1;

    if (hpux_read_stat((char *)ifEntries, size, ID_ifTable) == -1) {
	free( ifEntries );
	return -1;
    }

		/*
		 *  Read in ipAdddress table
		 */
    if (hpux_read_stat((char *)&numIpAddrEntries,
				sizeof(int), ID_ipAddrNumEnt) == -1) {
	free( ifEntries );
	return -1;
    }

    size = numIpAddrEntries*sizeof(mib_ipAdEnt);
    if ( (ipAddrEntries=(mib_ipAdEnt *)malloc ( size )) == NULL ) {
	free( ifEntries );
	return -1;
    }

    if (hpux_read_stat((char *)ipAddrEntries, size, ID_ipAddrTable) == -1) {
	free( ifEntries );
	free( ipAddrEntries );
	return -1;
    }

		/*
		 *  Merge the two
		 */
    for ( i = 0 ; i<numIfEntries ; i++ ) {
	entry.ifaddr = NULL;
	entry.ifstat = (mib_ifEntry *)malloc( sizeof( mib_ifEntry ));
	if ( entry.ifstat == NULL )
	    break;
	memcpy( entry.ifstat, &(ifEntries[i]), sizeof( mib_ifEntry ));
	cp = strchr( ifEntries[i].ifDescr, ' ');
	if ( cp != NULL )
	    *cp = '\0';
	entry.name = strdup( ifEntries[i].ifDescr );

	entry.ifaddr = NULL;
	for ( j = 0 ; j<numIpAddrEntries ; j++ )
	    if ( ifEntries[i].ifIndex == ipAddrEntries[j].IfIndex ) {
		entry.ifaddr = (mib_ipAdEnt *)malloc( sizeof( mib_ipAdEnt ));
		if ( entry.ifaddr == NULL ) {
		    free( entry.ifstat );
		    break;
		}
		memcpy( entry.ifaddr, &(ipAddrEntries[j]), sizeof(mib_ifEntry));
		break;
	    }

	if ( Add_IF_Entry( t, (void*)&entry) < 0 )
	    break;

		/*
		 *  Set up a mapping from HP's ifIndex values to UCDs
		 */
	ifIndexMap[ entry.ifstat->ifIndex ] = entry.index;

    }
    free( ifEntries );
    free( ipAddrEntries );
    return 0;
}
#endif

#ifdef  linux
#define LOAD_INTERFACE_LIST
const char *scan_line_2_2="%lu %lu %lu %*lu %*lu %*lu %*lu %*lu %lu %lu %lu %*lu %*lu %lu";
const char *scan_line_2_0="%lu %lu %*lu %*lu %*lu %lu %lu %*lu %*lu %lu";

int Load_Interface_List( mib_table_t t )
{
    FILE *in;
    char line [256], *cp1, *cp2, *ifname;
    struct if_entry entry;
    struct ifnet     *nnew;
    struct in_ifaddr *anew;
    struct ifreq ifrq;
    int  use_2_2_scan_line;
    int  fd;


    if (! (in = fopen ("/proc/net/dev", "r"))) {
	snmp_log(LOG_ERR,"cannot open /proc/net/dev ...\n");
	return -1;
    }

    Clear_Interface_Table( t );

	/*
	 *  There are two formats for interface statistics output,
	 *  corresponding to the 2.0 and 2.2 kernels.
	 *  They can be distinguished by the format of the header
	 *   (i.e. the first two lines) - the 2.2 format having
	 *   a number of additional values reported.
	 *
	 *  It might be possible to analyse the fields to determine
	 *    precisely which fields are needed, but frankly, it's
	 *    not really worth it.  This format changes so infrequently
	 *    that it's reasonable to hardwire the appropriate scan line
	 *    for particular kernels.
	 */
    fgets(line, sizeof(line), in);		/* skip the first line */
    fgets(line, sizeof(line), in);		/* this has the field names */
    if (strstr(line, "compressed")) {
	use_2_2_scan_line = TRUE;
	DEBUGMSGTL(("mibII/interfaces", "using linux 2.2 kernel /proc/net/dev\n"));
    } else {
	use_2_2_scan_line = FALSE;
	DEBUGMSGTL(("mibII/interfaces", "using linux 2.0 kernel /proc/net/dev\n"));
    }
 
	/*
	 * We need a network socket to perform ioctls on,
	 *   so let's open it now.
	 */
    if ((fd = socket (AF_INET, SOCK_DGRAM, 0)) < 0) {
	DEBUGMSGTL(("snmpd", "socket open failure in Interface_Scan_Init\n"));
	fclose(in);
	return -1;
    }
 
		/*
		 *  Read in the various interface statistics lines,
		 *    and create 'IfList' entries for each one,
		 *    linking them into a list.
		 */
    while (fgets (line, sizeof(line), in)) {

	nnew = (struct ifnet *) calloc (1, sizeof (struct ifnet));	    
	if ( !nnew ) {
	    break;
	}
	anew = (struct in_ifaddr *) calloc (1, sizeof (struct in_ifaddr));
	if ( !anew ) {
	    free( nnew );
	    break;
	}

		/*
		 * Extract the interface name
		 *   (skipping leading blanks)
		 */
	cp1 = line;
	while (isspace( *cp1 ))
	    cp1++;
	cp2 = strrchr( cp1, ':' );
	*cp2 = '\0';

	entry.name = strdup( cp1 );
	ifname = entry.name;	/* just for ease of use in this routine */
	
		/*
		 * Extract the appropriate statistics
		 * Note that the 2.0 kernel doesn't supply octet counts
		 */
	cp2++;
	if ( use_2_2_scan_line ) {
	    sscanf( cp2, scan_line_2_2,
			&nnew->if_ibytes, &nnew->if_ipackets, &nnew->if_ierrors,
			&nnew->if_obytes, &nnew->if_opackets, &nnew->if_oerrors,
			&nnew->if_collisions);
	}
	else {
	    sscanf( cp2, scan_line_2_0,
			&nnew->if_ipackets, &nnew->if_ierrors,
			&nnew->if_opackets, &nnew->if_oerrors,
			&nnew->if_collisions);
	    nnew->if_ibytes = nnew->if_obytes = 0;
	}

		/*
		 * Split the name into type and unit number
		 */
	nnew->if_name = strdup( cp1 );
	cp2 = &(cp1[ strlen( cp1 ) -1 ]);
	for ( cp2 = cp1 ; cp2 ; cp2++ )
	    if ( isdigit( *cp2 ))
		break;

	if ( cp2 )
	while ( isdigit( *cp2 )) {
	   cp2--;
	   if (cp2 == cp1 )
		break;
	}
				/* XXX - do we actually need this ? */
	if ( cp2 ) {
	    nnew->if_unit = strdup( cp2 );	/* or atoi()? */
	    *cp2 = '\0';
	}


		/*
		 *  Fill in the rest of the ifnet & ifaddr structures
		 *   using suitable ioctl calls
		 */
	
	strcpy (ifrq.ifr_name, ifname);
	if (ioctl (fd, SIOCGIFADDR, &ifrq) == 0)
	  anew->ia_addr = ifrq.ifr_addr;

	strcpy (ifrq.ifr_name, ifname);
	if (ioctl (fd, SIOCGIFBRDADDR, &ifrq) == 0)
	  anew->ia_broadaddr = ifrq.ifr_broadaddr;

	strcpy (ifrq.ifr_name, ifname);
	if (ioctl (fd, SIOCGIFNETMASK, &ifrq) == 0)
	  anew->ia_subnetmask = ifrq.ifr_netmask;
	  
	strcpy (ifrq.ifr_name, ifname);
	nnew->if_flags = ioctl (fd, SIOCGIFFLAGS, &ifrq) < 0 
	  		? 0 : ifrq.ifr_flags;
	
	strcpy (ifrq.ifr_name, ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifrq) == 0) {
	  memcpy (nnew->if_hwaddr, ifrq.ifr_hwaddr.sa_data, 6);

#ifdef ARPHRD_LOOPBACK
	  switch (ifrq.ifr_hwaddr.sa_family) {
	  case ARPHRD_TUNNEL:
	  case ARPHRD_TUNNEL6:
	  case ARPHRD_IPGRE:
	  case ARPHRD_SIT:
	      nnew->if_type = 131; break; /* tunnel */
	  case ARPHRD_SLIP:
	  case ARPHRD_CSLIP:
	  case ARPHRD_SLIP6:
	  case ARPHRD_CSLIP6:
	      nnew->if_type = 28; break; /* slip */
	  case ARPHRD_PPP:
	      nnew->if_type = 23; break; /* ppp */
	  case ARPHRD_LOOPBACK:
	      nnew->if_type = 24; break; /* softwareLoopback */
          /* XXX: more if_arp.h:ARPHDR_xxx to IANAifType mappings... */
	  }
#endif
	}
	    
	strcpy (ifrq.ifr_name, ifname);
	nnew->if_metric = ioctl (fd, SIOCGIFMETRIC, &ifrq) < 0
	  		? 0 : ifrq.ifr_metric;
	    
#ifdef SIOCGIFMTU
	strcpy (ifrq.ifr_name, ifname);
	nnew->if_mtu = (ioctl (fd, SIOCGIFMTU, &ifrq) < 0) 
			  ? 0 : ifrq.ifr_mtu;
#else
	nnew->if_mtu = 0;
#endif

	if (!nnew->if_type) 
	    nnew->if_type  = Interface_Type_From_Name(nnew->if_name);
	nnew->if_speed = Interface_Speed_From_Type(nnew->if_type);


		/*
		 * Add this to the table
		 */
	entry.ifstat = nnew;
	entry.ifaddr = anew;
	if ( Add_IF_Entry( t, &entry ) < 0 )
	    break;

    }	/* while fgets() */

    fclose( in );
    return 0;
}
#endif

#ifndef LOAD_INTERFACE_LIST
int Load_Interface_List( mib_table_t t )
{
    struct ifnet *ifnetaddr, ifnet;
    struct in_ifaddr *ia, in_ifaddr;
    struct if_entry entry;
    char *cp, ifname[32];

    Clear_Interface_Table( t );
    auto_nlist(IFNET_SYMBOL, (char *)&ifnetaddr, sizeof(ifnetaddr));
    
    while (ifnetaddr) {

	    /*
	     *	    Get the "ifnet" structure and extract the device name
	     */
	    klookup((unsigned long)ifnetaddr, (char *)&ifnet, sizeof ifnet);
#if STRUCT_IFNET_HAS_IF_XNAME
#if defined(netbsd1) || defined(openbsd2)
	strncpy(ifname, ifnet.if_xname, sizeof ifname);
#else
	klookup((unsigned long)ifnet.if_xname, (char *)ifname, sizeof ifname);
#endif
	ifname[sizeof (ifname)-1] = '\0';
#else
	klookup((unsigned long)ifnet.if_name, (char *)ifname, sizeof ifname);

	ifname[sizeof (ifname)-1] = '\0';
	cp = strchr(ifname, '\0');
	string_append_int (cp, ifnet.if_unit);
#endif

	entry.name = strdup( ifname );


		/*
		 *  Try to find an address for this interface
		 */

	auto_nlist(IFADDR_SYMBOL, (char *)&ia, sizeof(ia));
	while (ia) {
	    klookup((unsigned long)ia ,  (char *)&in_ifaddr, sizeof(in_ifaddr));
	    if (in_ifaddr.ia_ifp == ifnetaddr) break;
	    ia = in_ifaddr.ia_next;
	}

#if !defined(netbsd1) && !defined(freebsd2) && !defined(openbsd2) && !defined(STRUCT_IFNET_HAS_IF_ADDRLIST)
	ifnet.if_addrlist = (struct ifaddr *)ia;     /* WRONG DATA TYPE; ONLY A FLAG */
#endif

		/*
		 * Set up the entry and it to the table
		 */
	entry.ifstat = (struct ifnet *)malloc( sizeof( ifnet ));
	if ( entry.ifstat == NULL )
	    break;
	entry.ifaddr = (struct in_ifaddr *)malloc( sizeof( in_ifaddr ));
	if ( entry.ifaddr == NULL ) {
	    free( entry.ifstat );
	    break;
	}
	memcpy( &entry.ifstat, &ifnet,     sizeof( ifnet ));
	memcpy( &entry.ifaddr, &in_ifaddr, sizeof( in_ifaddr ));

	if ( Add_IF_Entry( t, &entry ) < 0 )
	    break;
	ifnetaddr = ifnet.if_next;
    }
    return 0;
}
#endif

