/*
 *  Template MIB group implementation - at.c
 *
 */

#include <config.h>
#if HAVE_STRING_H
#include <string.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if defined(IFNET_NEEDS_KERNEL) && !defined(_KERNEL)
#define _KERNEL 1
#define _I_DEFINED_KERNEL
#endif
#include <sys/types.h>
#include <sys/socket.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
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

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include "mibincl.h"
#include "at.h"
#include "interfaces.h"
#include "auto_nlist.h"
#include "system.h"

#if defined(HAVE_SYS_SYSCTL_H) && !defined(CAN_USE_SYSCTL)
# if defined(RTF_LLINFO) && !defined(irix6)
#  define CAN_USE_SYSCTL 1
# endif
#endif

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


#ifndef solaris2
static void ARP_Scan_Init (void);
#ifdef ARP_SCAN_FOUR_ARGUMENTS
static int ARP_Scan_Next (u_long *, char *, u_long *, u_short *);
#else
static int ARP_Scan_Next (u_long *, char *, u_long *);
#endif
#endif


	/*********************
	 *
	 *  Public interface functions
	 *
	 *********************/

/* define the structure we're going to ask the agent to register our
   information at */
struct variable4 at_variables[] = {
    {ATIFINDEX, ASN_INTEGER, RONLY, var_atEntry, 1, {1}},
    {ATPHYSADDRESS, ASN_OCTET_STR, RONLY, var_atEntry, 1, {2}},
    {ATNETADDRESS, ASN_IPADDRESS, RONLY, var_atEntry, 1, {3}}
};

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
oid at_variables_oid[] = { SNMP_OID_MIB2,3,1,1 };

void init_at(void)
{
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("mibII/at", at_variables, variable4, at_variables_oid);
}


#ifndef solaris2

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
    u_char		    *cp;
    oid			    *op;
    oid			    lowest[16];
    oid			    current[16];
    static char		    PhysAddr[6], LowPhysAddr[6];
    u_long		    Addr, LowAddr;
#ifdef ARP_SCAN_FOUR_ARGUMENTS
    u_short		    ifIndex, lowIfIndex = 0;
#endif/* ARP_SCAN_FOUR_ARGUMENTS */
    u_long		    ifType, lowIfType = 0;

    int                     oid_length;

    /* fill in object part of name for current (less sizeof instance part) */
    memcpy((char *)current, (char *)vp->name, (int)vp->namelen * sizeof(oid));

    if (current[6] == 3 ) {	/* AT group oid */
	oid_length = 16;
    }
    else {			/* IP NetToMedia group oid */
	oid_length = 15;
    }

    LowAddr = -1;      /* Don't have one yet */
    ARP_Scan_Init();
    for (;;) {
#ifdef ARP_SCAN_FOUR_ARGUMENTS
	if (ARP_Scan_Next(&Addr, PhysAddr, &ifType, &ifIndex) == 0)
	    break;
	current[10] = ifIndex;

	if (current[6] == 3 ) {	/* AT group oid */
	    current[11] = 1;
	    op = current + 12;
	}
	else {			/* IP NetToMedia group oid */
	    op = current + 11;
	}
#else /* ARP_SCAN_FOUR_ARGUMENTS */
	if (ARP_Scan_Next(&Addr, PhysAddr, &ifType) == 0)
	    break;
	current[10] = 1;

	if (current[6] == 3 ) {	/* AT group oid */
	    current[11] = 1;
	    op = current + 12;
	}
	else {			/* IP NetToMedia group oid */
	    op = current + 11;
	}
#endif /* ARP_SCAN_FOUR_ARGUMENTS */
	cp = (u_char *)&Addr;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;

	if (exact){
	    if (snmp_oid_compare(current, oid_length, name, *length) == 0){
		memcpy( (char *)lowest,(char *)current, oid_length * sizeof(oid));
		LowAddr = Addr;
#ifdef ARP_SCAN_FOUR_ARGUMENTS
		lowIfIndex = ifIndex;
#endif /*  ARP_SCAN_FOUR_ARGUMENTS */
		memcpy( LowPhysAddr,PhysAddr, sizeof(PhysAddr));
		lowIfType = ifType;
		break;	/* no need to search further */
	    }
	} else {
	    if ((snmp_oid_compare(current, oid_length, name, *length) > 0) &&
		 ((LowAddr == -1) || (snmp_oid_compare(current, oid_length, lowest, oid_length) < 0))){
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, save this one as the "next" one.
		 */
		memcpy( (char *)lowest,(char *)current, oid_length * sizeof(oid));
		LowAddr = Addr;
#ifdef ARP_SCAN_FOUR_ARGUMENTS
		lowIfIndex = ifIndex;
#endif /*  ARP_SCAN_FOUR_ARGUMENTS */
		memcpy( LowPhysAddr,PhysAddr, sizeof(PhysAddr));
		lowIfType = ifType;
	    }
	}
    }
    if (LowAddr == -1)
	return(NULL);

    memcpy( (char *)name,(char *)lowest, oid_length * sizeof(oid));
    *length = oid_length;
    *write_method = 0;
    switch(vp->magic){
	case IPMEDIAIFINDEX:			/* also ATIFINDEX */
	    *var_len = sizeof long_return;
#ifdef ARP_SCAN_FOUR_ARGUMENTS
	    long_return = lowIfIndex;
#else /* ARP_SCAN_FOUR_ARGUMENTS */
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = 1; /* XXX */
#endif /* ARP_SCAN_FOUR_ARGUMENTS */
	    return (u_char *)&long_return;
	case IPMEDIAPHYSADDRESS:		/* also ATPHYSADDRESS */
	    *var_len = sizeof(LowPhysAddr);
	    return (u_char *)LowPhysAddr;
	case IPMEDIANETADDRESS:			/* also ATNETADDRESS */
	    *var_len = sizeof long_return;
	    long_return = LowAddr;
	    return (u_char *)&long_return;
	case IPMEDIATYPE:
	    *var_len = sizeof long_return;
	    long_return = lowIfType;
	    return (u_char *)&long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_atEntry\n", vp->magic));
   }
   return NULL;
}

#else          /* solaris2 */

typedef struct if_ip {
  int ifIdx;
  IpAddress ipAddr;
} if_ip_t;

static int
AT_Cmp(void *addr, void *ep)
{ mib2_ipNetToMediaEntry_t *mp = (mib2_ipNetToMediaEntry_t *) ep;
  int ret = -1;
  DEBUGMSGTL(("mibII/at", "......... AT_Cmp %lx<>%lx %d<>%d (%.5s)\n",
	  mp->ipNetToMediaNetAddress, ((if_ip_t *)addr)->ipAddr,
	  ((if_ip_t*)addr)->ifIdx,Interface_Index_By_Name (mp->ipNetToMediaIfIndex.o_bytes, mp->ipNetToMediaIfIndex.o_length),
	  mp->ipNetToMediaIfIndex.o_bytes));
  if (mp->ipNetToMediaNetAddress != ((if_ip_t *)addr)->ipAddr)
    ret = 1;
  else if (((if_ip_t*)addr)->ifIdx !=
      Interface_Index_By_Name (mp->ipNetToMediaIfIndex.o_bytes, mp->ipNetToMediaIfIndex.o_length))
	ret = 1;
  else ret = 0;
  DEBUGMSGTL(("mibII/at", "......... AT_Cmp returns %d\n", ret));
  return ret;
}

u_char *
var_atEntry(struct variable *vp,
	    oid *name,
	    size_t *length,
	    int exact,
	    size_t *var_len,
	    WriteMethod **write_method)
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.3.1.1.1.interface.1.A.B.C.D,  where A.B.C.D is IP address.
     * Interface is at offset 10,
     * IPADDR starts at offset 12.
     */
#define AT_NAME_LENGTH	16
#define AT_IFINDEX_OFF	10
#define	AT_IPADDR_OFF	12
    u_char	*cp;
    oid		*op;
    oid		lowest[AT_NAME_LENGTH];
    oid		current[AT_NAME_LENGTH];
    if_ip_t	NextAddr;
    mib2_ipNetToMediaEntry_t entry, Lowentry;
    int		Found = 0;
    req_e	req_type;

    /* fill in object part of name for current (less sizeof instance part) */

    DEBUGMSGTL(("mibII/at", "var_atEntry: "));
    DEBUGMSGOID(("mibII/at", vp->name, vp->namelen));
    DEBUGMSG(("mibII/at"," %d\n", exact));

    memset (&Lowentry, 0, sizeof (Lowentry));
    memcpy( (char *)current,(char *)vp->name, vp->namelen * sizeof(oid));
    lowest[0] = 1024;
    for (NextAddr.ipAddr = (u_long)-1, NextAddr.ifIdx = 255, req_type = GET_FIRST;
	 ;
	 NextAddr.ipAddr = entry.ipNetToMediaNetAddress,
	 NextAddr.ifIdx = current [AT_IFINDEX_OFF],
	 req_type = GET_NEXT) {
	if (getMibstat(MIB_IP_NET, &entry, sizeof(mib2_ipNetToMediaEntry_t),
		 req_type, &AT_Cmp, &NextAddr) != 0)
		break;
      	current[AT_IFINDEX_OFF] = Interface_Index_By_Name (entry.ipNetToMediaIfIndex.o_bytes, entry.ipNetToMediaIfIndex.o_length);
	current[AT_IFINDEX_OFF+1] = 1;
        COPY_IPADDR(cp,(u_char *)&entry.ipNetToMediaNetAddress, op, current+AT_IPADDR_OFF);  
	if (exact){
	    if (snmp_oid_compare(current, AT_NAME_LENGTH, name, *length) == 0){
		memcpy( (char *)lowest,(char *)current, AT_NAME_LENGTH * sizeof(oid));
		Lowentry = entry;
		Found++;
		break;	/* no need to search further */
	    }
	} else {
	    if (snmp_oid_compare(current, AT_NAME_LENGTH, name, *length) > 0
	      && snmp_oid_compare(current, AT_NAME_LENGTH, lowest, AT_NAME_LENGTH) < 0) {
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, and is not equal to it, save this one as the "next" one.
		 */
		memcpy( (char *)lowest,(char *)current, AT_NAME_LENGTH * sizeof(oid));
		Lowentry = entry;
		Found++;
	    }
	}
    }
    DEBUGMSGTL(("mibII/at", "... Found = %d\n", Found));
    if (Found == 0)
	return(NULL);
    memcpy( (char *)name,(char *)lowest, AT_NAME_LENGTH * sizeof(oid));
    *length = AT_NAME_LENGTH;
    *write_method = 0;
    switch(vp->magic){
	case IPMEDIAIFINDEX:
	    *var_len = sizeof long_return;
	    long_return = Interface_Index_By_Name(Lowentry.ipNetToMediaIfIndex.o_bytes,
						  Lowentry.ipNetToMediaIfIndex.o_length);
	    return (u_char *)&long_return;
	case IPMEDIAPHYSADDRESS:
	    *var_len = Lowentry.ipNetToMediaPhysAddress.o_length;
	    (void)memcpy(return_buf, Lowentry.ipNetToMediaPhysAddress.o_bytes, *var_len);
	    return (u_char *)return_buf;
	case IPMEDIANETADDRESS:
	    *var_len = sizeof long_return;
	    long_return = Lowentry.ipNetToMediaNetAddress;
	    return (u_char *)&long_return;
	case IPMEDIATYPE:
	    *var_len = sizeof long_return;
	    long_return = Lowentry.ipNetToMediaType;
	    return (u_char *)&long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_atEntry\n", vp->magic));
   }
   return NULL;
}
#endif /* solaris2 */


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

#ifndef solaris2

#if CAN_USE_SYSCTL
static char *lim, *rtnext;
static char *at = 0;
#else
static int arptab_size, arptab_current;
#ifdef STRUCT_ARPHD_HAS_AT_NEXT
static struct arphd *at=0;
static struct arptab *at_ptr, at_entry;
static struct arpcom  at_com;
#else
static struct arptab *at=0;
#endif
#endif /* CAN_USE_SYSCTL */

static void ARP_Scan_Init (void)
{
#ifndef CAN_USE_SYSCTL
#ifndef linux
	if (!at) {
	    auto_nlist(ARPTAB_SIZE_SYMBOL, (char *)&arptab_size, sizeof arptab_size);
#ifdef STRUCT_ARPHD_HAS_AT_NEXT
          at = (struct arphd  *) malloc(arptab_size * sizeof(struct arphd));
#else
	    at = (struct arptab *) malloc(arptab_size * sizeof(struct arptab));
#endif
	}

#ifdef STRUCT_ARPHD_HAS_AT_NEXT
        auto_nlist(ARPTAB_SYMBOL, (char *)at, arptab_size * sizeof(struct arphd));
        at_ptr = at[0].at_next;
#else
        auto_nlist(ARPTAB_SYMBOL, (char *)at, arptab_size * sizeof(struct arptab));
#endif
	arptab_current = 0;
#else /* linux */
	FILE *in = fopen ("/proc/net/arp", "r");
	int i, n = 0;
        char line [128];
	int za, zb, zc, zd, ze, zf, zg, zh, zi, zj;

	if (!in) {
	 snmp_log(LOG_ERR, "snmpd: Cannot open /proc/net/arp\n");
		arptab_current = 0;
		return;
	}
	for (n = -1; fgets (line, sizeof(line), in); n++)
		;
	fclose (in);
	in = fopen ("/proc/net/arp", "r");
	if (at) free (at);
	arptab_current = 0; /* it was missing, bug??? */
	arptab_size = n;
	if (arptab_size > 0)
		at = (struct arptab *)
                  malloc (arptab_size * sizeof (struct arptab));
	else
		at = NULL;
	for (i = 0; i < arptab_size; i++) {
		while (line == fgets (line, sizeof(line), in) &&
			11 != sscanf (line, "%d.%d.%d.%d 0x%*x 0x%x %x:%x:%x:%x:%x:%x",
			&za, &zb, &zc, &zd, &at[i].at_flags,
			&ze, &zf, &zg, &zh, &zi, &zj))
			continue;
		at [i].at_enaddr[0] = ze;
		at [i].at_enaddr[1] = zf;
		at [i].at_enaddr[2] = zg;
		at [i].at_enaddr[3] = zh;
		at [i].at_enaddr[4] = zi;
		at [i].at_enaddr[5] = zj;
		at [i].at_iaddr.s_addr = (zd << 24) | (zc << 16) | (zb << 8) | za;
	}
	fclose (in);
#endif /* linux */
#else /* CAN_USE_SYSCTL */
	int mib[6];
	size_t needed;

	mib[0] = CTL_NET;
	mib[1] = PF_ROUTE;
	mib[2] = 0;
	mib[3] = AF_INET;
	mib[4] = NET_RT_FLAGS;
	mib[5] = RTF_LLINFO;

	if (at)
		free(at);
	if (sysctl(mib, 6, NULL, &needed, NULL, 0) < 0)
		snmp_log_perror("route-sysctl-estimate");
	if ((at = malloc(needed ? needed : 1)) == NULL)
		snmp_log_perror("malloc");
	if (sysctl(mib, 6, at, &needed, NULL, 0) < 0)
		snmp_log_perror("actual retrieval of routing table");
	lim = at + needed;
	rtnext = at;
#endif /* CAN_USE_SYSCTL */
}

#ifdef ARP_SCAN_FOUR_ARGUMENTS
static int ARP_Scan_Next(u_long *IPAddr, char *PhysAddr, u_long *ifType, u_short *ifIndex)
#else
static int ARP_Scan_Next(u_long *IPAddr, char *PhysAddr, u_long *ifType)
#endif
{
#ifndef CAN_USE_SYSCTL
#ifdef linux
	if (arptab_current<arptab_size)
	{
		/* copy values */
		*IPAddr= at[arptab_current].at_iaddr.s_addr;
		*ifType= (at[arptab_current].at_flags & ATF_PERM) ? 4/*static*/ : 3/*dynamic*/ ;
		memcpy( PhysAddr, &at[arptab_current].at_enaddr,
				sizeof(at[arptab_current].at_enaddr) );
		
		/* increment to point next entry */
		arptab_current++;
		/* return success */
		return( 1 );
	}
#endif /* linux */
  return 0; /* we need someone with an irix box to fix this section */
#else
#if !defined(ARP_SCAN_FOUR_ARGUMENTS) || defined(hpux)
	register struct arptab *atab;

	while (arptab_current < arptab_size) {
#ifdef STRUCT_ARPHD_HAS_AT_NEXT
              /* The arp table is an array of linked lists of arptab entries.
                 Unused slots have pointers back to the array entry itself */

              if ( at_ptr == (auto_nlist_value(ARPTAB_SYMBOL) +
                              arptab_current*sizeof(struct arphd))) {
                      /* Usused */
                  arptab_current++;
                  at_ptr = at[arptab_current].at_next;
                  continue;
              }

              klookup( at_ptr, (char *)&at_entry, sizeof(struct arptab));
              klookup( at_entry.at_ac, (char *)&at_com, sizeof(struct arpcom));

              at_ptr = at_entry.at_next;
              atab = &at_entry;
              *ifIndex = at_com.ac_if.if_index;       /* not strictly ARPHD */
#else /* STRUCT_ARPHD_HAS_AT_NEXT */
		atab = &at[arptab_current++];
#endif /* STRUCT_ARPHD_HAS_AT_NEXT */
		if (!(atab->at_flags & ATF_COM)) continue;
		*ifType = (atab->at_flags & ATF_PERM) ? 4 : 3 ;
		*IPAddr = atab->at_iaddr.s_addr;
#if defined (sunV3) || defined(sparc) || defined(hpux)
		memcpy( PhysAddr,(char *) &atab->at_enaddr, sizeof(atab->at_enaddr));
#endif
#if defined(mips) || defined(ibm032) 
		memcpy( PhysAddr,(char *)  atab->at_enaddr, sizeof(atab->at_enaddr));
#endif
	return(1);
	}
#else /* !defined(ARP_SCAN_FOUR_ARGUMENTS) || defined(hpux) */
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;

	while (rtnext < lim) {
		rtm = (struct rt_msghdr *)rtnext;
		sin = (struct sockaddr_inarp *)(rtm + 1);
		sdl = (struct sockaddr_dl *)(sin + 1);
		rtnext += rtm->rtm_msglen;
		if (sdl->sdl_alen) {
			*IPAddr = sin->sin_addr.s_addr;
			memcpy( PhysAddr,(char *) LLADDR(sdl), sdl->sdl_alen);
			*ifIndex = sdl->sdl_index;
			*ifType = 1;	/* XXX */
			return(1);
		}
	}
#endif /* !defined(ARP_SCAN_FOUR_ARGUMENTS) || defined(hpux) */
	return(0);	    /* "EOF" */
#endif /* !CAN_USE_SYSCTL */
}
#endif /* solaris2 */
