/*
 *  Template MIB group implementation - at.c
 *
 */

#include "../common_header.h"
#include "at.h"
#include "interfaces.h"


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


#ifndef linux
static struct nlist at_nl[] = {
#define N_ARPTAB_SIZE	0
#define N_ARPTAB        1
#if !defined(hpux) && !defined(solaris2)
	{ "_arptab_size" }, 
	{ "_arptab" },      
#else
	{ "arptab_nb" }, 
	{ "arphd" },      
#endif
        { 0 },
};
#endif

#ifndef solaris2
static void ARP_Scan_Init __P((void));
#if defined(freebsd2) || defined (netbsd1) || defined (hpux) || defined (bsdi2)
static int ARP_Scan_Next __P((u_long *, char *, u_long *, u_short *));
#else
static int ARP_Scan_Next __P((u_long *, char *, u_long *));
#endif
#endif


	/*********************
	 *
	 *  Public interface functions
	 *
	 *********************/


void	init_at( )
{
#ifndef linux
    init_nlist( at_nl );
#endif
}


#ifndef solaris2
u_char *
var_atEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;	/* IN - pointer to variable entry that points here */
    register oid	    *name;	/* IN/OUT - input name requested, output name found */
    register int	    *length;	/* IN/OUT - length of input and output oid's */
    int			    exact;	/* IN - TRUE if an exact match was requested. */
    int			    *var_len;	/* OUT - length of variable or 0 if function returned. */
    int			    (**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
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
#if defined(freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2)
    u_short		    ifIndex, lowIfIndex;
#endif/* (freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2) */
    u_long		    ifType, lowIfType;

    int                     oid_length;

    /* fill in object part of name for current (less sizeof instance part) */
    bcopy((char *)vp->name, (char *)current, (int)vp->namelen * sizeof(oid));

    if (current[6] == 3 ) {	/* AT group oid */
	oid_length = 16;
    }
    else {			/* IP NetToMedia group oid */
	oid_length = 15;
    }

    LowAddr = -1;      /* Don't have one yet */
    ARP_Scan_Init();
    for (;;) {
#if defined(freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2)
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
#else /* (freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2) */
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
#endif /* (freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2) */
	cp = (u_char *)&Addr;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;

	if (exact){
	    if (compare(current, oid_length, name, *length) == 0){
		bcopy((char *)current, (char *)lowest, oid_length * sizeof(oid));
		LowAddr = Addr;
#if defined(freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2)
		lowIfIndex = ifIndex;
#endif /*  defined(freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2) */
		bcopy(PhysAddr, LowPhysAddr, sizeof(PhysAddr));
		lowIfType = ifType;
		break;	/* no need to search further */
	    }
	} else {
	    if ((compare(current, oid_length, name, *length) > 0) &&
		 ((LowAddr == -1) || (compare(current, oid_length, lowest, oid_length) < 0))){
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, save this one as the "next" one.
		 */
		bcopy((char *)current, (char *)lowest, oid_length * sizeof(oid));
		LowAddr = Addr;
#if defined(freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2)
		lowIfIndex = ifIndex;
#endif /*  defined(freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2) */
		bcopy(PhysAddr, LowPhysAddr, sizeof(PhysAddr));
		lowIfType = ifType;
	    }
	}
    }
    if (LowAddr == -1)
	return(NULL);

    bcopy((char *)lowest, (char *)name, oid_length * sizeof(oid));
    *length = oid_length;
    *write_method = 0;
    switch(vp->magic){
	case IPMEDIAIFINDEX:			/* also ATIFINDEX */
	    *var_len = sizeof long_return;
#if defined(freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2)
	    long_return = lowIfIndex;
#else /* (freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2) */
	    long_return = 1; /* XXX */
#endif /* (freebsd2) || defined(netbsd1) || defined(hpux) || defined(bsdi2) */
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
	    ERROR_MSG("");
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
#ifdef DODEBUG
  printf ("......... AT_Cmp %lx<>%lx %d<>%d (%.5s)\n",
	  mp->ipNetToMediaNetAddress, ((if_ip_t *)addr)->ipAddr,
	  ((if_ip_t*)addr)->ifIdx,Interface_Index_By_Name (mp->ipNetToMediaIfIndex.o_bytes, mp->ipNetToMediaIfIndex.o_length),
	  mp->ipNetToMediaIfIndex.o_bytes);
#endif /*  DODEBUG */
  if (mp->ipNetToMediaNetAddress != ((if_ip_t *)addr)->ipAddr)
    ret = 1;
  else if (((if_ip_t*)addr)->ifIdx !=
      Interface_Index_By_Name (mp->ipNetToMediaIfIndex.o_bytes, mp->ipNetToMediaIfIndex.o_length))
	ret = 1;
  else ret = 0;
#ifdef DODEBUG
  printf ("......... AT_Cmp returns %d\n", ret);
#endif /*  DODEBUG */
  return ret;
}

u_char *
var_atEntry(struct variable *vp, oid *name, int *length, int exact,
	    int *var_len, int (**write_method)(int, u_char *, u_char, int, u_char *, oid *, int))
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
#ifdef DODEBUG
    char	c_oid[1024];
#endif /* DODEBUG */

    /* fill in object part of name for current (less sizeof instance part) */

#ifdef DODEBUG
    sprint_objid (c_oid, vp->name, vp->namelen);
    printf ("var_atEntry: %s %d\n", c_oid, exact);
#endif /* DODEBUG */
    memset (&Lowentry, 0, sizeof (Lowentry));
    bcopy((char *)vp->name, (char *)current, (int)vp->namelen * sizeof(oid));
    if (*length == AT_NAME_LENGTH) /* Assume that the input name is the lowest */
      bcopy((char *)name, (char *)lowest, AT_NAME_LENGTH * sizeof(oid));
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
	    if (compare(current, AT_NAME_LENGTH, name, *length) == 0){
		bcopy((char *)current, (char *)lowest, AT_NAME_LENGTH * sizeof(oid));
		Lowentry = entry;
		Found++;
		break;	/* no need to search further */
	    }
	} else {
	  if (Lowentry.ipNetToMediaNetAddress == entry.ipNetToMediaNetAddress) break;
	  if (compare(current, AT_NAME_LENGTH, name, *length) > 0
	      && (NextAddr.ipAddr == (u_long)-1
		  || compare(current, AT_NAME_LENGTH, lowest, AT_NAME_LENGTH) < 0)) {
/*
		  || (compare(name, AT_NAME_LENGTH, lowest, AT_NAME_LENGTH) == 0))){
*/
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, and is not equal to it, save this one as the "next" one.
		 */
		bcopy((char *)current, (char *)lowest, AT_NAME_LENGTH * sizeof(oid));
		Lowentry = entry;
		Found++;
	    }
	}
    }
#ifdef DODEBUG
    printf ("... Found = %d\n", Found);
#endif /* DODEBUG */
    if (Found == 0)
      return(NULL);
    bcopy((char *)lowest, (char *)name, AT_NAME_LENGTH * sizeof(oid));
    *length = AT_NAME_LENGTH;
    *write_method = 0;
    switch(vp->magic){
	case ATIFINDEX:
	    *var_len = sizeof long_return;
	    long_return = Interface_Index_By_Name(Lowentry.ipNetToMediaIfIndex.o_bytes,
						  Lowentry.ipNetToMediaIfIndex.o_length);
	    return (u_char *)&long_return;
	case ATPHYSADDRESS:
	    *var_len = Lowentry.ipNetToMediaPhysAddress.o_length;
	    (void)memcpy(return_buf, Lowentry.ipNetToMediaPhysAddress.o_bytes, *var_len);
	    return (u_char *)return_buf;
	case ATNETADDRESS:
	    *var_len = sizeof long_return;
	    long_return = Lowentry.ipNetToMediaNetAddress;
	    return (u_char *)&long_return;
	default:
	    ERROR_MSG("");
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

static void ARP_Scan_Init __P((void))
{
#ifndef CAN_USE_SYSCTL
#ifndef linux
	if (!at) {
	    KNLookup(at_nl, N_ARPTAB_SIZE, (char *)&arptab_size, sizeof arptab_size);
#ifdef STRUCT_ARPHD_HAS_AT_NEXT
          at = (struct arphd  *) malloc(arptab_size * sizeof(struct arphd));
#else
	    at = (struct arptab *) malloc(arptab_size * sizeof(struct arptab));
#endif
	}

#ifdef STRUCT_ARPHD_HAS_AT_NEXT
      KNLookup(at_nl,  N_ARPTAB, (char *)at, arptab_size * sizeof(struct arphd));
      at_ptr = at[0].at_next;
#else
	KNLookup(at_nl,  N_ARPTAB, (char *)at, arptab_size * sizeof(struct arptab));
#endif
	arptab_current = 0;
#else /* linux */
	FILE *in = fopen ("/proc/net/arp", "r");
	int i, n = 0;
        char line [128];
	int za, zb, zc, zd, ze, zf, zg, zh, zi, zj;

	if (!in) {
		fprintf (stderr, "snmpd: Cannot open /proc/net/arp\n");
		arptab_current = 0;
		return;
	}
	for (n = -1; fgets (line, sizeof line, in); n++)
		;
	fclose (in);
	in = fopen ("/proc/net/arp", "r");
	if (at) free (at);
	arptab_size = n;
	if (arptab_size > 0)
		at = malloc (arptab_size * sizeof (struct arptab));
	else
		at = NULL;
	for (i = 0; i < arptab_size; i++) {
		while (line == fgets (line, sizeof line, in) &&
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
		perror("route-sysctl-estimate");
	if ((at = malloc(needed)) == NULL)
		perror("malloc");
	if (sysctl(mib, 6, at, &needed, NULL, 0) < 0)
		perror("actual retrieval of routing table");
	lim = at + needed;
	rtnext = at;
#endif /* CAN_USE_SYSCTL */
}

#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2) || defined(hpux)
static int ARP_Scan_Next(IPAddr, PhysAddr, ifType, ifIndex)
u_short *ifIndex;
#else
static int ARP_Scan_Next(IPAddr, PhysAddr, ifType)
#endif
u_long *IPAddr;
char *PhysAddr;
u_long *ifType;
{
#if !defined (netbsd1) && !defined (freebsd2) && !defined(bsdi2)
	register struct arptab *atab;

	while (arptab_current < arptab_size) {
#ifdef STRUCT_ARPHD_HAS_AT_NEXT
              /* The arp table is an array of linked lists of arptab entries.
                 Unused slots have pointers back to the array entry itself */

              if ( at_ptr == (at_nl[N_ARPTAB].n_value +
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
		bcopy((char *) &atab->at_enaddr, PhysAddr, sizeof(atab->at_enaddr));
#endif
#if defined(mips) || defined(ibm032) 
		bcopy((char *)  atab->at_enaddr, PhysAddr, sizeof(atab->at_enaddr));
#endif
	return(1);
	}
#else /* netbsd1, freebsd2, bsdi2 */
	struct rt_msghdr *rtm;
	struct sockaddr_inarp *sin;
	struct sockaddr_dl *sdl;
	extern int h_errno;

	while (rtnext < lim) {
		rtm = (struct rt_msghdr *)rtnext;
		sin = (struct sockaddr_inarp *)(rtm + 1);
		sdl = (struct sockaddr_dl *)(sin + 1);
		rtnext += rtm->rtm_msglen;
		if (sdl->sdl_alen) {
			*IPAddr = sin->sin_addr.s_addr;
			bcopy((char *) LLADDR(sdl), PhysAddr, sdl->sdl_alen);
			*ifIndex = sdl->sdl_index;
			*ifType = 1;	/* XXX */
			return(1);
		}
	}
#endif /* netbsd1, freebsd2, bsdi2 */
	return(0);	    /* "EOF" */
}
#endif /* solaris2 */
