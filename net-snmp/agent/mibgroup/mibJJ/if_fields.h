/*
 *	System-specific type and field-name information.
 *	Used by 'interface' and 'ipAddr' groups.
 */

#ifndef _MIBGROUP_IF_FIELDS_H
#define _MIBGROUP_IF_FIELDS_H

#ifdef freebsd4		/* XXX Use the same ifdefs as in interfaces.c */
#define USE_SYSCTL_IFLIST	1
#endif

	/*
	 * Definitions for 'USE_SYSCTL_IFLIST'
	 */

#ifdef						 USE_SYSCTL_IFLIST
struct small_ifaddr
{
  struct in_addr	sifa_addr;
  struct in_addr	sifa_netmask;
  struct in_addr	sifa_broadcast;
};
#define IFENTRY_TYPE	struct if_msghdr
#define IFADDR_TYPE	struct small_ifaddr

#define IFENTRY_FIELD_TYPE	ifm_data.ifi_type
#define IFENTRY_FIELD_MTU	ifm_data.ifi_mtu
#define IFENTRY_FIELD_SPEED	ifm_data.ifi_baudrate
#undef  IFENTRY_FIELD_PHYSADDR
#undef  IFENTRY_FIELD_ADMIN
#undef  IFENTRY_FIELD_OPER
#undef  IFENTRY_FIELD_LASTCH
#define IFENTRY_FIELD_INOCTETS	ifm_data.ifi_ibytes
#define IFENTRY_FIELD_INPKTS	ifm_data.ifi_ipackets
#define IFENTRY_FIELD_INMCASTS	ifm_data.ifi_imcasts
#define IFENTRY_FIELD_INDISCARDS ifm_data.ifi_iqdrops
#define IFENTRY_FIELD_INERRORS	ifm_data.ifi_ierrors
#define IFENTRY_FIELD_UNKNOWN	ifm_data.ifi_noproto
#define IFENTRY_FIELD_OUTOCTETS	ifm_data.ifi_obytes
#define IFENTRY_FIELD_OUTPKTS	ifm_data.ifi_opackets
#define IFENTRY_FIELD_OUTMCASTS	ifm_data.ifi_omcasts
#ifndef freebsd4
#define IFENTRY_FIELD_OUTDISCARDS ifm_data.ifi_oqdrops
#endif
#define IFENTRY_FIELD_OUTERRORS	ifm_data.ifi_oerrors
#undef  IFENTRY_FIELD_QLEN
#undef  IFENTRY_FIELD_OID

#define IPADDR_ADDRESS_FIELD	sifa_addr
#define IPADDR_BCAST_FIELD	sifa_broadcast
#define IPADDR_NETMASK_FIELD	sifa_netmask

#undef	IFENTRY_CALCULATE_PHYSADDR
#define	IFENTRY_CALCULATE_STATUS	1
#define IFENTRY_FIELD_FLAGS		ifm_flags
#undef	IFENTRY_CALCULATE_LASTCH
#define	IFENTRY_FIX_UNICAST		1
#endif



	/*
	 * Definitions for 'HAVE_NET_IF_MIB_H'
	 */

#if !defined(USE_SYSCTL_IFLIST) && defined(HAVE_NET_IF_MIB_H)
#define IFENTRY_TYPE	struct if_mibdata
#define IFADDR_TYPE	struct in_ifaddr

#define IFENTRY_FIELD_TYPE	ifm_data.ifi_type
#define IFENTRY_FIELD_MTU	ifm_data.ifi_mtu
#define IFENTRY_FIELD_SPEED	ifm_data.ifi_baudrate
#undef  IFENTRY_FIELD_PHYSADDR
#undef  IFENTRY_FIELD_ADMIN
#undef  IFENTRY_FIELD_OPER
#define IFENTRY_FIELD_LASTCH	ifm_data.ifi_lastchange
#define IFENTRY_FIELD_INOCTETS	ifm_data.ifi_ibytes
#define IFENTRY_FIELD_INPKTS	ifm_data.ifi_ipackets
#define IFENTRY_FIELD_INMCASTS	ifm_data.ifi_imcasts
#define IFENTRY_FIELD_INDISCARDS ifm_data.ifi_iqdrops
#define IFENTRY_FIELD_INERRORS	ifm_data.ifi_ierrors
#define IFENTRY_FIELD_UNKNOWN	ifm_data.ifi_noproto
#define IFENTRY_FIELD_OUTOCTETS	ifm_data.ifi_obytes
#define IFENTRY_FIELD_OUTPKTS	ifm_data.ifi_opackets
#define IFENTRY_FIELD_OUTMCASTS	ifm_data.ifi_omcasts
#define IFENTRY_FIELD_OUTDISCARDS ifm_snd_drops
#define IFENTRY_FIELD_OUTERRORS	ifm_data.ifi_oerrors
#define IFENTRY_FIELD_QLEN	ifm_snd_len
#undef  IFENTRY_FIELD_OID

#define IPADDR_ADDRESS_FIELD	ia_addr
#define IPADDR_BCAST_FIELD	ia_broadaddr
#define IPADDR_NETMASK_FIELD	ia_subnetmask

#define	IFENTRY_CALCULATE_PHYSADDR	1
#define	IFENTRY_CALCULATE_STATUS	1
#define IFENTRY_FIELD_FLAGS		ifm_flags
#define	IFENTRY_CALCULATE_LASTCH	1
#define	IFENTRY_FIX_UNICAST		1
#endif



	/*
	 * Definitions for 'solaris2'
	 */

#ifdef						 solaris2
#define IFENTRY_TYPE	mib2_ifEntry_t
#define IFADDR_TYPE	mib2_ipAddrEntry_t

#define IFENTRY_FIELD_TYPE	ifType
#define IFENTRY_FIELD_MTU	ifMtu
#define IFENTRY_FIELD_SPEED	ifSpeed
#define IFENTRY_FIELD_PHYSADDR	ifPhysAddress
#define IFENTRY_FIELD_ADMIN	ifAdminStatus
#define IFENTRY_FIELD_OPER	ifOperStatus
#define IFENTRY_FIELD_LASTCH	ifLastChange
#define IFENTRY_FIELD_INOCTETS	ifInOctets
#define IFENTRY_FIELD_INPKTS	ifInUcastPkts
#define IFENTRY_FIELD_INMCASTS	ifInNUcastPkts
#define IFENTRY_FIELD_INDISCARDS ifInDiscards
#define IFENTRY_FIELD_INERRORS	ifInErrors
#define IFENTRY_FIELD_UNKNOWN	ifInUnknownProtos
#define IFENTRY_FIELD_OUTOCTETS	ifOutOctets
#define IFENTRY_FIELD_OUTPKTS	ifOutUcastPkts
#define IFENTRY_FIELD_OUTMCASTS	ifOutNUcastPkts
#define IFENTRY_FIELD_OUTDISCARDS ifOutDiscards
#define IFENTRY_FIELD_OUTERRORS	ifOutErrors
#define IFENTRY_FIELD_QLEN	ifOutQLen
#undef  IFENTRY_FIELD_OID

#define IPADDR_ADDRESS_FIELD	ia_addr
#define IPADDR_BCAST_FIELD	ia_broadaddr
#define IPADDR_NETMASK_FIELD	ia_subnetmask

#undef	IFENTRY_CALCULATE_PHYSADDR
#define IFENTRY_STRING_SIZE(x)	(x.olength)
#define IFENTRY_STRING_VALUE(x)	(x.obytes)
#undef	IFENTRY_CALCULATE_STATUS
#undef	IFENTRY_CALCULATE_LASTCH
#undef	IFENTRY_FIX_UNICAST
#endif


	/*
	 * Definitions for 'hpux'
	 */

#ifdef						 hpux
#define IFENTRY_TYPE	mib_ifEntry
#define IFADDR_TYPE	mib_ipAdEnt

#define IFENTRY_FIELD_TYPE	ifType
#define IFENTRY_FIELD_MTU	ifMtu
#define IFENTRY_FIELD_SPEED	ifSpeed
#define IFENTRY_FIELD_PHYSADDR	ifPhysAddress
#define IFENTRY_FIELD_ADMIN	ifAdmin
#define IFENTRY_FIELD_OPER	ifOper
#define IFENTRY_FIELD_LASTCH	ifLastChange
#define IFENTRY_FIELD_INOCTETS	ifInOctets
#define IFENTRY_FIELD_INPKTS	ifInUcastPkts
#define IFENTRY_FIELD_INMCASTS	ifInNUcastPkts
#define IFENTRY_FIELD_INDISCARDS ifInDiscards
#define IFENTRY_FIELD_INERRORS	ifInErrors
#define IFENTRY_FIELD_UNKNOWN	ifInUnknownProtos
#define IFENTRY_FIELD_OUTOCTETS	ifOutOctets
#define IFENTRY_FIELD_OUTPKTS	ifOutUcastPkts
#define IFENTRY_FIELD_OUTMCASTS	ifOutNUcastPkts
#define IFENTRY_FIELD_OUTDISCARDS ifOutDiscards
#define IFENTRY_FIELD_OUTERRORS	ifOutErrors
#define IFENTRY_FIELD_QLEN	ifOutQlen
#undef  IFENTRY_FIELD_OID

#undef	IFENTRY_CALCULATE_PHYSADDR
	/*
	 * XXX - this is currently only used for the determining the size
	 *  of the PhysAddr field, which ought to be six bytes, but is
	 *  actually eight (with two characters unused)
	 *
	 * If we start using this macro more widely, we'll need to
	 *  fudge this more cleanly.
	 */
#define IFENTRY_STRING_SIZE(x)	(6)
#define IFENTRY_STRING_VALUE(x)	(x)
#undef	IFENTRY_CALCULATE_STATUS
#undef	IFENTRY_CALCULATE_LASTCH
#undef	IFENTRY_FIX_UNICAST

#define IPADDR_ADDRESS_FIELD	Addr
#define IPADDR_BCAST_FIELD	NetMask
#define IPADDR_NETMASK_FIELD	BcastAddr

#undef  SOCKADDR
#define SOCKADDR(x)		(x)
#endif


	/*
	 * Definitions for 'linux'
	 */

#ifdef linux
/*
 * this struct ifnet is cloned from the generic type and somewhat modified.
 * it will not work for other un*x'es...
 */

struct ifnet {
	char	*if_name;		/* name, e.g. ``en'' or ``lo'' */
	char	*if_unit;		/* sub-unit for lower level driver */
	short	if_mtu;			/* maximum transmission unit */
	short	if_flags;		/* up/down, broadcast, etc. */
	int	if_metric;		/* routing metric (external only) */
	char    if_hwaddr [6];		/* ethernet address */
	int	if_type;		/* interface type: 1=generic,
					   28=slip, ether=6, loopback=24 */
	int	if_speed;		/* interface speed: in bits/sec */

	struct	ifqueue {
		int	ifq_len;
		int	ifq_drops;
	} if_snd;			/* output queue */
	u_long	if_ibytes;		/* octets received on interface */
	u_long	if_ipackets;		/* packets received on interface */
	u_long	if_ierrors;		/* input errors on interface */
	u_long	if_obytes;		/* octets sent on interface */
	u_long	if_opackets;		/* packets sent on interface */
	u_long	if_oerrors;		/* output errors on interface */
	u_long	if_collisions;		/* collisions on csma interfaces */
/* end statistics */
	struct	ifnet *if_next;
};

struct in_ifaddr {

	struct sockaddr ia_addr;	/* interface's address */
	struct sockaddr ia_broadaddr;	/* broadcast address */
	struct sockaddr ia_subnetmask; 	/* interface's mask */

};

#define IFENTRY_TYPE	struct ifnet
#define IFADDR_TYPE	struct in_ifaddr

#define IFENTRY_FIELD_TYPE	if_type
#ifdef SIOCGIFMTU
#define IFENTRY_FIELD_MTU	if_mtu
#endif
#define IFENTRY_FIELD_SPEED	if_speed
#define IFENTRY_FIELD_PHYSADDR	if_hwaddr
#undef  IFENTRY_FIELD_ADMIN
#undef  IFENTRY_FIELD_OPER
#undef  IFENTRY_FIELD_LASTCH
#define IFENTRY_FIELD_INOCTETS	if_ibytes
#define IFENTRY_FIELD_INPKTS	if_ipackets
#undef  IFENTRY_FIELD_INMCASTS
#undef  IFENTRY_FIELD_INDISCARDS
#define IFENTRY_FIELD_INERRORS	if_ierrors
#undef  IFENTRY_FIELD_UNKNOWN
#define IFENTRY_FIELD_OUTOCTETS	if_obytes
#define IFENTRY_FIELD_OUTPKTS	if_opackets
#undef  IFENTRY_FIELD_OUTMCASTS
#define IFENTRY_FIELD_OUTDISCARDS if_snd.ifq_drops
#define IFENTRY_FIELD_OUTERRORS	if_oerrors
#define IFENTRY_FIELD_QLEN	if_snd.ifq_len
#undef  IFENTRY_FIELD_OID

#define IPADDR_ADDRESS_FIELD	ia_addr
#define IPADDR_BCAST_FIELD	ia_broadaddr
#define IPADDR_NETMASK_FIELD	ia_subnetmask

#undef	IFENTRY_CALCULATE_PHYSADDR
#define IFENTRY_STRING_SIZE(x)	(sizeof(x))
#define IFENTRY_STRING_VALUE(x)	(x)
#define	IFENTRY_CALCULATE_STATUS	1
#define IFENTRY_FIELD_FLAGS		if_flags
#undef	IFENTRY_CALCULATE_LASTCH
#undef	IFENTRY_FIX_UNICAST
#endif



	/*
	 * Definitions for other 'traditional' systems
	 */

#ifndef IFENTRY_TYPE
#define IFENTRY_TYPE	struct ifnet
#define IFADDR_TYPE	struct in_ifaddr

#ifdef STRUCT_IFNET_HAS_IF_TYPE
#define IFENTRY_FIELD_TYPE	if_type
#endif
#define IFENTRY_FIELD_MTU	if_mtu
#undef  IFENTRY_FIELD_SPEED
#ifdef STRUCT_IFNET_HAS_IF_BAUDRATE
#define IFENTRY_FIELD_SPEED	if_baudrate
#else
#ifdef STRUCT_IFNET_HAS_IF_SPEED
#define IFENTRY_FIELD_SPEED	if_speed
#endif
#endif

#undef  IFENTRY_FIELD_PHYSADDR
#undef  IFENTRY_FIELD_ADMIN
#undef  IFENTRY_FIELD_OPER
#if defined(STRUCT_IFNET_HAS_IF_LASTCHANGE_TV_SEC) && !(defined(freebsd2) && __FreeBSD_version < 199607)
#define IFENTRY_FIELD_LASTCH	if_lastchange
#endif

#ifdef STRUCT_IFNET_HAS_IF_IBYTES
#define IFENTRY_FIELD_INOCTETS	if_ibytes
#endif
#define IFENTRY_FIELD_INPKTS	if_ipackets
#ifdef STRUCT_IFNET_HAS_IF_IMCASTS
#define IFENTRY_FIELD_INMCASTS	if_imcasts
#endif
#ifdef STRUCT_IFNET_HAS_IF_IQDROPS
#define IFENTRY_FIELD_INDISCARDS if_iqdrops
#endif
#define IFENTRY_FIELD_INERRORS	if_ierrors
#ifdef STRUCT_IFNET_HAS_IF_NOPROTO
#define IFENTRY_FIELD_UNKNOWN	if_noproto
#endif

#ifdef STRUCT_IFNET_HAS_IF_OBYTES
#define IFENTRY_FIELD_OUTOCTETS	if_obytes
#endif
#define IFENTRY_FIELD_OUTPKTS	if_opackets
#ifdef STRUCT_IFNET_HAS_IF_OMCASTS
#define IFENTRY_FIELD_OUTMCASTS	if_omcasts
#endif
#define IFENTRY_FIELD_OUTDISCARDS if_snd.ifq_drops
#define IFENTRY_FIELD_OUTERRORS	if_oerrors
#define IFENTRY_FIELD_QLEN	if_snd.ifq_len
#undef  IFENTRY_FIELD_OID

#define IPADDR_ADDRESS_FIELD	ia_addr
#define IPADDR_BCAST_FIELD	ia_broadaddr
#define IPADDR_NETMASK_FIELD	ia_subnetmask

#define	IFENTRY_CALCULATE_PHYSADDR	1
#define	IFENTRY_CALCULATE_STATUS	1
#define IFENTRY_FIELD_FLAGS		if_flags
#ifdef IFENTRY_FIELD_LASTCH
#define	IFENTRY_CALCULATE_LASTCH	1
#endif
#ifdef IFENTRY_FIELD_INMCASTS
#define	IFENTRY_FIX_UNICAST		1
#endif

#endif



struct if_entry {
    int			 index;
    char		*name;
    IFENTRY_TYPE	*ifstat;
    IFADDR_TYPE		*ifaddr;
};

#endif /* _MIBGROUP_IF_FIELDS_H */
