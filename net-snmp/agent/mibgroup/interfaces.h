/*
 *  Interfaces MIB group interface - interfaces.h
 *
 */
#ifndef _MIBGROUP_INTERFACES_H
#define _MIBGROUP_INTERFACES_H

config_require(util_funcs)
config_arch_require(solaris2, kernel_sunos5)

struct in_ifaddr;
struct ifnet;

int Interface_Index_By_Name __P((char *, int));
void Interface_Scan_Init __P((void));
#if defined(sunV3) || defined(linux)
int Interface_Scan_Next __P((short *, char *, struct ifnet *));
#else
int Interface_Scan_Next __P((short *, char *, struct ifnet *, struct in_ifaddr *));
#endif

extern void	init_interfaces __P((void));
extern u_char	*var_interfaces __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char,int, u_char *, oid *, int)) ));
extern u_char	*var_ifEntry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#define IFNUMBER        0
#define IFINDEX         1
#define IFDESCR         2
#define IFTYPE          3
#define IFMTU           4
#define IFSPEED         5
#define IFPHYSADDRESS   6
#define IFADMINSTATUS   7
#define IFOPERSTATUS    8
#define IFLASTCHANGE    9
#define IFINOCTETS      10
#define IFINUCASTPKTS   11
#define IFINNUCASTPKTS  12
#define IFINDISCARDS    13
#define IFINERRORS      14
#define IFINUNKNOWNPROTOS 15
#define IFOUTOCTETS     16
#define IFOUTUCASTPKTS  17
#define IFOUTNUCASTPKTS 18
#define IFOUTDISCARDS   19
#define IFOUTERRORS     20
#define IFOUTQLEN       21
#define IFSPECIFIC      22

#ifdef IN_SNMP_VARS_C
struct variable4 interfaces_variables[] = {
    {IFNUMBER, INTEGER, RONLY, var_interfaces, 1, {1}},
    {IFINDEX, INTEGER, RONLY, var_ifEntry, 3, {2, 1, 1}},
    {IFDESCR, STRING, RONLY, var_ifEntry, 3, {2, 1, 2}},
    {IFTYPE, INTEGER, RONLY, var_ifEntry, 3, {2, 1, 3}},
    {IFMTU, INTEGER, RONLY, var_ifEntry, 3, {2, 1, 4}},
    {IFSPEED, GAUGE, RONLY, var_ifEntry, 3, {2, 1, 5}},
    {IFPHYSADDRESS, STRING, RONLY, var_ifEntry, 3, {2, 1, 6}},
    {IFADMINSTATUS, INTEGER, RWRITE, var_ifEntry, 3, {2, 1, 7}},
    {IFOPERSTATUS, INTEGER, RONLY, var_ifEntry, 3, {2, 1, 8}},
    {IFLASTCHANGE, TIMETICKS, RONLY, var_ifEntry, 3, {2, 1, 9}},
    {IFINOCTETS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 10}},
    {IFINUCASTPKTS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 11}},
    {IFINNUCASTPKTS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 12}},
    {IFINDISCARDS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 13}},
    {IFINERRORS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 14}},
    {IFINUNKNOWNPROTOS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 15}},
    {IFOUTOCTETS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 16}},
    {IFOUTUCASTPKTS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 17}},
    {IFOUTNUCASTPKTS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 18}},
    {IFOUTDISCARDS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 19}},
    {IFOUTERRORS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 20}},
    {IFOUTQLEN, GAUGE, RONLY, var_ifEntry, 3, {2, 1, 21}},
    {IFSPECIFIC, OBJID, RONLY, var_ifEntry, 3, {2, 1, 22}}
};

config_load_mib(MIB.2, 7, interfaces_variables)
#endif

#ifdef linux
/*
 * this struct ifnet is cloned from the generic type and somewhat modified.
 * it will not work for other un*x'es...
 */

struct ifnet {
	char	*if_name;		/* name, e.g. ``en'' or ``lo'' */
	short	if_unit;		/* sub-unit for lower level driver */
	short	if_mtu;			/* maximum transmission unit */
	short	if_flags;		/* up/down, broadcast, etc. */
	int	if_metric;		/* routing metric (external only) */
	char    if_hwaddr [6];		/* ethernet address */
	int	if_type;		/* interface type: 1=generic,
					   28=slip, ether=6, loopback=24 */
	int	if_speed;		/* interface speed: in bits/sec */

	struct sockaddr if_addr;	/* interface's address */
	struct sockaddr ifu_broadaddr;	/* broadcast address */
	struct sockaddr ia_subnetmask; 	/* interface's mask */

	struct	ifqueue {
		int	ifq_len;
		int	ifq_drops;
	} if_snd;			/* output queue */
	int	if_ipackets;		/* packets received on interface */
	int	if_ierrors;		/* input errors on interface */
	int	if_opackets;		/* packets sent on interface */
	int	if_oerrors;		/* output errors on interface */
	int	if_collisions;		/* collisions on csma interfaces */
/* end statistics */
	struct	ifnet *if_next;
};
#endif
#endif /* _MIBGROUP_INTERFACES_H */
