/*
 *  Interfaces MIB group interface - interfaces.h
 *
 */
#ifndef _MIBGROUP_INTERFACES_H
#define _MIBGROUP_INTERFACES_H

config_require(util_funcs)
config_arch_require(solaris2, kernel_sunos5)

int Interface_Index_By_Name (char * );
/*
struct in_ifaddr;
struct ifnet;

void Interface_Scan_Init (void);
#ifdef sunV3
struct in_ifaddr { int dummy; };
#endif
int Interface_Scan_Next (short *, char *, struct ifnet *, struct in_ifaddr *);
 */

void	init_interfaces (void);
extern FindVarMethod var_interfaces;
extern FindVarMethod var_ifEntry;

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

#endif /* _MIBGROUP_INTERFACES_H */
