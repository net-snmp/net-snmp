/*
 *  Interfaces MIB group interface - interfaces.h
 *
 */
#ifndef _MIBGROUP_INTERFACES_H
#define _MIBGROUP_INTERFACES_H

struct in_ifaddr;
struct ifnet;

int Interface_Scan_Get_Count __P((void));
int Interface_Index_By_Name __P((char *, int));
void Interface_Scan_Init __P((void));
#ifdef sunV3
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

#endif /* _MIBGROUP_INTERFACES_H */
