/*
 *  Template MIB group interface - udp.h
 *
 */
#ifndef _MIBGROUP_UDP_H
#define _MIBGROUP_UDP_H

config_arch_require(solaris2, kernel_sunos5)

extern void	init_udp __P((void));
extern u_char	*var_udp __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern u_char	*var_udpEntry __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));


#define UDPINDATAGRAMS	    0
#define UDPNOPORTS	    1
#define UDPINERRORS	    2
#define UDPOUTDATAGRAMS     3
#define UDPLOCALADDRESS     4
#define UDPLOCALPORT	    5


#ifdef IN_SNMP_VARS_C

struct variable8 udp_variables[] = {
    {UDPINDATAGRAMS, COUNTER, RONLY, var_udp, 1, {1}},
    {UDPNOPORTS, COUNTER, RONLY, var_udp, 1, {2}},
    {UDPINERRORS, COUNTER, RONLY, var_udp, 1, {3}},
    {UDPOUTDATAGRAMS, COUNTER, RONLY, var_udp, 1, {4}},
    {UDPLOCALADDRESS, IPADDRESS, RONLY, var_udpEntry, 3, {5, 1, 1}},
    {UDPLOCALPORT, INTEGER, RONLY, var_udpEntry, 3, {5, 1, 2}}
};

config_load_mib(MIB.7, 7,udp_variables)
#endif

#endif /* _MIBGROUP_UDP_H */
