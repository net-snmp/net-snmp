/*
 *  Host Resources MIB - network device group interface - hr_network.h
 *
 */
#ifndef _MIBGROUP_HRNET_H
#define _MIBGROUP_HRNET_H

extern void	init_hr_network();
extern u_char	*var_hrnet();

config_require(interfaces);

#define	HRNET_IFINDEX		1

#ifdef IN_SNMP_VARS_C

struct variable4 hrnet_variables[] = {
    { HRNET_IFINDEX,   ASN_INTEGER, RONLY, var_hrnet, 2, {1,1}}
};
config_load_mib( MIB.25.3.4, 9, hrnet_variables)

#endif
#endif /* _MIBGROUP_HRNET_H */
