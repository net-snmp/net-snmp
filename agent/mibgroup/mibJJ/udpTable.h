/*
 *  Template MIB group interface - udp.h
 *
 */
#ifndef _MIBGROUP_UDPTABLE_H
#define _MIBGROUP_UDPTABLE_H

config_require(mibJJ/udp util_funcs)
config_arch_require(solaris2, kernel_sunos5)

#define UDPLOCALADDRESS     4
#define UDPLOCALPORT	    5

extern void	init_udpTable(void);
extern FindVarMethod var_udpEntry;

#endif /* _MIBGROUP_UDPTABLE_H */
