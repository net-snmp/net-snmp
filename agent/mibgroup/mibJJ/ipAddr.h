/*
 *  Template MIB group interface - ipAddr.h
 *
 */
#ifndef _MIBGROUP_IPADDR_H
#define _MIBGROUP_IPADDR_H

config_require(util_funcs)

#define IPADADDR	1
#define IPADIFINDEX	2
#define IPADNETMASK	3
#define IPADBCASTADDR	4
#define IPADREASMMAX	5

extern FindVarMethod var_ipAddrEntry;
void init_ipAddr( void );

#endif /* _MIBGROUP_IPADDR_H */
