/*
 *  Template MIB group interface - ip.h
 *
 */

#ifndef _MIBGROUP_IP_H
#define _MIBGROUP_IP_H


config_require(mibJJ/interfaces mibJJ/ipAddr mibJJ/ipMedia mibJJ/ipRoute)
config_arch_require(solaris2, kernel_sunos5)
config_arch_require(linux, mibJJ/kernel_linux)
config_arch_require(hpux, mibJJ/kernel_hpux)

extern void	init_ip (void);
extern FindVarMethod var_ip;


#define IPFORWARDING	0
#define IPDEFAULTTTL	1
#define IPINRECEIVES	2
#define IPINHDRERRORS	3
#define IPINADDRERRORS	4
#define IPFORWDATAGRAMS 5
#define IPINUNKNOWNPROTOS 6
#define IPINDISCARDS	7
#define IPINDELIVERS	8
#define IPOUTREQUESTS	9
#define IPOUTDISCARDS	10
#define IPOUTNOROUTES	11
#define IPREASMTIMEOUT	12
#define IPREASMREQDS	13
#define IPREASMOKS	14
#define IPREASMFAILS	15
#define IPFRAGOKS	16
#define IPFRAGFAILS	17
#define IPFRAGCREATES	18
#define IPROUTEDISCARDS	19


#endif /* _MIBGROUP_IP_H */
