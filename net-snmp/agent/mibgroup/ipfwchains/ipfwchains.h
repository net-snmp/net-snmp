/*
 *  IPFWCHAINS-MIB group interface - ipfwchains.h
 *
 *
 *
 *
 *
 *  Firewalling rules
 */
#ifndef _MIBGROUP_IPFWCHAINS_H
#define _MIBGROUP_IPFWCHAINS_H

config_add_mib(IPFWCHAINS-MIB)


config_require(util_funcs)
config_require(ipfwchains/libipfwc)

extern FindVarMethod var_ipfwchains;
extern FindVarMethod var_ipfwrules;
extern void    init_ipfwchains( void );

#define	IPFWCCHAININDEX		1
#define	IPFWCCHAINLABEL		2
#define	IPFWCPOLICY		3
#define IPFWCREFCNT		4
#define IPFWCPKTS		5
#define IPFWCBYTES		6

#define IPFWRRULEINDEX		1
#define IPFWRCHAIN		2
#define IPFWRPKTS		3
#define IPFWRBYTES		4
#define IPFWRTARGET		5
#define IPFWRPROT		6
#define IPFWRSOURCE		7
#define IPFWRDESTINATION	8
#define IPFWRPORTS		9
#define IPFWROPT		10
#define IPFWRIFNAME		11
#define IPFWRTOSA		12
#define IPFWRTOSX		13
#define IPFWRMARK		14
#define IPFWROUTSIZE		15



#endif /* _MIBGROUP_IPFWCHAINS_H */
