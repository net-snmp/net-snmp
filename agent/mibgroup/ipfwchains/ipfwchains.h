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

u_char *var_ipfwchains(struct variable *, oid *, int *, int, int *, WriteMethod **write);
u_char *var_ipfwrules(struct variable *, oid *, int *, int, int *, WriteMethod **write); 

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



#ifdef IN_SNMP_VARS_C

struct variable4 ipfwchains_variables[] = {
    { IPFWCCHAININDEX,		ASN_INTEGER, 	RONLY, var_ipfwchains, 3, {1, 1, 1}},
    { IPFWCCHAINLABEL,       	ASN_OCTET_STR, 	RONLY, var_ipfwchains, 3, {1, 1, 2}},
    { IPFWCPOLICY,          	ASN_OCTET_STR,  RONLY, var_ipfwchains, 3, {1, 1, 3}},
    { IPFWCREFCNT,          	ASN_INTEGER,  	RONLY, var_ipfwchains, 3, {1, 1, 4}},
    { IPFWCPKTS,          	ASN_OCTET_STR,  RONLY, var_ipfwchains, 3, {1, 1, 5}},
    { IPFWCBYTES,          	ASN_OCTET_STR,  RONLY, var_ipfwchains, 3, {1, 1, 6}},
    { IPFWRRULEINDEX,          	ASN_INTEGER,  	RONLY, var_ipfwrules,  3, {2, 1, 1}},
    { IPFWRCHAIN,             	ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 2}},
    { IPFWRPKTS,                ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 3}},
    { IPFWRBYTES,               ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 4}},
    { IPFWRTARGET,              ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 5}},
    { IPFWRPROT,               	ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 6}},
    { IPFWRSOURCE,              ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 7}},
    { IPFWRDESTINATION,    	ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 8}},
    { IPFWRPORTS,               ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 9}},
    { IPFWROPT,         	ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 10}},
    { IPFWRIFNAME,              ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 11}},
    { IPFWRTOSA,               	ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 12}},
    { IPFWRTOSX,               	ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 13}},
    { IPFWRMARK,              	ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 14}},
    { IPFWROUTSIZE,             ASN_OCTET_STR,  RONLY, var_ipfwrules,  3, {2, 1, 15}}
};

config_load_mib(1.3.6.1.4.1.2021.13.3, 9, ipfwchains_variables)
  /* arguments:
     .1.3.6.1.2.1.2021.13:  MIB oid to put the tables at.
     8:                     Length of the mib oid above.
     ipfwchains_variables:  The structure we just defined above */

#endif
#endif /* _MIBGROUP_IPFWCHAINS_H */
