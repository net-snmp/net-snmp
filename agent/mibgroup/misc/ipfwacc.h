/*
 *  MIB group interface - ipfwacc.h
 *  IP accounting through firewall rules
 */
#ifndef _MIBGROUP_IPFWACC_H
#define _MIBGROUP_IPFWACC_H

/* we use checkmib from the util_funcs module */

config_require(util_funcs)

/* add the mib we implement to the list of default mibs to load */
config_add_mib(IPFWACC-MIB)

/* Magic number definitions: */


#define	IPFWACCINDEX		1
#define	IPFWACCSRCADDR		2
#define	IPFWACCSRCNM		3
#define	IPFWACCDSTADDR		4
#define	IPFWACCDSTNM		5
#define	IPFWACCVIANAME		6
#define	IPFWACCVIAADDR		7
#define	IPFWACCPROTO		8
#define	IPFWACCBIDIR		9
#define	IPFWACCDIR		10
#define	IPFWACCBYTES		11
#define	IPFWACCPACKETS		12
#define	IPFWACCNSRCPRTS		13
#define	IPFWACCNDSTPRTS		14
#define	IPFWACCSRCISRNG		15
#define	IPFWACCDSTISRNG		16
#define	IPFWACCPORT1		17
#define	IPFWACCPORT2		18
#define	IPFWACCPORT3		19
#define	IPFWACCPORT4		20
#define	IPFWACCPORT5		21
#define	IPFWACCPORT6		22
#define	IPFWACCPORT7		23
#define	IPFWACCPORT8		24
#define	IPFWACCPORT9		25
#define	IPFWACCPORT10		26

/* function definitions */

  /* extern void	init_ipfwacc __P(void);*/

extern unsigned char	*var_ipfwacc __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, unsigned char *, unsigned char, int, unsigned char *, oid *, int)) ));

/* Only load this structure when this .h file is called in the snmp_vars.c 
   file in tha agent subdirectory of the source tree */

#ifdef IN_SNMP_VARS_C

/* this variable defines function callbacks and type return information 
   for the ipfwaccounting mib */

struct variable2 ipfwacc_variables[] = {
    { IPFWACCINDEX,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCINDEX}},
    { IPFWACCSRCADDR,  ASN_IPADDRESS, RONLY, var_ipfwacc, 1, {IPFWACCSRCADDR}},
    { IPFWACCSRCNM,  ASN_IPADDRESS, RONLY, var_ipfwacc, 1, {IPFWACCSRCNM}},
    { IPFWACCDSTADDR,  ASN_IPADDRESS, RONLY, var_ipfwacc, 1, {IPFWACCDSTADDR}},
    { IPFWACCDSTNM,  ASN_IPADDRESS, RONLY, var_ipfwacc, 1, {IPFWACCDSTNM}},
    { IPFWACCVIANAME,  ASN_OCTET_STR, RONLY, var_ipfwacc, 1, {IPFWACCVIANAME}},
    { IPFWACCVIAADDR,  ASN_IPADDRESS, RONLY, var_ipfwacc, 1, {IPFWACCVIAADDR}},
    { IPFWACCPROTO,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPROTO}},
    { IPFWACCBIDIR,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCBIDIR}},
    { IPFWACCDIR,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCDIR}},
    { IPFWACCBYTES,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCBYTES}},
    { IPFWACCPACKETS,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPACKETS}},
    { IPFWACCNSRCPRTS,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCNSRCPRTS}},
    { IPFWACCNDSTPRTS,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCNDSTPRTS}},
    { IPFWACCSRCISRNG,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCSRCISRNG}},
    { IPFWACCDSTISRNG,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCDSTISRNG}},
    { IPFWACCPORT1,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT1}},
    { IPFWACCPORT2,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT2}},
    { IPFWACCPORT3,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT3}},
    { IPFWACCPORT4,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT4}},
    { IPFWACCPORT5,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT5}},
    { IPFWACCPORT6,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT6}},
    { IPFWACCPORT7,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT7}},
    { IPFWACCPORT8,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT8}},
    { IPFWACCPORT9,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT9}},
    { IPFWACCPORT10,  ASN_INTEGER, RONLY, var_ipfwacc, 1, {IPFWACCPORT10}}
};

/* now load this mib into the agents mib table */

config_load_mib(1.3.6.1.4.1.2021.13, 8 , ipfwacc_variables)

#endif /* IN_SNMP_VARS_C */
#endif /* _MIBGROUP_IPFWACC_H */

