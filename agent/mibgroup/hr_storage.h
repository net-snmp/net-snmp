/*
 *  Host Resources MIB - storage group interface - hr_system.h
 *
 */
#ifndef _MIBGROUP_HRSTORAGE_H
#define _MIBGROUP_HRSTORAGE_H

extern void	init_hrstore __P((void));
extern u_char	*var_hrstore __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#define	HRSTORE_MEMSIZE		1

#define	HRSTORE_INDEX		2
#define	HRSTORE_TYPE		3
#define	HRSTORE_DESCR		4
#define	HRSTORE_UNITS		5
#define	HRSTORE_SIZE		6
#define	HRSTORE_USED		7
#define	HRSTORE_FAILS		8

#define	HRS_TYPE_FS_MAX		100	/* Maximum # of filesystems supported */

#define	HRS_TYPE_MEM		101	/* incrementally from FS_MAX */
#define	HRS_TYPE_SWAP		102
#define	HRS_TYPE_MBUF		103
					/* etc, etc, etc */
#define	HRS_TYPE_MAX		104	/* one greater than largest type */

#ifdef IN_SNMP_VARS_C

struct variable4 hrstore_variables[] = {
    { HRSTORE_MEMSIZE,   ASN_INTEGER, RONLY, var_hrstore, 1, {2}},
    { HRSTORE_INDEX,     ASN_INTEGER, RONLY, var_hrstore, 3, {3,1,1}},
    { HRSTORE_TYPE,    ASN_OBJECT_ID, RONLY, var_hrstore, 3, {3,1,2}},
    { HRSTORE_DESCR,   ASN_OCTET_STR, RONLY, var_hrstore, 3, {3,1,3}},
    { HRSTORE_UNITS,     ASN_INTEGER, RONLY, var_hrstore, 3, {3,1,4}},
    { HRSTORE_SIZE,      ASN_INTEGER, RONLY, var_hrstore, 3, {3,1,5}},
    { HRSTORE_USED,      ASN_INTEGER, RONLY, var_hrstore, 3, {3,1,6}},
    { HRSTORE_FAILS,     ASN_COUNTER, RONLY, var_hrstore, 3, {3,1,7}}
};
config_load_mib( MIB.25.2, 8, hrstore_variables)

#endif
#endif /* _MIBGROUP_HRSTORAGE_H */
