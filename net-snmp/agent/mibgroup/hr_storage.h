/*
 *  Host Resources MIB - storage group interface - hr_system.h
 *
 */
#ifndef _MIBGROUP_HRSTORAGE_H
#define _MIBGROUP_HRSTORAGE_H

extern void	init_hrstore();
extern u_char	*var_hrstore();


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
    { HRSTORE_MEMSIZE,   INTEGER, RONLY, var_hrstore, 1, {2}},
    { HRSTORE_INDEX,     INTEGER, RONLY, var_hrstore, 3, {3,1,1}},
    { HRSTORE_TYPE,        OBJID, RONLY, var_hrstore, 3, {3,1,2}},
    { HRSTORE_DESCR,      STRING, RONLY, var_hrstore, 3, {3,1,3}},
    { HRSTORE_UNITS,     INTEGER, RONLY, var_hrstore, 3, {3,1,4}},
    { HRSTORE_SIZE,      INTEGER, RONLY, var_hrstore, 3, {3,1,5}},
    { HRSTORE_USED,      INTEGER, RONLY, var_hrstore, 3, {3,1,6}},
    { HRSTORE_FAILS,     COUNTER, RONLY, var_hrstore, 3, {3,1,7}}
};
config_load_mib( MIB.25.2, 8, hrstore_variables)

#endif
#endif /* _MIBGROUP_HRSTORAGE_H */
