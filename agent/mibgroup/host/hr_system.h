/*
 *  Host Resources MIB - system group interface - hr_system.h
 *
 */
#ifndef _MIBGROUP_HRSYSTEM_H
#define _MIBGROUP_HRSYSTEM_H

config_require(host/hr_utils )

extern void	init_hr_system (void);
extern u_char	*var_hrsys (struct variable *, oid *, int *, int, int *, int
			    (**write) (int, u_char *, u_char, int, u_char *,
				       oid *, int));


#define	HRSYS_UPTIME		1
#define	HRSYS_DATE		2
#define	HRSYS_LOAD_DEV		3
#define	HRSYS_LOAD_PARAM	4
#define	HRSYS_USERS		5
#define	HRSYS_PROCS		6
#define	HRSYS_MAXPROCS		7

#ifdef IN_SNMP_VARS_C

struct variable2 hrsystem_variables[] = {
    { HRSYS_UPTIME,     ASN_TIMETICKS, RONLY, var_hrsys, 1, {1}},
    { HRSYS_DATE,       ASN_OCTET_STR, RONLY, var_hrsys, 1, {2}},
    { HRSYS_LOAD_DEV,     ASN_INTEGER, RONLY, var_hrsys, 1, {3}},
    { HRSYS_LOAD_PARAM, ASN_OCTET_STR, RONLY, var_hrsys, 1, {4}},
    { HRSYS_USERS,          ASN_GAUGE, RONLY, var_hrsys, 1, {5}},
    { HRSYS_PROCS,          ASN_GAUGE, RONLY, var_hrsys, 1, {6}},
    { HRSYS_MAXPROCS,     ASN_INTEGER, RONLY, var_hrsys, 1, {7}}
};
config_load_mib( MIB.25.1, 8, hrsystem_variables)

#endif
#endif /* _MIBGROUP_HRSYSTEM_H */
