/*
 *  Host Resources MIB - Running Software group interface - hr_swrun.h
 *	(also includes Running Software Performance group )
 *
 */
#ifndef _MIBGROUP_HRSWRUN_H
#define _MIBGROUP_HRSWRUN_H

extern void	init_hr_swrun (void);
extern u_char	*var_hrswrun  (struct variable *, oid *, int *, int, int *,
			       int (**write) (int, u_char *, u_char, int,
					      u_char *, oid *, int));



#define	HRSWRUN_OSINDEX		1

#define	HRSWRUN_INDEX		2
#define	HRSWRUN_NAME		3
#define	HRSWRUN_ID		4
#define	HRSWRUN_PATH		5
#define	HRSWRUN_PARAMS		6
#define	HRSWRUN_TYPE		7
#define	HRSWRUN_STATUS		8

#define	HRSWRUNPERF_CPU		9
#define	HRSWRUNPERF_MEM		10


#ifdef IN_SNMP_VARS_C

struct variable4 hrswrun_variables[] = {
    { HRSWRUN_OSINDEX,   ASN_INTEGER, RONLY, var_hrswrun, 1, {1}},
    { HRSWRUN_INDEX,     ASN_INTEGER, RONLY, var_hrswrun, 3, {2,1,1}},
    { HRSWRUN_NAME,    ASN_OCTET_STR, RONLY, var_hrswrun, 3, {2,1,2}},
    { HRSWRUN_ID,      ASN_OBJECT_ID, RONLY, var_hrswrun, 3, {2,1,3}},
    { HRSWRUN_PATH,    ASN_OCTET_STR, RONLY, var_hrswrun, 3, {2,1,4}},
    { HRSWRUN_PARAMS,  ASN_OCTET_STR, RONLY, var_hrswrun, 3, {2,1,5}},
    { HRSWRUN_TYPE,      ASN_INTEGER, RONLY, var_hrswrun, 3, {2,1,6}},
    { HRSWRUN_STATUS,    ASN_INTEGER, RONLY, var_hrswrun, 3, {2,1,7}}
};

struct variable4 hrswrunperf_variables[] = {
    { HRSWRUNPERF_CPU,   ASN_INTEGER, RONLY, var_hrswrun, 3, {1,1,1}},
    { HRSWRUNPERF_MEM,   ASN_INTEGER, RONLY, var_hrswrun, 3, {1,1,2}}
};

config_load_mib( MIB.25.4, 8, hrswrun_variables)
config_load_mib( MIB.25.5, 8, hrswrunperf_variables)

#endif
#endif /* _MIBGROUP_HRSWRUN_H */
