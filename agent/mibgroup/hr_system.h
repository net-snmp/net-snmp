/*
 *  Host Resources MIB - system group interface - hr_system.h
 *
 */
#ifndef _MIBGROUP_HRSYSTEM_H
#define _MIBGROUP_HRSYSTEM_H

extern void	init_hr_system();
extern u_char	*var_hrsys();


#define	HRSYS_UPTIME		1
#define	HRSYS_DATE		2
#define	HRSYS_LOAD_DEV		3
#define	HRSYS_LOAD_PARAM	4
#define	HRSYS_USERS		5
#define	HRSYS_PROCS		6
#define	HRSYS_MAXPROCS		7

#ifdef IN_SNMP_VARS_C

struct variable2 hrsystem_variables[] = {
    { HRSYS_UPTIME,  TIMETICKS, RONLY, var_hrsys, 1, {1}},
    { HRSYS_DATE,       STRING, RONLY, var_hrsys, 1, {2}},
    { HRSYS_LOAD_DEV,  INTEGER, RONLY, var_hrsys, 1, {3}},
    { HRSYS_LOAD_PARAM, STRING, RONLY, var_hrsys, 1, {4}},
    { HRSYS_USERS,       GAUGE, RONLY, var_hrsys, 1, {5}},
    { HRSYS_PROCS,       GAUGE, RONLY, var_hrsys, 1, {6}},
    { HRSYS_MAXPROCS,  INTEGER, RONLY, var_hrsys, 1, {7}}
};
config_load_mib( MIB.25.1, 8, hrsystem_variables)

#endif
#endif /* _MIBGROUP_HRSYSTEM_H */
