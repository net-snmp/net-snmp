/*
 *  Host Resources MIB - processor device group interface - hr_proc.h
 *
 */
#ifndef _MIBGROUP_HRPROC_H
#define _MIBGROUP_HRPROC_H

extern void	init_hr_proc();
extern u_char	*var_hrproc();


#define	HRPROC_ID		1
#define	HRPROC_LOAD		2

#ifdef IN_SNMP_VARS_C

struct variable4 hrproc_variables[] = {
    { HRPROC_ID,          OBJID, RONLY, var_hrproc, 2, {1,1}},
    { HRPROC_LOAD,      INTEGER, RONLY, var_hrproc, 2, {1,2}}
};
config_load_mib( MIB.25.3.3, 9, hrproc_variables)

#endif
#endif /* _MIBGROUP_HRPROC_H */
