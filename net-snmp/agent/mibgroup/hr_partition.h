/*
 *  Host Resources MIB - partition device group interface - hr_partition.h
 *
 */
#ifndef _MIBGROUP_HRPART_H
#define _MIBGROUP_HRPART_H

extern void	init_hrpartition();
extern u_char	*var_hrpartition();


#define	HRPART_INDEX		1
#define	HRPART_LABEL		2
#define	HRPART_ID		3
#define	HRPART_SIZE		4
#define	HRPART_FSIDX		5

#ifdef IN_SNMP_VARS_C

struct variable4 hrpartition_variables[] = {
    { HRPART_INDEX,     INTEGER, RONLY, var_hrpartition, 2, {1,1}},
    { HRPART_LABEL,      STRING, RONLY, var_hrpartition, 2, {1,2}},
    { HRPART_ID,         STRING, RONLY, var_hrpartition, 2, {1,3}},
    { HRPART_SIZE,      INTEGER, RONLY, var_hrpartition, 2, {1,4}},
    { HRPART_FSIDX,     INTEGER, RONLY, var_hrpartition, 2, {1,5}}
};
config_load_mib( MIB.25.3.7, 9, hrpartition_variables)

#endif
#endif /* _MIBGROUP_HRPART_H */
