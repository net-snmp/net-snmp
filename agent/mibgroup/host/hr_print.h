/*
 *  Host Resources MIB - printer device group interface - hr_print.h
 *
 */
#ifndef _MIBGROUP_HRPRINT_H
#define _MIBGROUP_HRPRINT_H

extern void	init_hr_print (void);
extern FindVarMethod var_hrprint;


#define	HRPRINT_STATUS		1
#define	HRPRINT_ERROR		2

#ifdef IN_SNMP_VARS_C

struct variable4 hrprint_variables[] = {
    { HRPRINT_STATUS,    ASN_INTEGER, RONLY, var_hrprint, 2, {1,1}},
    { HRPRINT_ERROR,   ASN_OCTET_STR, RONLY, var_hrprint, 2, {1,2}}
};
config_load_mib( MIB.25.3.5, 9, hrprint_variables)

#endif
#endif /* _MIBGROUP_HRPRINT_H */
