/*
 *  Host Resources MIB - disk device group interface - hr_disk.h
 *
 */
#ifndef _MIBGROUP_HRDISK_H
#define _MIBGROUP_HRDISK_H

extern void	init_hr_disk (void);
extern void	Init_HR_Disk (void);
extern int	Get_Next_HR_Disk (void);
extern u_char	*var_hrdisk  (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int));


#define	HRDISK_ACCESS		1
#define	HRDISK_MEDIA		2
#define	HRDISK_REMOVEABLE	3
#define	HRDISK_CAPACITY		4

#ifdef IN_SNMP_VARS_C

struct variable4 hrdisk_variables[] = {
    { HRDISK_ACCESS,    ASN_INTEGER, RONLY, var_hrdisk, 2, {1,1}},
    { HRDISK_MEDIA,     ASN_INTEGER, RONLY, var_hrdisk, 2, {1,2}},
    { HRDISK_REMOVEABLE,ASN_INTEGER, RONLY, var_hrdisk, 2, {1,3}},
    { HRDISK_CAPACITY,  ASN_INTEGER, RONLY, var_hrdisk, 2, {1,4}}
};
config_load_mib( MIB.25.3.6, 9, hrdisk_variables)

#endif
#endif /* _MIBGROUP_HRDISK_H */
