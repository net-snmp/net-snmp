/*
 *  Host Resources MIB - Running Software group interface - hr_swinst.h
 *
 */
#ifndef _MIBGROUP_HRSWINST_H
#define _MIBGROUP_HRSWINST_H

extern void	init_hr_swinst (void);
extern u_char	*var_hrswinst  (struct variable *, oid *, int *, int, int *,
				int (**write) (int, u_char *, u_char, int,
					       u_char *, oid *, int));



#define	HRSWINST_CHANGE		1
#define	HRSWINST_UPDATE		2

#define	HRSWINST_INDEX		3
#define	HRSWINST_NAME		4
#define	HRSWINST_ID		5
#define	HRSWINST_TYPE		6
#define	HRSWINST_DATE		7


#ifdef IN_SNMP_VARS_C

struct variable4 hrswinst_variables[] = {
    { HRSWINST_CHANGE,  ASN_TIMETICKS, RONLY, var_hrswinst, 1, {1}},
    { HRSWINST_UPDATE,  ASN_TIMETICKS, RONLY, var_hrswinst, 1, {2}},
    { HRSWINST_INDEX,     ASN_INTEGER, RONLY, var_hrswinst, 3, {3,1,1}},
    { HRSWINST_NAME,    ASN_OCTET_STR, RONLY, var_hrswinst, 3, {3,1,2}},
    { HRSWINST_ID,      ASN_OBJECT_ID, RONLY, var_hrswinst, 3, {3,1,3}},
    { HRSWINST_TYPE,      ASN_INTEGER, RONLY, var_hrswinst, 3, {3,1,4}},
    { HRSWINST_DATE,    ASN_OCTET_STR, RONLY, var_hrswinst, 3, {3,1,5}}
};

config_load_mib( MIB.25.6, 8, hrswinst_variables)

#endif
#endif /* _MIBGROUP_HRSWINST_H */
