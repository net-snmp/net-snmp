/*
 *  Host Resources MIB - file system device group interface - hr_filesys.h
 *
 */
#ifndef _MIBGROUP_HRFSYS_H
#define _MIBGROUP_HRFSYS_H

extern void	init_hrfilesys();
extern u_char	*var_hrfilesys();

extern int   	Get_FSIndex();
extern int   	Get_FSSize();	/* Temporary */


#define HRFSYS_INDEX		1
#define HRFSYS_MOUNT		2
#define HRFSYS_RMOUNT		3
#define HRFSYS_TYPE		4
#define HRFSYS_ACCESS		5
#define HRFSYS_BOOT		6
#define HRFSYS_STOREIDX		7
#define HRFSYS_FULLDUMP		8
#define HRFSYS_PARTDUMP		9

#ifdef IN_SNMP_VARS_C

struct variable4 hrfsys_variables[] = {
    { HRFSYS_INDEX,     INTEGER, RONLY, var_hrfilesys, 2, {1,1}},
    { HRFSYS_MOUNT,      STRING, RONLY, var_hrfilesys, 2, {1,2}},
    { HRFSYS_RMOUNT,     STRING, RONLY, var_hrfilesys, 2, {1,3}},
    { HRFSYS_TYPE,        OBJID, RONLY, var_hrfilesys, 2, {1,4}},
    { HRFSYS_ACCESS,    INTEGER, RONLY, var_hrfilesys, 2, {1,5}},
    { HRFSYS_BOOT,      INTEGER, RONLY, var_hrfilesys, 2, {1,6}},
    { HRFSYS_STOREIDX,  INTEGER, RONLY, var_hrfilesys, 2, {1,7}},
    { HRFSYS_FULLDUMP,   STRING, RONLY, var_hrfilesys, 2, {1,8}},
    { HRFSYS_PARTDUMP,   STRING, RONLY, var_hrfilesys, 2, {1,9}},
};
config_load_mib( MIB.25.3.8, 9, hrfsys_variables)

#endif
#endif /* _MIBGROUP_HRFSYS_H */
