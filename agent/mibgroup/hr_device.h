/*
 *  Host Resources MIB - device group interface - hr_device.h
 *
 */
#ifndef _MIBGROUP_HRDEVICE_H
#define _MIBGROUP_HRDEVICE_H

extern void	init_hrdevice();
extern u_char	*var_hrdevice();



#define	HRDEV_INDEX		1
#define	HRDEV_TYPE		2
#define	HRDEV_DESCR		3
#define	HRDEV_ID		4
#define	HRDEV_STATUS		5
#define	HRDEV_ERRORS		6

#ifdef IN_SNMP_VARS_C

struct variable4 hrdevice_variables[] = {
    { HRDEV_INDEX,     INTEGER, RONLY, var_hrdevice, 2, {1,1}},
    { HRDEV_TYPE,        OBJID, RONLY, var_hrdevice, 2, {1,2}},
    { HRDEV_DESCR,      STRING, RONLY, var_hrdevice, 2, {1,3}},
    { HRDEV_ID,          OBJID, RONLY, var_hrdevice, 2, {1,4}},
    { HRDEV_STATUS,    INTEGER, RONLY, var_hrdevice, 2, {1,5}},
    { HRDEV_ERRORS,    COUNTER, RONLY, var_hrdevice, 2, {1,6}}
};
config_load_mib( MIB.25.3.2, 9, hrdevice_variables)

#endif
#endif /* _MIBGROUP_HRDEVICE_H */
