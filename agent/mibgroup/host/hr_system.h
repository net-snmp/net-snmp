/*
 *  Host Resources MIB - system group interface - hr_system.h
 *
 */
#ifndef _MIBGROUP_HRSYSTEM_H
#define _MIBGROUP_HRSYSTEM_H

config_require(host/hr_utils )

extern void	init_hr_system (void);
extern FindVarMethod var_hrsys;


#endif /* _MIBGROUP_HRSYSTEM_H */
