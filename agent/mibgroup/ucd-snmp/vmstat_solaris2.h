/*
 *  vmstat_solaris2.h
 *  Header file for vmstat_solaris2 module for UCD-SNMP
 *  Jochen Kmietsch <jochen.kmietsch@gmx.de>
 *  see vmstat_solaris2.c for more comments
 *  Version 0.1 initial release (Dec 1999)
 *  Version 0.2 added support for multiprocessor machines (Jan 2000)
 *  Version 0.3 some reliability enhancements and compile time fixes (Feb 2000)
 *
 */

/* Prevent accidental double inclusions */
#ifndef _MIBGROUP_VMSTAT_H
#define _MIBGROUP_VMSTAT_H

/* Defines for vp magic numbers */
#define SWAPIN 3
#define SWAPOUT 4
#define IOSENT 5
#define IORECEIVE 6
#define SYSINTERRUPTS 7
#define SYSCONTEXT 8
#define CPUUSER 9
#define CPUSYSTEM 10
#define CPUIDLE 11
#define CPUERROR 16

/* MIB wants CPU_SYSTEM which is sysinfo CPU_KERNEL + CPU_WAIT */
#define CPU_SYSTEM 4 

/* Directive to include utility module */
config_require(util_funcs)

/* Declared in vmstat_solaris2.c, from prototype */
extern void init_vmstat_solaris2(void);

/* Declared in snmp_vars.h */
extern FindVarMethod var_extensible_vmstat; 

/* Missing in Solaris header files prior to 2.6, no harm done on 2.6 and up. */
extern int getpagesize(void);

#endif /* _MIBGROUP_VMSTAT_H */
