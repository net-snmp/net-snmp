/*
 *  vmstat_solaris2.h
 *  Header file for vmstat_solaris2 module for UCD-SNMP
 *  Jochen Kmietsch <kmietsch@jochen.de>
 *  see vmstat_solaris2.c for revision history and additional comments
 *
 */

/* Prevent accidental double inclusions */
#ifndef _MIBGROUP_VMSTAT_H
#define _MIBGROUP_VMSTAT_H

/* The following statements are used by the configure script */
/* Dependency requirements */
config_arch_require(solaris2, kernel_sunos5)

/* Directive to include utility module */
config_require(util_funcs)

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
#define CPURAWUSER 50
#define CPURAWNICE 51
#define CPURAWSYSTEM 52
#define CPURAWIDLE 53

/* MIB wants CPU_SYSTEM which is sysinfo CPU_KERNEL + CPU_WAIT */
#define CPU_SYSTEM 4 

/* Time interval to gather system data */
/* Lower value -> more accurate data, higher value -> less CPU usage */
/* Value is in seconds */
#define POLL_INTERVAL 60

/* How many snapshots of system data to keep.  Values returned are over */
/* time difference between first and last snapshot */
/* Using POLL_INTERVAL 60 and POLL_VALUES 5 we get the values */
/* over five minutes, which is a reasonable figure */
#define POLL_VALUES    5

/* Declared in vmstat_solaris2.c, from prototype */
extern void init_vmstat_solaris2(void);

#endif /* _MIBGROUP_VMSTAT_H */
