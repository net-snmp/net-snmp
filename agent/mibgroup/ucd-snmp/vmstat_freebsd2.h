/*
 *  vmstat mib groups
 *
 */
#ifndef _MIBGROUP_VMSTAT_H
#define _MIBGROUP_VMSTAT_H

#include "mibdefs.h"

extern FindVarMethod var_extensible_vmstat;
extern void init_vmstat_freebsd2(void);

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

#endif /* _MIBGROUP_VMSTAT_H */
