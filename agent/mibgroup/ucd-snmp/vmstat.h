/*
 *  vmstat mib groups
 *
 */
#ifndef _MIBGROUP_VMSTAT_H
#define _MIBGROUP_VMSTAT_H

#include "mibdefs.h"

unsigned char *var_extensible_vmstat (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int));


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
