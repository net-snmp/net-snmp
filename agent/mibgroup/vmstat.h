/*
 *  vmstat mib groups
 *
 */
#ifndef _MIBGROUP_VMSTAT_H
#define _MIBGROUP_VMSTAT_H

#include "mibdefs.h"

unsigned char *var_extensible_vmstat __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));


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

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_vmstat_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_vmstat,1,{MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_vmstat, 1, {ERRORNAME }},
  {SWAPIN, INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPIN}},
  {SWAPOUT, INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPOUT}},
  {IOSENT, INTEGER, RONLY, var_extensible_vmstat, 1, {IOSENT}},
  {IORECEIVE, INTEGER, RONLY, var_extensible_vmstat, 1, {IORECEIVE}},
  {SYSINTERRUPTS, INTEGER, RONLY, var_extensible_vmstat, 1, {SYSINTERRUPTS}},
  {SYSCONTEXT, INTEGER, RONLY, var_extensible_vmstat, 1, {SYSCONTEXT}},
  {CPUUSER, INTEGER, RONLY, var_extensible_vmstat, 1, {CPUUSER}},
  {CPUSYSTEM, INTEGER, RONLY, var_extensible_vmstat, 1, {CPUSYSTEM}},
  {CPUIDLE, INTEGER, RONLY, var_extensible_vmstat, 1, {CPUIDLE}},
  {ERRORFLAG, INTEGER, RONLY, var_extensible_vmstat, 1, {ERRORFLAG }},
  {ERRORMSG, STRING, RONLY, var_extensible_vmstat, 1, {ERRORMSG }}
};

config_load_mib(EXTENSIBLEMIB.8, EXTENSIBLENUM+1, extensible_vmstat_variables)

#endif
#endif /* _MIBGROUP_VMSTAT_H */
