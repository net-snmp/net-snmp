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
  {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_vmstat,1,{MIBINDEX}},
  {ERRORNAME, ASN_OCTET_STR, RONLY, var_extensible_vmstat, 1, {ERRORNAME }},
  {SWAPIN, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPIN}},
  {SWAPOUT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPOUT}},
  {IOSENT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {IOSENT}},
  {IORECEIVE, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {IORECEIVE}},
  {SYSINTERRUPTS, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SYSINTERRUPTS}},
  {SYSCONTEXT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SYSCONTEXT}},
  {CPUUSER, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUUSER}},
  {CPUSYSTEM, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUSYSTEM}},
  {CPUIDLE, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUIDLE}},
/* Future use: */
/*
  {ERRORFLAG, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {ERRORFLAG }},
  {ERRORMSG, ASN_OCTET_STR, RONLY, var_extensible_vmstat, 1, {ERRORMSG }}
*/
};

config_load_mib(EXTENSIBLEMIB.11, EXTENSIBLENUM+1, extensible_vmstat_variables)

#endif
#endif /* _MIBGROUP_VMSTAT_H */
