/*
 *  Template MIB group interface - disk.h
 *
 */
#ifndef _MIBGROUP_DISK_H
#define _MIBGROUP_DISK_H

config_require(util_funcs read_config errormib)

unsigned char *var_extensible_disk __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#include "mibdefs.h"

#define DISKDEVICE 3
#define DISKMINIMUM 4
#define DISKTOTAL 5
#define DISKAVAIL 6
#define DISKUSED 7
#define DISKPERCENT 8

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_disk_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_disk, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_disk, 1, {ERRORNAME}},
  {DISKDEVICE, STRING, RONLY, var_extensible_disk, 1, {DISKDEVICE}},
  {DISKMINIMUM, INTEGER, RONLY, var_extensible_disk, 1, {DISKMINIMUM}},
  {DISKTOTAL, INTEGER, RONLY, var_extensible_disk, 1, {DISKTOTAL}},
  {DISKAVAIL, INTEGER, RONLY, var_extensible_disk, 1, {DISKAVAIL}},
  {DISKUSED, INTEGER, RONLY, var_extensible_disk, 1, {DISKUSED}},
  {DISKPERCENT, INTEGER, RONLY, var_extensible_disk, 1, {DISKPERCENT}},
  {ERRORFLAG, INTEGER, RONLY, var_extensible_disk, 1, {ERRORFLAG }},
  {ERRORMSG, STRING, RONLY, var_extensible_disk, 1, {ERRORMSG }}
};

config_load_mib({EXTENSIBLEMIB.DISKMIBNUM}, EXTENSIBLENUM+1, extensible_disk_variables)

#endif
#endif /* _MIBGROUP_DISK_H */
