/*
 *  Template MIB group interface - versioninfo.h
 *
 */
#ifndef _MIBGROUP_VERSIONINFO_H
#define _MIBGROUP_VERSIONINFO_H

unsigned char *var_extensible_version __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#include "mibdefs.h"

/* Version info mib */
#define VERTAG 2
#define VERDATE 3
#define VERCDATE 4
#define VERIDENT 5
#define VERCLEARCACHE 10
#define VERUPDATECONFIG 11
#define VERRESTARTAGENT 12

config_require(util_funcs)

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_version_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_version, 1, {MIBINDEX}},
  {VERTAG, STRING, RONLY, var_extensible_version, 1, {VERTAG}},
  {VERDATE, STRING, RONLY, var_extensible_version, 1, {VERDATE}},
  {VERCDATE, STRING, RONLY, var_extensible_version, 1, {VERCDATE}},
  {VERIDENT, STRING, RONLY, var_extensible_version, 1, {VERIDENT}},
  {VERCLEARCACHE, INTEGER, RONLY, var_extensible_version, 1, {VERCLEARCACHE}},
  {VERUPDATECONFIG, INTEGER, RWRITE, var_extensible_version, 1, {VERUPDATECONFIG}},
  {VERRESTARTAGENT, INTEGER, RWRITE, var_extensible_version, 1, {VERRESTARTAGENT}}
};

config_load_mib(EXTENSIBLEMIB.VERSIONMIBNUM, EXTENSIBLENUM+1, extensible_version_variables)

#endif
#endif /* _MIBGROUP_VERSIONINFO_H */
