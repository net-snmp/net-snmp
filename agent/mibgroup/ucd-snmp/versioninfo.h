/*
 *  Template MIB group interface - versioninfo.h
 *
 */
#ifndef _MIBGROUP_VERSIONINFO_H
#define _MIBGROUP_VERSIONINFO_H

unsigned char *var_extensible_version __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
int update_hook __P((int, u_char *, u_char, int, u_char *, oid *,int));
int debugging_hook __P((int, u_char *, u_char, int, u_char *, oid *,int));

#include "mibdefs.h"

/* Version info mib */
#define VERTAG 2
#define VERDATE 3
#define VERCDATE 4
#define VERIDENT 5
#define VERCONFIG 6
#define VERCLEARCACHE 10
#define VERUPDATECONFIG 11
#define VERRESTARTAGENT 12
#define VERDEBUGGING 20

config_require(util_funcs)

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_version_variables[] = {
  {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_version, 1, {MIBINDEX}},
  {VERTAG, ASN_OCTET_STR, RONLY, var_extensible_version, 1, {VERTAG}},
  {VERDATE, ASN_OCTET_STR, RONLY, var_extensible_version, 1, {VERDATE}},
  {VERCDATE, ASN_OCTET_STR, RONLY, var_extensible_version, 1, {VERCDATE}},
  {VERIDENT, ASN_OCTET_STR, RONLY, var_extensible_version, 1, {VERIDENT}},
  {VERCONFIG, ASN_OCTET_STR, RONLY, var_extensible_version, 1, {VERCONFIG}},
  {VERCLEARCACHE, ASN_INTEGER, RONLY, var_extensible_version, 1, {VERCLEARCACHE}},
  {VERUPDATECONFIG, ASN_INTEGER, RWRITE, var_extensible_version, 1, {VERUPDATECONFIG}},
  {VERRESTARTAGENT, ASN_INTEGER, RWRITE, var_extensible_version, 1, {VERRESTARTAGENT}},
  {VERDEBUGGING, ASN_INTEGER, RWRITE, var_extensible_version, 1, {VERDEBUGGING}}
};

config_load_mib(EXTENSIBLEMIB.VERSIONMIBNUM, EXTENSIBLENUM+1, extensible_version_variables)

#endif
#endif /* _MIBGROUP_VERSIONINFO_H */
