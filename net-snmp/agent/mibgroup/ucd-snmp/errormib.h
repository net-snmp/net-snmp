/*
 *  Errormibess watching mib group
 */
#ifndef _MIBGROUP_ERRORMIB_H
#define _MIBGROUP_ERRORMIB_H

config_require(util_funcs)

void setPerrorstatus __P((char *));
void seterrorstatus __P((char *, int));
unsigned char *var_extensible_errors __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#include "mibdefs.h"

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_error_variables[] = {
  {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_errors, 1, {MIBINDEX}},
  {ERRORNAME, ASN_OCTET_STR, RONLY, var_extensible_errors, 1, {ERRORNAME}},
  {ERRORFLAG, ASN_INTEGER, RONLY, var_extensible_errors, 1, {ERRORFLAG}},
  {ERRORMSG, ASN_OCTET_STR, RONLY, var_extensible_errors, 1, {ERRORMSG}}
};

config_load_mib(EXTENSIBLEMIB.ERRORMIBNUM, EXTENSIBLENUM+1, extensible_error_variables)

#endif
#endif /* _MIBGROUP_ERRORMIB_H */
