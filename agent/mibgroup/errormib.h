/*
 *  Errormibess watching mib group
 */
#ifndef _MIBGROUP_ERRORMIB_H
#define _MIBGROUP_ERRORMIB_H

config_require(util_funcs)

void setPerrorstatus __UCD_P((char *));
void seterrorstatus __UCD_P((char *, int));
unsigned char *var_extensible_errors __UCD_P((struct variable *, oid *, int *, int, int *, int (**write) __UCD_P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#include "mibdefs.h"

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_error_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_errors, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_errors, 1, {ERRORNAME}},
    {ERRORFLAG, INTEGER, RONLY, var_extensible_errors, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_extensible_errors, 1, {ERRORMSG}}
};

config_load_mib(EXTENSIBLEMIB.ERRORMIBNUM, EXTENSIBLENUM+1, extensible_error_variables)

#endif
#endif /* _MIBGROUP_ERRORMIB_H */
