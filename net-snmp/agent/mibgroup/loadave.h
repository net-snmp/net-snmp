/*
 *  Loadaveess watching mib group
 */
#ifndef _MIBGROUP_LOADAVE_H
#define _MIBGROUP_LOADAVE_H

config_require(read_config util_funcs)

void	init_loadave __P((void));
unsigned char *var_extensible_loadave __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

/* config file parsing routines */
void loadave_parse_config __P((char *, char *));
void loadave_free_config __P((void));
config_parse_dot_conf("load", loadave_parse_config, loadave_free_config);

#include "mibdefs.h"

#define LOADAVE 3
#define LOADMAXVAL 4

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_loadave_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_loadave, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_loadave, 1, {ERRORNAME}},
  {LOADAVE, STRING, RONLY, var_extensible_loadave, 1, {LOADAVE}},
  {LOADMAXVAL, STRING, RONLY, var_extensible_loadave, 1, {LOADMAXVAL}},
    {ERRORFLAG, INTEGER, RONLY, var_extensible_loadave, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_extensible_loadave, 1, {ERRORMSG}}
};

config_load_mib(EXTENSIBLEMIB.LOADAVEMIBNUM, EXTENSIBLENUM+1, extensible_loadave_variables)

#endif
#endif /* _MIBGROUP_LOADAVE_H */
