/*
 *  Errormibess watching mib group
 */
#ifndef _MIBGROUP_ERRORMIB_H
#define _MIBGROUP_ERRORMIB_H

config_require(util_funcs)

void setPerrorstatus (char *);
void seterrorstatus (char *, int);
extern FindVarMethod var_extensible_errors;

#include "mibdefs.h"

#endif /* _MIBGROUP_ERRORMIB_H */
