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

#endif /* _MIBGROUP_ERRORMIB_H */
