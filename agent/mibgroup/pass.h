/*
 *  pass: pass through extensiblity
 */
#ifndef _MIBGROUP_PASS_H
#define _MIBGROUP_PASS_H

config_require(extensible read_config)

int setPass __P((int, u_char *, u_char, int, u_char *,oid *, int));
unsigned char *var_extensible_pass __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#include "mibdefs.h"

#endif /* _MIBGROUP_PASS_H */
