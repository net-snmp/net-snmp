/*
 *  Loadaveess watching mib group
 */
#ifndef _MIBGROUP_LOADAVE_H
#define _MIBGROUP_LOADAVE_H

config_require(util_funcs)

void	init_loadave (void);
unsigned char *var_extensible_loadave (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );

/* config file parsing routines */
void loadave_parse_config (char *, char *);
void loadave_free_config (void);

#include "mibdefs.h"

#define LOADAVE 3
#define LOADMAXVAL 4

#endif /* _MIBGROUP_LOADAVE_H */
