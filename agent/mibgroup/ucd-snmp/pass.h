/*
 *  pass: pass through extensiblity
 */
#ifndef _MIBGROUP_PASS_H
#define _MIBGROUP_PASS_H

config_require(ucd-snmp/extensible util_funcs)

extern FindVarMethod var_extensible_pass;
WriteMethod setPass;
int pass_compare (void *, void *);

/* config file parsing routines */
void pass_free_config (void);
void pass_parse_config (char *, char *);

#include "mibdefs.h"

#endif /* _MIBGROUP_PASS_H */
