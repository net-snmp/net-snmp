/*
 *  pass: pass through extensiblity
 */
#ifndef _MIBGROUP_PASS_PERSIST_H
#define _MIBGROUP_PASS_PERSIST_H

config_require(ucd-snmp/extensible util_funcs)

extern FindVarMethod var_extensible_pass_persist;
extern WriteMethod setPassPersist;

/* config file parsing routines */
void pass_persist_free_config (void);
void pass_persist_parse_config (char *, char *);
int pass_persist_compare (void *, void *);

#include "mibdefs.h"

#endif /* _MIBGROUP_PASS_PERSIST_H */



