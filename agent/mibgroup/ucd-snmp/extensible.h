/*
 *  Template MIB group interface - extensible.h
 *
 */
#ifndef _MIBGROUP_EXTENSIBLE_H
#define _MIBGROUP_EXTENSIBLE_H

config_require(util_funcs)
  
struct extensible *get_exten_instance (struct extensible *, int);
extern FindVarMethod var_extensible_shell;
extern WriteMethod fixExecError;
extern FindVarMethod var_extensible_relocatable;
struct subtree *find_extensible (struct subtree *, oid *, int, int);

/* config file parsing routines */
void extensible_free_config (void);
void extensible_parse_config (char *, char *);

#include "mibdefs.h"

#define SHELLCOMMAND 3
#define SHELLRESULT 6
#define SHELLOUTPUT 7

#endif /* _MIBGROUP_EXTENSIBLE_H */
