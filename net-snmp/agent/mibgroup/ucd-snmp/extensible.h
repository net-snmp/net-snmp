/*
 *  Template MIB group interface - extensible.h
 *
 */
#ifndef _MIBGROUP_EXTENSIBLE_H
#define _MIBGROUP_EXTENSIBLE_H

config_require(util_funcs)
  
struct extensible *get_exten_instance (struct extensible *, int);
unsigned char *var_extensible_shell (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );
int fixExecError (int, u_char *, u_char, int, u_char *, oid *,int);
unsigned char *var_extensible_relocatable (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );
struct subtree *find_extensible (struct subtree *, oid *, int, int);

/* config file parsing routines */
void extensible_free_config (void);
void extensible_parse_config (char *, char *);

#include "mibdefs.h"

#define SHELLCOMMAND 3
#define SHELLRESULT 6
#define SHELLOUTPUT 7

#endif /* _MIBGROUP_EXTENSIBLE_H */
