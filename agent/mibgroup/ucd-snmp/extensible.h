/*
 *  Template MIB group interface - extensible.h
 *
 */
#ifndef _MIBGROUP_EXTENSIBLE_H
#define _MIBGROUP_EXTENSIBLE_H

config_require(util_funcs)
  
struct extensible *get_exten_instance __P((struct extensible *, int));
unsigned char *var_extensible_shell __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
int fixExecError __P((int, u_char *, u_char, int, u_char *, oid *,int));
unsigned char *var_extensible_relocatable __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
struct subtree *find_extensible __P((struct subtree *, oid *, int, int));

/* config file parsing routines */
void extensible_free_config __P((void));
void extensible_parse_config __P((char *, char *));

#include "mibdefs.h"

#define SHELLCOMMAND 3
#define SHELLRESULT 6
#define SHELLOUTPUT 7

#endif /* _MIBGROUP_EXTENSIBLE_H */
