/*
 *  pass: pass through extensiblity
 */
#ifndef _MIBGROUP_PASS_PERSIST_H
#define _MIBGROUP_PASS_PERSIST_H

config_require(ucd-snmp/extensible util_funcs)

int setPassPersist __P((int, u_char *, u_char, int, u_char *,oid *, int));
unsigned char *var_extensible_pass_persist __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

/* config file parsing routines */
void pass_persist_free_config __P((void));
void pass_persist_parse_config __P((char *, char *));
config_parse_dot_conf("pass_persist", pass_persist_parse_config, pass_persist_free_config)

#include "mibdefs.h"

#endif /* _MIBGROUP_PASS_PERSIST_H */



