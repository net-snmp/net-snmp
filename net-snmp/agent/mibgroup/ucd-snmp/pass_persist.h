/*
 *  pass: pass through extensiblity
 */
#ifndef _MIBGROUP_PASS_PERSIST_H
#define _MIBGROUP_PASS_PERSIST_H

config_require(ucd-snmp/extensible util_funcs)

int setPassPersist (int, u_char *, u_char, int, u_char *,oid *, int);
unsigned char *var_extensible_pass_persist (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );

/* config file parsing routines */
void pass_persist_free_config (void);
void pass_persist_parse_config (char *, char *);
int pass_persist_compare (void *, void *);

#include "mibdefs.h"

#endif /* _MIBGROUP_PASS_PERSIST_H */



