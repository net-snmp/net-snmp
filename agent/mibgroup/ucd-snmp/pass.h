/*
 *  pass: pass through extensiblity
 */
#ifndef _MIBGROUP_PASS_H
#define _MIBGROUP_PASS_H

config_require(ucd-snmp/extensible util_funcs)

int setPass (int, u_char *, u_char, int, u_char *,oid *, int);
unsigned char *var_extensible_pass (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );
int pass_compare (void *, void *);

/* config file parsing routines */
void pass_free_config (void);
void pass_parse_config (char *, char *);

#include "mibdefs.h"

#endif /* _MIBGROUP_PASS_H */
