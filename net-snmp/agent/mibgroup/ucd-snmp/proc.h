/*
 *  Process watching mib group
 */
#ifndef _MIBGROUP_PROC_H
#define _MIBGROUP_PROC_H

config_require(util_funcs)

int fixProcError (int, u_char *, u_char, int, u_char *, oid *,int);
unsigned char *var_extensible_proc (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );
struct myproc *get_proc_instance (struct myproc*, int);
int sh_count_procs (char *);
int get_ps_output (struct extensible *);

/* config file parsing routines */
void proc_free_config (void);
void proc_parse_config (char *, char *);

#include "mibdefs.h"

#define PROCMIN 3
#define PROCMAX 4
#define PROCCOUNT 5

#endif /* _MIBGROUP_PROC_H */
