/*
 *  Process watching mib group
 */
#ifndef _MIBGROUP_PROC_H
#define _MIBGROUP_PROC_H

config_require(util_funcs)

int fixProcError __P((int, u_char *, u_char, int, u_char *, oid *,int));
unsigned char *var_extensible_proc __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
struct myproc *get_proc_instance __P((struct myproc*, int));
int sh_count_procs __P((char *));
int get_ps_output __P((struct extensible *));

/* config file parsing routines */
void proc_free_config __P((void));
void proc_parse_config __P((char *, char *));

#include "mibdefs.h"

#define PROCMIN 3
#define PROCMAX 4
#define PROCCOUNT 5

#endif /* _MIBGROUP_PROC_H */
