/*
 *  Process watching mib group
 */
#ifndef _MIBGROUP_PROC_H
#define _MIBGROUP_PROC_H

config_require(util_funcs)

int fixProcError __UCD_P((int, u_char *, u_char, int, u_char *, oid *,int));
unsigned char *var_extensible_proc __UCD_P((struct variable *, oid *, int *, int, int *, int (**write) __UCD_P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
struct myproc *get_proc_instance __UCD_P((struct myproc*, int));
int sh_count_procs __UCD_P((char *));
int get_ps_output __UCD_P((struct extensible *));

/* config file parsing routines */
void proc_free_config __UCD_P((void));
void proc_parse_config __UCD_P((char *, char *));
config_parse_dot_conf("proc", proc_parse_config, proc_free_config);

#include "mibdefs.h"

#define PROCMIN 3
#define PROCMAX 4
#define PROCCOUNT 5

#ifdef IN_SNMP_VARS_C

struct variable2 extensible_proc_variables[] = {
  {MIBINDEX, INTEGER, RONLY, var_extensible_proc, 1, {MIBINDEX}},
  {ERRORNAME, STRING, RONLY, var_extensible_proc, 1, {ERRORNAME}}, 
    {PROCMIN, INTEGER, RONLY, var_extensible_proc, 1, {PROCMIN}}, 
    {PROCMAX, INTEGER, RONLY, var_extensible_proc, 1, {PROCMAX}},
    {PROCCOUNT, INTEGER, RONLY, var_extensible_proc, 1, {PROCCOUNT}},
    {ERRORFLAG, INTEGER, RONLY, var_extensible_proc, 1, {ERRORFLAG}},
    {ERRORMSG, STRING, RONLY, var_extensible_proc, 1, {ERRORMSG}},
  {ERRORFIX, INTEGER, RWRITE, var_extensible_proc, 1, {ERRORFIX }}
};

config_load_mib(EXTENSIBLEMIB.PROCMIBNUM, EXTENSIBLENUM+1, extensible_proc_variables)

#endif
#endif /* _MIBGROUP_PROC_H */
