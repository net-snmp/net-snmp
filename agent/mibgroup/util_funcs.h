/*
 *  util_funcs.h:  utilitiy functions for extensible groups.
 */
#ifndef _MIBGROUP_UTIL_FUNCS_H
#define _MIBGROUP_UTIL_FUNCS_H

#ifdef IN_UCD_SNMP_SOURCE
#include "struct.h"
#else
#include <ucd-snmp/struct.h>
#endif

void Exit (int);
int shell_command (struct extensible *);
int exec_command (struct extensible *);
int get_exec_output (struct extensible *);
int get_exec_pipes (char *cmd, int *fdIn, int *fdOut, int *pid);
WriteMethod clear_cache;
RETSIGTYPE restart_doit (int);
WriteMethod restart_hook;
void print_mib_oid (oid *, size_t);
void sprint_mib_oid (char *, oid *, size_t);
int header_simple_table (struct variable *, oid *,  size_t *, int,  size_t *, WriteMethod **write_method, int);
int header_generic (struct variable *,oid *,  size_t *, int,  size_t *, WriteMethod **);
int checkmib (struct variable *, oid *,  size_t *, int,  size_t *, WriteMethod **write_method, int);
char *find_field (char *, int);
int parse_miboid (const char *, oid *);
void string_append_int (char *, int);
void wait_on_exec (struct extensible *);

#endif /* _MIBGROUP_UTIL_FUNCS_H */
