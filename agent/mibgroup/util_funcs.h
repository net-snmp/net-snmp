/*
 *  util_funcs.h:  utilitiy functions for extensible groups.
 */
#ifndef _MIBGROUP_UTIL_FUNCS_H
#define _MIBGROUP_UTIL_FUNCS_H

#include "struct.h"

void Exit (int);
int shell_command (struct extensible *);
int exec_command (struct extensible *);
int get_exec_output (struct extensible *);
int get_exec_pipes (char *cmd, int *fdIn, int *fdOut, int *pid);
int clear_cache (int, u_char *, u_char, int, u_char *, oid *,int);
RETSIGTYPE restart_doit (int);
int restart_hook (int, u_char *, u_char, int, u_char *, oid *,int);
void print_mib_oid (oid *,int);
void sprint_mib_oid (char *, oid *,int);
int checkmib (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int), int);
int header_generic (struct variable *,oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *,oid *,int));
char *find_field (char *, int);
int parse_miboid (char *, oid *);
void string_append_int (char *, int);
void wait_on_exec (struct extensible *);
int calculate_time_diff (struct timeval, struct timeval);

#endif /* _MIBGROUP_UTIL_FUNCS_H */
