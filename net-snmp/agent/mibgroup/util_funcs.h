/*
 *  util_funcs.h:  utilitiy functions for extensible groups.
 */
#ifndef _MIBGROUP_UTIL_FUNCS_H
#define _MIBGROUP_UTIL_FUNCS_H

#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

#include "struct.h"

void Exit __P((int));
int shell_command __P((struct extensible *));
int exec_command __P((struct extensible *));
int get_exec_output __P((struct extensible *));
int get_exec_pipes __P((char *cmd, int *fdIn, int *fdOut, int *pid));
int clear_cache __P((int, u_char *, u_char, int, u_char *, oid *,int));
RETSIGTYPE restart_doit __P((int));
int restart_hook __P((int, u_char *, u_char, int, u_char *, oid *,int));
void print_mib_oid __P((oid *,int));
void sprint_mib_oid __P((char *, oid *,int));
int checkmib __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)), int));
int header_generic __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int))));
char *find_field __P((char *, int));
int parse_miboid __P((char *, oid *));
void string_append_int __P((char *, int));
void wait_on_exec __P((struct extensible *));

#endif /* _MIBGROUP_UTIL_FUNCS_H */
