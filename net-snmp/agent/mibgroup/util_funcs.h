/*
 *  util_funcs.h:  utilitiy functions for extensible groups.
 */
#ifndef _MIBGROUP_UTIL_FUNCS_H
#define _MIBGROUP_UTIL_FUNCS_H

config_require(errormib)

void Exit __P((int));
int shell_command __P((struct extensible *));
int exec_command __P((struct extensible *));
int get_exec_output __P((struct extensible *));
int clear_cache __P((int, u_char *, u_char, int, u_char *, oid *,int));
int update_hook __P((int, u_char *, u_char, int, u_char *, oid *,int));
RETSIGTYPE restart_doit __P((int));
int restart_hook __P((int, u_char *, u_char, int, u_char *, oid *,int));
void print_mib_oid __P((oid *,int));
void sprint_mib_oid __P((char *, oid *,int));
int checkmib __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)), oid *,int));
char *skip_white __P((char *));
char *skip_not_white __P((char *));
void copy_word __P((char *, char *));
char *find_field __P((char *, int));
int parse_miboid __P((char *, oid *));

#endif /* _MIBGROUP_UTIL_FUNCS_H */
