/*
 *  util_funcs.h:  utilitiy functions for extensible groups.
 */
#ifndef _MIBGROUP_UTIL_FUNCS_H
#define _MIBGROUP_UTIL_FUNCS_H

void Exit __UCD_P((int));
int shell_command __UCD_P((struct extensible *));
int exec_command __UCD_P((struct extensible *));
int get_exec_output __UCD_P((struct extensible *));
int clear_cache __UCD_P((int, u_char *, u_char, int, u_char *, oid *,int));
RETSIGTYPE restart_doit __UCD_P((int));
int restart_hook __UCD_P((int, u_char *, u_char, int, u_char *, oid *,int));
void print_mib_oid __UCD_P((oid *,int));
void sprint_mib_oid __UCD_P((char *, oid *,int));
int checkmib __UCD_P((struct variable *, oid *, int *, int, int *, int (**write) __UCD_P((int, u_char *, u_char, int, u_char *, oid *, int)), oid *,int));
char *find_field __UCD_P((char *, int));
int parse_miboid __UCD_P((char *, oid *));
void string_append_int __UCD_P((char *, int));

#endif /* _MIBGROUP_UTIL_FUNCS_H */
