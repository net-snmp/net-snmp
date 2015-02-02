#ifndef _MIBGROUP_EXECUTE_H
#define _MIBGROUP_EXECUTE_H

config_belongs_in(agent_module)

void netsnmp_close_fds(int fd);
int run_shell_command(char *command, char *input,
                      char *output,  int  *out_len);
int run_exec_command( char *command, char *input,
                      char *output,  int  *out_len);

#endif /* _MIBGROUP_EXECUTE_H */
