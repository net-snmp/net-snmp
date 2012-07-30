#ifndef _MIBGROUP_EXECUTE_H
#define _MIBGROUP_EXECUTE_H

config_belongs_in(agent_module)

int run_shell_command(char *command, char *input,
                      char *output,  size_t  *out_len);
int run_exec_command( char *command, char *input,
                      char *output,  size_t  *out_len);

#endif /* _MIBGROUP_EXECUTE_H */
