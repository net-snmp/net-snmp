/*
 *  read_config: reads configuration files for extensible sections.
 *
 */
#ifndef _MIBGROUP_READ_CONFIG_H
#define _MIBGROUP_READ_CONFIG_H

struct config_line {
   char *config_token;
   void (*parse_line) __P((char *, char *));
   void (*free_func) __P((void));
};

config_require(util_funcs extensible)

void init_read_config __P((void));
int read_config __P((char *));
void free_config __P((void));
RETSIGTYPE update_config __P((int));
int pass_compare __P((void *, void *));
void config_perror __P((char *));

#endif /* _MIBGROUP_READ_CONFIG_H */
