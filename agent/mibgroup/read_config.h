/*
 *  read_config: reads configuration files for extensible sections.
 *
 */
#ifndef _MIBGROUP_READ_CONFIG_H
#define _MIBGROUP_READ_CONFIG_H

config_require(util_funcs extensible)

void init_read_config __P((void));
int read_config __P((char *, struct myproc **, int *, struct extensible **, int *, struct extensible**, int *, struct extensible **, int *, int *, struct diskpart *, int *, double *));
void free_config __P((struct myproc **, struct extensible **, struct extensible **, struct extensible **));
RETSIGTYPE update_config __P((int));
int pass_compare __P((void *, void *));

#endif /* _MIBGROUP_READ_CONFIG_H */
