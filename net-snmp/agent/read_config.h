/*
 *  read_config: reads configuration files for extensible sections.
 *
 */
#ifndef _MIBGROUP_READ_CONFIG_H
#define _MIBGROUP_READ_CONFIG_H

struct config_line {
   char *config_token;
   void (*parse_line) __UCD_P((char *, char *));
   void (*free_func) __UCD_P((void));
};

void init_read_config __UCD_P((void));
int read_config __UCD_P((char *));
void free_config __UCD_P((void));
RETSIGTYPE update_config __UCD_P((int));
int pass_compare __UCD_P((void *, void *));
void config_perror __UCD_P((char *));
char *skip_white __UCD_P((char *));
char *skip_not_white __UCD_P((char *));
void copy_word __UCD_P((char *, char *));
int tree_compare __UCD_P((const void *, const void *));
void setup_tree __UCD_P((void));

#endif /* _MIBGROUP_READ_CONFIG_H */
