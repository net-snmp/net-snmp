/*
 *  read_config: reads configuration files for extensible sections.
 *
 */
#ifndef READ_CONFIG_H
#define READ_CONFIG_H

#define STRINGMAX 1024

#define NORMAL_CONFIG 0
#define PREMIB_CONFIG 1
#define EITHER_CONFIG 2

struct config_files {
   char *fileHeader;
   struct config_line *start;
   struct config_files *next;
};

struct config_line {
   char *config_token;
   char *help;
   void (*parse_line) (char *, char *);
   void (*free_func) (void);
   struct config_line *next;
   char config_time;
};

void read_config (char *, struct config_line *, int);
void read_configs (void);
void read_premib_configs (void);
void read_config_files (int);
void free_config (void);
void config_perror (char *);
void config_pwarn (char *);
char *skip_white (char *);
char *skip_not_white (char *);
char *skip_token(char *);
char *copy_word (char *, char *);
void read_config_with_type (char *, char *);
struct config_line *register_config_handler (char *, char *,
                                                 void (*parser)(char *, char *),
                                                 void (*releaser) (void),
                                                 char *);
struct config_line *register_premib_handler (char *, char *,
                                                 void (*parser)(char *, char *),
                                                 void (*releaser) (void),
                                                 char *);
void unregister_config_handler (char *, char *);
void read_config_print_usage(char *lead);
char *read_config_save_octet_string(char *saveto, u_char *str, int len);
char *read_config_read_octet_string(char *readfrom, u_char **str, int *len);
char *read_config_read_objid(char *readfrom, oid **objid, int *len);
char *read_config_save_objid(char *saveto, oid *objid, int len);

#endif /* READ_CONFIG_H */
