/*
 *  read_config.h: reads configuration files for extensible sections.
 *
 */
#ifndef READ_CONFIG_H
#define READ_CONFIG_H

#define STRINGMAX 1024

#define NORMAL_CONFIG 0
#define PREMIB_CONFIG 1
#define EITHER_CONFIG 2



/*
 * Defines a set of file types and the parse and free functions
 * which process the syntax following a given token in a given file.
 */
struct config_files {
   char			*fileHeader;	/* Label for entire file. */
   struct config_line	*start;
   struct config_files	*next;
};

struct config_line {
   char			 *config_token;	/* Label for each line parser
					 * in the given file.
					 */
   void			(*parse_line) __P((char *, char *));
   void			(*free_func) __P((void));
   struct config_line	 *next;
   char			  config_time;	/* {NORMAL,PREMIB,EITHER}_CONFIG */
   char                  *help;
};

void read_config __P((char *, struct config_line *, int));
void read_configs __P((void));
void read_premib_configs __P((void));
void read_config_files __P((int));
void free_config __P((void));
void config_perror __P((char *));
void config_pwarn __P((char *));
char *skip_white __P((char *));
char *skip_not_white __P((char *));
char *skip_token(char *ptr);
char *copy_word __P((char *, char *));
void read_config_with_type __P((char *, char *));
struct config_line *register_config_handler __P((char *, char *,
                                                 void (*parser)(char *, char *),
                                                 void (*releaser) (void),
                                                 char *));
struct config_line *register_premib_handler __P((char *, char *,
                                                 void (*parser)(char *, char *),
                                                 void (*releaser) (void),
                                                 char *));
void unregister_config_handler __P((char *, char *));
void  read_config_print_usage(char *lead);
char *read_config_save_octet_string(char *saveto, u_char *str, int len);
char *read_config_read_octet_string(char *readfrom, u_char **str, int *len);
char *read_config_read_objid(char *readfrom, oid **objid, int *len);
char *read_config_save_objid(char *saveto, oid *objid, int len);

void  read_config_store(char *type, char *line);
void  snmp_clean_persistent(char *type);

#endif /* READ_CONFIG_H */
