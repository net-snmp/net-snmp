/*
 *  read_config.h: reads configuration files for extensible sections.
 *
 */
#ifndef READ_CONFIG_H
#define READ_CONFIG_H

#ifdef __cplusplus
extern "C" {
#endif

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
                                           in the given file. */
   void			(*parse_line) (const char *, char *);
   void			(*free_func) (void);
   struct config_line	 *next;
   char			  config_time;	/* {NORMAL,PREMIB,EITHER}_CONFIG */
   char                  *help;
};

void read_config (const char *, struct config_line *, int);
void read_configs (void);
void read_premib_configs (void);
void read_config_files (int);
void free_config (void);
void config_perror (const char *);
void config_pwarn (const char *);
char *skip_white (char *);
char *skip_not_white (char *);
char *skip_token(char *);
char *copy_word (char *, char *);
void read_config_with_type (const char *, const char *);
struct config_line *register_config_handler (const char *, const char *,
                                             void (*parser)(const char *, char *),
                                             void (*releaser) (void),
                                             const char *);
struct config_line *register_app_config_handler (const char *,
                                             void (*parser)(const char *, char *),
                                             void (*releaser) (void),
                                             const char *);
struct config_line *register_premib_handler (const char *, const char *,
                                             void (*parser)(const char *, char *),
                                             void (*releaser) (void),
                                             const char *);
struct config_line *register_app_premib_handler (const char *,
                                             void (*parser)(const char *, char *),
                                             void (*releaser) (void),
                                             const char *);
void unregister_config_handler (const char *, const char *);
void unregister_app_config_handler (const char *);
void unregister_all_config_handlers(void);
void read_config_print_usage(const char *lead);
char *read_config_save_octet_string(char *saveto, u_char *str, size_t len);
char *read_config_read_octet_string(char *readfrom, u_char **str, size_t *len);
char *read_config_read_objid(char *readfrom, oid **objid, size_t *len);
char *read_config_save_objid(char *saveto, oid *objid, size_t len);
char *read_config_read_data(int type, char *readfrom, void *dataptr, size_t *len);
char *read_config_store_data(int type, char *storeto, void *dataptr, size_t *len);
void  read_config_store(const char *type, const char *line);
void  read_app_config_store(const char *line);
void  snmp_save_persistent(const char *type);
void  snmp_clean_persistent(const char *type);
struct config_line *read_config_get_handlers(const char *type);

void set_configuration_directory(const char *dir);
const char *get_configuration_directory(void);
void set_persistent_directory(const char *dir);
const char *get_persistent_directory(void);

#ifdef __cplusplus
}
#endif

#endif /* READ_CONFIG_H */
