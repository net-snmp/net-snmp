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
   void (*parse_line) __P((char *, char *));
   void (*free_func) __P((void));
   struct config_line *next;
   char config_time;
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
void copy_word __P((char *, char *));
void read_config_with_type __P((char *, char *));
struct config_line *register_config_handler __P((char *, char *,
                                                 void (*parser)(char *, char *),
                                                 void (*releaser) (void)));
struct config_line *register_premib_handler __P((char *, char *,
                                                 void (*parser)(char *, char *),
                                                 void (*releaser) (void)));
void unregister_config_handler __P((char *, char *));

#endif /* READ_CONFIG_H */
