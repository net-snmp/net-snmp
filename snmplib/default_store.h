/* default_store.h: storage space for defaults */
#ifndef DEFAULT_STORE_H
#define DEFAULT_STORE_H

#ifdef __cplusplus
extern "C" {
#endif

#define DS_MAX_IDS 3
#define DS_MAX_SUBIDS 10

#define DS_LIBRARY_ID     0
#define DS_APPLICATION_ID 1
#define DS_TOKEN_ID       2

/* library booleans */
#define DS_LIB_MIB_ERRORS          0
#define DS_LIB_SAVE_MIB_DESCRS     1
#define DS_LIB_MIB_COMMENT_TERM    2
#define DS_LIB_MIB_PARSE_LABEL     3
#define DS_LIB_DUMP_PACKET         4
#define DS_LIB_LOG_TIMESTAMP       5
#define DS_LIB_DONT_READ_CONFIGS   6
#define DS_LIB_MIB_REPLACE         7  /* replace objects from latest module */

/* library integers */
#define DS_LIB_MIB_WARNINGS  0
#define DS_LIB_SECLEVEL      1
#define DS_LIB_SNMPVERSION   2

/* library strings */
#define DS_LIB_SECNAME         0
#define DS_LIB_CONTEXT         1
#define DS_LIB_PASSPHRASE      2
#define DS_LIB_AUTHPASSPHRASE  3
#define DS_LIB_PRIVPASSPHRASE  4
#define DS_LIB_OPTIONALCONFIG  5
#define DS_LIB_APPTYPE         6


struct ds_read_config {
   u_char type;
   char  *token;
   int    storeid;
   int    which;
   struct ds_read_config *next;
};
   
int ds_set_boolean(int storeid, int which, int value);
int ds_get_boolean(int storeid, int which);
int ds_set_int(int storeid, int which, int value);
int ds_get_int(int storeid, int which);
int ds_set_string(int storeid, int which, const char *value);
char *ds_get_string(int storeid, int which);
int ds_register_config(u_char type, const char *ftype, const char *token,
                       int storeid, int which);
int ds_register_premib(u_char type, const char *ftype, const char *token,
                       int storeid, int which);

#ifdef __cplusplus
}
#endif

#endif /* DEFAULT_STORE_H */
