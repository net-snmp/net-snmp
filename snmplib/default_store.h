/* default_store.h: storage space for defaults */
#ifndef DEFAULT_STORE_H
#define DEFAULT_STORE_H

#ifdef __cplusplus
extern "C" {
#endif

#define DS_MAX_IDS 3
#define DS_MAX_SUBIDS 32    /* needs to be a multiple of 8 */

/* begin storage definitions */
/* These definitions correspond with the "storid" argument to the API */
#define DS_LIBRARY_ID     0
#define DS_APPLICATION_ID 1
#define DS_TOKEN_ID       2

/* These definitions correspond with the "which" argument to the API,
   when the storeid argument is DS_LIBRARY_ID */
/* library booleans */
#define DS_LIB_MIB_ERRORS          0
#define DS_LIB_SAVE_MIB_DESCRS     1
#define DS_LIB_MIB_COMMENT_TERM    2
#define DS_LIB_MIB_PARSE_LABEL     3
#define DS_LIB_DUMP_PACKET         4
#define DS_LIB_LOG_TIMESTAMP       5
#define DS_LIB_DONT_READ_CONFIGS   6
#define DS_LIB_MIB_REPLACE         7  /* replace objects from latest module */
#define DS_LIB_PRINT_NUMERIC_ENUM  8  /* print only numeric enum values */
#define DS_LIB_PRINT_NUMERIC_OIDS  9  /* print only numeric enum values */
#define DS_LIB_DONT_BREAKDOWN_OIDS 10 /* dont print oid indexes specially */
#define DS_LIB_ALARM_DONT_USE_SIG  11 /* don't use the alarm() signal */
#define DS_LIB_PRINT_FULL_OID      12 /* print fully qualified oids */
#define DS_LIB_QUICK_PRINT         13 /* print very brief output for parsing */
#define DS_LIB_RANDOM_ACCESS	   14 /* random access to oid labels */
#define DS_LIB_REGEX_ACCESS	   15 /* regex matching to oid labels */
#define DS_LIB_DONT_CHECK_RANGE    16 /* don't check values for ranges on send*/
#define DS_LIB_NO_TOKEN_WARNINGS   17 /* no warn about unknown config tokens */
#define DS_LIB_NUMERIC_TIMETICKS   18 /* print timeticks as a number */
#define DS_LIB_ESCAPE_QUOTES       19 /* shell escape quote marks in oids */
#define DS_LIB_REVERSE_ENCODE      20 /* encode packets from back to front */
#define DS_LIB_PRINT_BARE_VALUE	   21 /* just print value (not OID = value) */
#define DS_LIB_EXTENDED_INDEX	   22 /* print extended index format [x1][x2] */
#define DS_LIB_PRINT_HEX_TEXT      23 /* print ASCII text along with hex strings */

/* library integers */
#define DS_LIB_MIB_WARNINGS  0
#define DS_LIB_SECLEVEL      1
#define DS_LIB_SNMPVERSION   2
#define DS_LIB_DEFAULT_PORT  3
#define DS_LIB_PRINT_SUFFIX_ONLY 4 /* print out only a single oid node  == 1.
                                      like #1 but supply mib module too == 2. */

/* library strings */
#define DS_LIB_SECNAME           0
#define DS_LIB_CONTEXT           1
#define DS_LIB_PASSPHRASE        2
#define DS_LIB_AUTHPASSPHRASE    3
#define DS_LIB_PRIVPASSPHRASE    4
#define DS_LIB_OPTIONALCONFIG    5
#define DS_LIB_APPTYPE           6
#define DS_LIB_COMMUNITY         7
#define DS_LIB_PERSISTENT_DIR    8
#define DS_LIB_CONFIGURATION_DIR 9

/* end storage definitions */

struct ds_read_config {
   u_char type;
   char  *token;
   char  *ftype;
   int    storeid;
   int    which;
   struct ds_read_config *next;
};
   
int ds_set_boolean(int storeid, int which, int value);
int ds_get_boolean(int storeid, int which);
int ds_toggle_boolean(int storeid, int which);
int ds_set_int(int storeid, int which, int value);
int ds_get_int(int storeid, int which);
int ds_set_string(int storeid, int which, const char *value);
char *ds_get_string(int storeid, int which);
int ds_set_void(int storeid, int which, void *value);
void *ds_get_void(int storeid, int which);
int ds_register_config(u_char type, const char *ftype, const char *token,
                       int storeid, int which);
int ds_register_premib(u_char type, const char *ftype, const char *token,
                       int storeid, int which);
void ds_shutdown(void);

#ifdef __cplusplus
}
#endif

#endif /* DEFAULT_STORE_H */
