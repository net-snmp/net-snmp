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

