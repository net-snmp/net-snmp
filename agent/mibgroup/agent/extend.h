#ifndef NETSNMP_EXTEND_H
#define NETSNMP_EXTEND_H

typedef struct netsnmp_extend_s {
    char    *token;
    char    *command;
    char    *args;
    char    *input;

    int      out_len;
    char    *output;
    int      numlines;
    char   **lines;
    int      result;

    int      flags;
    netsnmp_cache *cache;
} netsnmp_extend;

void                 init_extend(void);
Netsnmp_Node_Handler handle_nsExtendTable;
void                 extend_parse_config(const char*, char*);

#define COLUMN_EXTEND_COMMAND	2
#define COLUMN_EXTEND_ARGS	3
#define COLUMN_EXTEND_INPUT	4
#define COLUMN_EXTEND_CACHETIME	5
#define COLUMN_EXTEND_EXECTYPE	6
#define COLUMN_EXTEND_RUNTYPE	7

#define COLUMN_EXTEND_OUTLEN	10
#define COLUMN_EXTEND_OUTPUT1	11	/* First Line */
#define COLUMN_EXTEND_OUTPUT2	12	/* Full Output */
#define COLUMN_EXTEND_NUMLINES	13
#define COLUMN_EXTEND_RESULT	14

#define COLUMN_EXTEND_STORAGE	20
#define COLUMN_EXTEND_STATUS	21

#define COLUMN_EXTEND_LAST_COLUMN	COLUMN_EXTEND_STATUS


#define NS_EXTEND_FLAGS_ACTIVE      0x01
#define NS_EXTEND_FLAGS_SHELL       0x02
#define NS_EXTEND_FLAGS_WRITEABLE   0x04
#define NS_EXTEND_FLAGS_CONFIG      0x08

#define NS_EXTEND_ETYPE_EXEC    1
#define NS_EXTEND_ETYPE_SHELL   2
#define NS_EXTEND_RTYPE_RONLY   1
#define NS_EXTEND_RTYPE_RWRITE  2

#endif /* NETSNMP_EXTEND_H */
