/* testhandler.h */
#ifndef _TABLE_HANDLER_H_
#define _TABLE_HANDLER_H_

#ifdef __cplusplus
extern "C" {
#endif

/* The table helper is designed to simplify the task of writing a
 * table handler for the net-snmp agent.  You should create a normal
 * handler and register it using the register_table() function instead
 * of the register_handler() function.
 */

/*
 * Notes:
 *
 *   1) illegal indexes automatically get handled for get/set cases.
 *      Simply check to make sure the value is type ASN_NULL before
 *      you answer a request.
 */

/* used as an index to parent_data lookups */
#define TABLE_HANDLER_NAME "table"

/*
 * column info struct.  OVERLAPPING RANGES ARE NOT SUPPORTED.
 */
typedef struct column_info_t {
  char isRange;
  char list_count; /* only useful if isRange == 0 */

  union {
	unsigned int range[2];
	unsigned int *list;
  } details;

  struct column_info_t *next;

} column_info;

typedef struct variable_list * (FirstDataPoint)(void **loop_context,
                                                void **data_context,
                                                struct variable_list *);
typedef struct variable_list * (NextDataPoint)(void **loop_context,
                                               void **data_context,
                                               struct variable_list *);
typedef void (FreeLoopContext)(void *);
typedef void (FreeDataContext)(void *);

typedef struct _table_registration_info {
   struct variable_list *indexes; /* list of varbinds with only 'type' set */
   unsigned int number_indexes;   /* calculated automatically */

  /* the minimum and maximum columns numbers. If there are columns
   * in-between which are not valid, use valid_columns to get
   * automatic column range checking.
   */
   unsigned int min_column;
   unsigned int max_column;

   column_info *valid_columns;    /* more details on columns */

   /* used by the table_iterator helper */
   /* XXXWWW: move these to an iterator specific struct */
   FirstDataPoint  *get_first_data_point;
   NextDataPoint   *get_next_data_point;
   FreeLoopContext *free_loop_context;
   FreeDataContext *free_data_context;

   /* get_first_index *() */
  /* unsigned int auto_getnext; */
} table_registration_info;

typedef struct _table_request_info {
   unsigned int colnum;            /* 0 if OID not long enough */
   unsigned int number_indexes;    /* 0 if failure to parse any */
   struct variable_list *indexes; /* contents freed by helper upon exit */
  oid index_oid[MAX_OID_LEN];
  size_t index_oid_len;
  table_registration_info *reg_info;
} table_request_info;

mib_handler *get_table_handler(table_registration_info *tabreq);
int register_table(handler_registration *reginfo,
                   table_registration_info *tabreq);
int table_build_oid(handler_registration *reginfo,
                    request_info *reqinfo,
                    table_request_info *table_info);
int table_build_oid_from_index(handler_registration *reginfo,
                               request_info *reqinfo,
                               table_request_info *table_info);
int table_build_result(handler_registration *reginfo,
                       request_info *reqinfo,
                       table_request_info *table_info, u_char type,
                       u_char *result, size_t result_len);
int update_variable_list_from_index( table_request_info * );
int update_indexes_from_variable_list( table_request_info *tri );
table_registration_info *find_table_registration_info(handler_registration *reginfo);
    
unsigned int closest_column(unsigned int current, column_info *valid_columns);

NodeHandler table_helper_handler;

#define table_helper_add_index(tinfo, type) snmp_varlist_add_variable(&tinfo->indexes, NULL, 0, type, NULL, 0);

int
check_getnext_reply(request_info *request, oid *prefix,
                    size_t prefix_len,
                    struct variable_list *newvar,
                    struct variable_list **outvar);

table_request_info *extract_table_info(request_info *);


#define ROWSTATUS_DECLARE long *rs = NULL; request_info *rsi = NULL
#define ROWSTATUS_VALIDATE( v, r ) do { \
    if( ( *v->val.integer > SNMP_ROW_DESTROY ) || \
        ( *v->val.integer < 0) ) { \
        set_mode_request_error(MODE_SET_BEGIN, r, SNMP_ERR_BADVALUE ); \
        return; \
    } \
    rs = v->val.integer; \
    rsi = r; \
} while(0)
#define ROWSTATUS_CHECK( orv, osv, ri ) do { \
    if( orv == SNMP_ROW_NONEXISTENT ) { \
        if( ! rs ) { \
            set_mode_request_error(MODE_SET_BEGIN, ri, SNMP_ERR_NOSUCHNAME );\
        } \
    } \
    else if( rs ) { \
        int rc = check_rowstatus_transition( orv, *rs, \
                                             st ? *st : osv ); \
        if(rc != SNMP_ERR_NOERROR) \
            set_mode_request_error(MODE_SET_BEGIN, rsi, rc ); \
    } \
} while(0)


#define STORAGETYPE_DECLARE long *st = NULL; request_info *sti = NULL
#define STORAGETYPE_VALIDATE( v, r ) do { \
    if ((*v->val.integer > SNMP_STORAGE_READONLY) || \
        (*v->val.integer < 0) ) { \
        set_mode_request_error(MODE_SET_BEGIN, r, SNMP_ERR_BADVALUE ); \
        return; \
    } \
    st = v->val.integer; sti = r; \
} while(0)
#define STORAGETYPE_CHECK( osv ) do { \
    if( st ) { \
        int rc = check_storage_transition( osv, *st ); \
        if(rc != SNMP_ERR_NOERROR) \
            set_mode_request_error(MODE_SET_BEGIN, sti, rc ); \
    } \
} while(0)


#ifdef __cplusplus
};
#endif

#endif /* _TABLE_HANDLER_H_ */
