/* table_iterator.h */
#ifndef _TABLE_DATA_SET_HANDLER_H_
#define _TABLE_DATA_SET_HANDLER_H_

#ifdef __cplusplus
extern "C" {
#endif

/* This helper is designed to completely automate the task of storing
   tables of data within the agent that are not tied to external data
   sources (like the kernel, hardware, or other processes, etc).  IE,
   all rows within a table are expected to be added manually using
   functions found below.
 */

#define TABLE_DATA_SET_NAME "table_data_set"

typedef int (Value_Change_Ok)(char *old_value, size_t old_value_len,
                              char *new_value, size_t new_value_len);

/* stored within a given row */
typedef struct table_data_set_storage_s {
   unsigned int column;

   /* info about it? */
   char writable;
   int type;
   Value_Change_Ok *change_ok_fn;

   /* data actually stored */
    union { /* value of variable */
       void    *voidp;
       long    *integer;
       u_char  *string;
       oid     *objid;
       u_char  *bitstring;
       struct counter64 *counter64;
#ifdef OPAQUE_SPECIAL_TYPES
       float   *floatVal;
       double  *doubleVal;
#endif /* OPAQUE_SPECIAL_TYPES */
    } data;
   u_long  data_len;
   
   struct table_data_set_storage_s *next;
} table_data_set_storage;

typedef struct table_data_set_s {
   table_data *table;
   table_data_set_storage *default_row;
} table_data_set;

NodeHandler table_data_set_helper_handler;

int table_set_add_default_row(table_data_set *, unsigned int, int, int);
int set_row_column(table_row *, unsigned int, int, const char *, size_t);
table_data_set_storage *table_data_set_find_column(table_data_set_storage *,
                                                   int);
int register_table_data_set(handler_registration *, table_data_set *,
                            table_registration_info *);
mib_handler *get_table_data_set_handler(table_data_set *);
table_data_set *create_table_data_set(const char *);
int mark_row_column_writable(table_row *row, int column, int writable);
inline table_data_set *extract_table_data_set(request_info *request);
void config_parse_table_set(const char *token, char *line);
void config_parse_add_row(const char *token, char *line);
inline void table_dataset_add_index(table_data_set *table, int type);
inline void table_dataset_add_row(table_data_set *table, table_row *row);
    
#ifdef __cplusplus
};
#endif

#define table_row_add_column(row, type, value, value_len) snmp_varlist_add_variable(&row->indexes, NULL, 0, type, (u_char *) value, value_len)

#endif /* _TABLE_DATA_SET_HANDLER_H_ */
