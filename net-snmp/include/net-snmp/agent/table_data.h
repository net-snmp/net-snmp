/* table_iterator.h */
#ifndef _TABLE_DATA_HANDLER_H_
#define _TABLE_DATA_HANDLER_H_

#ifdef __cplusplus
extern "C" {
#endif

/* This helper is designed to completely automate the task of storing
   tables of data within the agent that are not tied to external data
   sources (like the kernel, hardware, or other processes, etc).  IE,
   all rows within a table are expected to be added manually using
   functions found below.
 */

#define TABLE_DATA_NAME "table_data"

typedef struct table_row_s {
   struct variable_list *indexes; /* warning: not stored permanently */
   oid *index_oid;
   size_t index_oid_len;
   void *data;                    /* the data to store */

   struct table_row_s *next, *prev; /* if used in a list */
} table_row;

typedef struct table_data_s {
   struct variable_list *indexes_template; /* containing only types */
   char *name;                    /* if !NULL, it's registered globally */
   int flags;                     /* not currently used */
   table_row *first_row;
} table_data;

mib_handler *get_table_data_handler(table_data *table);
void table_data_generate_index_oid(table_row *row);
int table_data_add_row(table_data *table, table_row *row);
int table_data_remove_row(table_data *table, table_row *row);
  
table_row *table_data_get(table_data *table, struct variable_list *indexes);
    
table_row *table_data_get_from_oid(table_data *table,
                                    oid *searchfor, size_t searchfor_len);

int register_table_data(handler_registration *reginfo, table_data *table,
                        table_registration_info *table_info);
int register_read_only_table_data(handler_registration *reginfo,
                                  table_data *table,
                                  table_registration_info *table_info);

table_row *extract_table_row(request_info *);
void *extract_table_row_data(request_info *);
table_data *create_table_data(const char *name);
table_row *create_table_data_row(void);

int table_data_build_result(handler_registration *reginfo,
                            agent_request_info   *reqinfo,
                            request_info *request,
                            table_row *row,
                            int column,
                            u_char type,
                            u_char *result_data, size_t result_data_len);


#define table_data_add_index(thetable, type) snmp_varlist_add_variable(&thetable->indexes_template, NULL, 0, type, NULL, 0)
#define table_row_add_index(row, type, value, value_len) snmp_varlist_add_variable(&row->indexes, NULL, 0, type, (u_char *) value, value_len)


NodeHandler table_data_helper_handler;

#ifdef __cplusplus
};
#endif

#endif /* _TABLE_DATA_HANDLER_H_ */
