/* table_iterator.h */
#ifndef _TABLE_ITERATOR_HANDLER_H_
#define _TABLE_ITERATOR_HANDLER_H_

#ifdef __cplusplus
extern "C" {
#endif

struct iterator_info_s;
    
typedef struct variable_list * (FirstDataPoint)(void **loop_context,
                                                void **data_context,
                                                struct variable_list *,
                                                struct iterator_info_s *);
typedef struct variable_list * (NextDataPoint)(void **loop_context,
                                               void **data_context,
                                               struct variable_list *,
                                               struct iterator_info_s *);
typedef void *                 (MakeDataContext)(void *loop_context,
                                                 struct iterator_info_s *);
typedef void (FreeLoopContext)(void *, struct iterator_info_s *);
typedef void (FreeDataContext)(void *, struct iterator_info_s *);

typedef struct iterator_info_s {
   FirstDataPoint  *get_first_data_point;
   NextDataPoint   *get_next_data_point;
   MakeDataContext *make_data_context;
   FreeLoopContext *free_loop_context;
   FreeDataContext *free_data_context;
   FreeLoopContext *free_loop_context_at_end;
   
   void *myvoid;

   table_registration_info *table_reginfo;
} iterator_info;
     
#define TABLE_ITERATOR_NAME "table_iterator"

netsnmp_mib_handler *get_table_iterator_handler(iterator_info *iinfo);
int register_table_iterator(netsnmp_handler_registration *reginfo,
                            iterator_info *iinfo);

void *extract_iterator_context(netsnmp_request_info *);

Netsnmp_Node_Handler table_iterator_helper_handler;

#ifdef __cplusplus
};
#endif

#endif /* _TABLE_ITERATOR_HANDLER_H_ */
