/* table_iterator.h */
#ifndef _TABLE_ITERATOR_HANDLER_H_
#define _TABLE_ITERATOR_HANDLER_H_

#ifdef __cplusplus
extern "C" {
#endif

typedef struct iterator_info_s {
   FirstDataPoint  *get_first_data_point;
   NextDataPoint   *get_next_data_point;
   FreeLoopContext *free_loop_context;
   FreeDataContext *free_data_context;

   table_registration_info *table_reginfo;
} iterator_info;
     
#define TABLE_ITERATOR_NAME "table_iterator"

mib_handler *get_table_iterator_handler(iterator_info *iinfo);
int register_table_iterator(handler_registration *reginfo,
                            iterator_info *iinfo);

void *extract_iterator_context(request_info *);

NodeHandler table_iterator_helper_handler;

#ifdef __cplusplus
};
#endif

#endif /* _TABLE_ITERATOR_HANDLER_H_ */
