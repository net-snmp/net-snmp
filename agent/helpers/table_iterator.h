/* table_iterator.h */
#ifndef _TABLE_ITERATOR_HANDLER_H_
#define _TABLE_ITERATOR_HANDLER_H_

#ifdef __cplusplus
extern "C" {
#endif

/* The table iterator helper is designed to simplify the task of
   writing a table handler for the net-snmp agent when the data being
   accessed is not in an oid sorted form and must be accessed
   externally.  Functionally, it is a specialized version of the more
   generic table helper but easies the burden of GETNEXT processing by
   manually looping through all the data indexes retrieved through
   function calls which should be supplied by the module that wishes
   help.  The module the table_iterator helps should, afterwards,
   never be called for the case of "MODE_GETNEXT" and only for the GET
   and SET related modes instead.
 */

#define TABLE_ITERATOR_NAME "table_iterator"

mib_handler *get_table_iterator_handler(table_registration_info *tabreq);
int register_table_iterator(handler_registration *reginfo,
                            table_registration_info *tabreq);

void *extract_iterator_context(request_info *);

NodeHandler table_iterator_helper_handler;

#ifdef __cplusplus
};
#endif

#endif /* _TABLE_ITERATOR_HANDLER_H_ */
