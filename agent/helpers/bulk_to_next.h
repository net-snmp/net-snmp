/* bulk_to_next.h */

/* The helper merely intercepts GETBULK requests and converts them to
 * GETNEXT reequests.
 */


mib_handler *get_bulk_to_next_handler(void);
void init_bulk_to_next_helper(void);
   
NodeHandler bulk_to_next_helper;

