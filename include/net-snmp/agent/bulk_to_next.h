/* bulk_to_next.h */

/* The helper merely intercepts GETBULK requests and converts them to
 * GETNEXT reequests.
 */


netsnmp_mib_handler *get_bulk_to_next_handler(void);
void init_bulk_to_next_helper(void);
   
Netsnmp_Node_Handler bulk_to_next_helper;

