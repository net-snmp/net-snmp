/* bulk_to_next.h */

/* The helper merely intercepts GETBULK requests and converts them to
 * GETNEXT reequests.
 */


netsnmp_mib_handler *netsnmp_get_bulk_to_next_handler(void);
void init_netsnmp_bulk_to_next_helper(void);
   
Netsnmp_Node_Handler netsnmp_bulk_to_next_helper;

