/* read_only.h */

/* The helper merely intercepts SET requests and handles them early on
   making everything read-only (no SETs are actually permitted).
   Useful as a helper to handlers that are implementing MIBs with no
   SET support.
 */


netsnmp_mib_handler *netsnmp_get_read_only_handler(void);
void init_netsnmp_read_only_helper(void);
   
Netsnmp_Node_Handler netsnmp_read_only_helper;

