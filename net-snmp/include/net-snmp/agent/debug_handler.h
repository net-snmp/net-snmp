#ifndef DEBUG_HANDLER_H
#define DEBUG_HANDLER_H

netsnmp_mib_handler *get_debug_handler(void);
void init_debug_helper(void);
   
Netsnmp_Node_Handler debug_helper;

#endif /* DEBUG_HANDLER_H */
