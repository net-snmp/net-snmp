#ifndef DEBUG_HANDLER_H
#define DEBUG_HANDLER_H

netsnmp_mib_handler *netsnmp_get_debug_handler(void);
void            netsnmp_init_debug_helper(void);

Netsnmp_Node_Handler netsnmp_debug_helper;

#endif                          /* DEBUG_HANDLER_H */
