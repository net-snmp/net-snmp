/* null.h */

/* literally does nothing and is used as a final handler for
   "do-nothing" nodes that must exist solely for mib tree storage
   usage..
 */

int netsnmp_register_null(oid *, size_t);
   
Netsnmp_Node_Handler netsnmp_null_handler;

