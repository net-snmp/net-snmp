#ifndef NSDEBUG_H
#define NSDEBUG_H

/*
 * function declarations 
 */
void            init_nsDebug(void);
Netsnmp_Node_Handler handle_nsDebugEnabled;
Netsnmp_Node_Handler handle_nsDebugOutputAll;
Netsnmp_Node_Handler handle_nsDebugDumpPdu;

FindVarMethod        var_dbgtokens;
WriteMethod          write_dbgPrefix;
WriteMethod          write_dbgEnabled;

#endif /* NSDEBUG_H */
