#ifndef SNMPTRAPD_HANDLERS_H
#define SNMPTRAPD_HANDLERS_H

typedef struct netsnmp_trapd_handler_s netsnmp_trapd_handler;

typedef int (Netsnmp_Trap_Handler)(netsnmp_pdu           *pdu,
                                   netsnmp_transport     *transport,
                                   netsnmp_trapd_handler *handler);


struct netsnmp_trapd_handler_s {
     oid  *trapoid;
     int   trapoid_len;
     char *token;		/* Or an array of tokens? */
     char *format;		/* Formatting string */
     int   version;		/* ??? */
     Netsnmp_Trap_Handler *handler;

     netsnmp_trapd_handler *nexth;	/* Next handler for this trap */
             /* Doubly-linked list of traps with registered handlers */
     netsnmp_trapd_handler *prevt;
     netsnmp_trapd_handler *nextt;
};

Netsnmp_Trap_Handler   syslog_handler;
Netsnmp_Trap_Handler   print_handler;
Netsnmp_Trap_Handler   command_handler;
Netsnmp_Trap_Handler   notification_handler;
Netsnmp_Trap_Handler   event_handler;
Netsnmp_Trap_Handler   forward_handler;

void free_trap1_fmt(void);
void free_trap2_fmt(void);
extern char *print_format1;
extern char *print_format2;

void snmptrapd_register_configs( void );
netsnmp_trapd_handler *netsnmp_add_global_traphandler(Netsnmp_Trap_Handler handler);
netsnmp_trapd_handler *netsnmp_add_default_traphandler(Netsnmp_Trap_Handler handler);
netsnmp_trapd_handler *netsnmp_add_traphandler(Netsnmp_Trap_Handler handler,
                        oid *trapOid, int trapOidLen);
netsnmp_trapd_handler *netsnmp_get_traphandler(oid *trapOid, int trapOidLen);

#endif                          /* SNMPTRAPD_HANDLERS_H */
