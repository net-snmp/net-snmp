#ifndef MTETRIGGERCONF_H
#define MTETRIGGERCONF_H

/*
 * function declarations 
 */
void            init_mteTriggerConf(void);
void            parse_mteMonitor( const char *, char *);
void            parse_mteTTable(  const char *, char *);
void            parse_mteTDTable( const char *, char *);
void            parse_mteTExTable(const char *, char *);
void            parse_mteTBlTable(const char *, char *);
void            parse_mteTThTable(const char *, char *);
void            parse_mteTriggerTable(const char *, char *);
SNMPCallback    store_mteTTable;

#endif                          /* MTETRIGGERCONF_H */
