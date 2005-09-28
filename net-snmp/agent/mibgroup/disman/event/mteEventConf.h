#ifndef MTEEVENTCONF_H
#define MTEEVENTCONF_H

/*
 * function declarations 
 */
void            init_mteEventConf(void);

void            parse_notificationEvent(const char *, char *);
void            parse_setEvent(         const char *, char *);

void            parse_mteETable(   const char *, char *);
void            parse_mteENotTable(const char *, char *);
void            parse_mteESetTable(const char *, char *);
SNMPCallback    store_mteETable;

#endif                          /* MTEEVENTCONF_H */
