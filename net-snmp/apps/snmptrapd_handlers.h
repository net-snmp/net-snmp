#ifndef SNMPTRAPD_HANDLERS_H
#define SNMPTRAPD_HANDLERS_H
char *snmptrapd_get_traphandler __P((oid *, int));
void snmptrapd_traphandle __P((char *, char *));

#endif /* SNMPTRAPD_HANDLERS_H */
