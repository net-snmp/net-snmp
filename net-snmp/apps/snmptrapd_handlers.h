#ifndef SNMPTRAPD_HANDLERS_H
#define SNMPTRAPD_HANDLERS_H
char *snmptrapd_get_traphandler (oid *, size_t);
void snmptrapd_traphandle (char *, char *);

#endif /* SNMPTRAPD_HANDLERS_H */
