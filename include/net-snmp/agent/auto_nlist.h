/*
 * auto_nlist.h
 */

#ifdef CAN_USE_NLIST
int auto_nlist (const char *, char *, int);
long auto_nlist_value (const char *);
int KNLookup (struct nlist *, int, char *, int);
#else
int auto_nlist_noop(void);
#	define auto_nlist(x,y,z) auto_nlist_noop()
#	define auto_nlist_value(z) auto_nlist_noop()
#	define KNLookup(w,x,y,z) auto_nlist_noop()
#endif

