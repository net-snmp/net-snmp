#ifdef CAN_USE_NLIST
int auto_nlist (char *, char *, int);
long auto_nlist_value (char *);
int KNLookup (struct nlist *, int, char *, int);
#else
#define auto_nlist(x,y,z)
#endif
