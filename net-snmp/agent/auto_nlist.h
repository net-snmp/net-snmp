/*
 * auto_nlist.h
 */

#ifdef CAN_USE_NLIST
int	auto_nlist __P((char *, char *, int));
long	auto_nlist_value __P((char *));
int	KNLookup __P((struct nlist *, int, char *, int));

#else
#	define auto_nlist(x,y,z)
#endif

