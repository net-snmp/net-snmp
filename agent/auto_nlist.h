#ifdef CAN_USE_NLIST
int auto_nlist __P((char *, char *, int));
#else
#define auto_nlist(x,y,z)
#endif
