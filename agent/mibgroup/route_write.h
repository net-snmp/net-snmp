/*
 *  Template MIB group interface - route_write.h
 *
 */
#ifndef _MIBGROUP_ROUTE_WRITE_H
#define _MIBGROUP_ROUTE_WRITE_H

config_require(ip)

int addRoute __P((u_long, u_long, u_long, u_short));
int delRoute __P((u_long, u_long, u_long, u_short));
struct rtent *findCacheRTE __P((u_long));
struct rtent *newCacheRTE __P((void));
int delCacheRTE __P((u_long));
struct  rtent  *cacheKernelRTE __P((u_long));
int write_rte __P((int, u_char *, u_char, int, u_char *, oid *, int));

#endif /* _MIBGROUP_ROUTE_WRITE_H */
