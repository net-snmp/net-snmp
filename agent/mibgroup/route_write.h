/*
 *  Template MIB group interface - route_write.h
 *
 */
#ifndef _MIBGROUP_ROUTE_WRITE_H
#define _MIBGROUP_ROUTE_WRITE_H

config_require(ip)

int addRoute __UCD_P((u_long, u_long, u_long, u_short));
int delRoute __UCD_P((u_long, u_long, u_long, u_short));
struct rtent *findCacheRTE __UCD_P((u_long));
struct rtent *newCacheRTE __UCD_P((void));
int delCacheRTE __UCD_P((u_long));
struct  rtent  *cacheKernelRTE __UCD_P((u_long));
int write_rte __UCD_P((int, u_char *, u_char, int, u_char *, oid *, int));

#endif /* _MIBGROUP_ROUTE_WRITE_H */
