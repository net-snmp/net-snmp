/*
 *  Template MIB group interface - var_route.h
 *
 */
#ifndef _MIBGROUP_VAR_ROUTE_H
#define _MIBGROUP_VAR_ROUTE_H

config_require(ip util_funcs)
config_arch_require(solaris2, kernel_sunos5)

void init_var_route __P((void));
#ifdef RTENTRY_4_4
void load_rtentries __P((struct radix_node *));
#endif
#if defined(freebsd2) || defined(netbsd1) || defined(bsdi2) || defined(openbsd2)
struct sockaddr_in *klgetsa __P((struct sockaddr_in *));
#endif
u_char	*var_ipRouteEntry __P((struct variable*, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#endif /* _MIBGROUP_VAR_ROUTE_H */
