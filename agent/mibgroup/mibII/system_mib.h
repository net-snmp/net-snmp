/*
 *  System MIB group interface - system.h
 *
 */
#ifndef _MIBGROUP_SYSTEM_MIB_H
#define _MIBGROUP_SYSTEM_MIB_H

config_require(util_funcs)

extern char version_descr[];

void init_system __P((void));
u_char	*var_system __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

/* config file parsing routines */
void system_parse_config_sysloc __P((char *, char *));
void system_parse_config_syscon __P((char *, char *));

#define	VERSION_DESCR		1
#define	VERSIONID		2
#define	UPTIME			3
#define SYSCONTACT		4
#define SYSTEMNAME		5
#define SYSLOCATION		6
#define SYSSERVICES		7
#define SYSORLASTCHANGE		8

#endif /* _MIBGROUP_SYSTEM_MIB_H */
