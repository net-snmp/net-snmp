/*
 *  System MIB group interface - system.h
 *
 */
#ifndef _MIBGROUP_SYSTEM_H
#define _MIBGROUP_SYSTEM_H

config_require(util_funcs)

extern char version_descr[];

void init_system __P((void));
u_char	*var_system __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

/* config file parsing routines */
void system_parse_config_sysloc __P((char *, char *));
void system_parse_config_syscon __P((char *, char *));
config_parse_dot_conf("syslocation",system_parse_config_sysloc, NULL);
config_parse_dot_conf("syscontact",system_parse_config_syscon, NULL);

#define	VERSION_DESCR		1
#define	VERSIONID		2
#define	UPTIME			3
#define SYSCONTACT		4
#define SYSTEMNAME		5
#define SYSLOCATION		6
#define SYSSERVICES		7
#define SYSORLASTCHANGE		8


#include <var_struct.h>


#ifdef IN_SNMP_VARS_C

struct variable2 system_variables[] = {
    {VERSION_DESCR, ASN_OCTET_STR, RWRITE, var_system, 1, {1}},
    {VERSIONID, ASN_OBJECT_ID, RONLY, var_system, 1, {2}},
    {UPTIME, ASN_TIMETICKS, RONLY, var_system, 1, {3}},
    {SYSCONTACT, ASN_OCTET_STR, RWRITE, var_system, 1, {4}},
    {SYSTEMNAME, ASN_OCTET_STR, RWRITE, var_system, 1, {5}},
    {SYSLOCATION, ASN_OCTET_STR, RWRITE, var_system, 1, {6}},
    {SYSSERVICES, ASN_INTEGER, RONLY, var_system, 1, {7}},
    {SYSORLASTCHANGE, ASN_TIMETICKS, RONLY, var_system, 1, {8}}
};

config_load_mib(MIB.1, 7, system_variables)

#endif
#endif /* _MIBGROUP_SYSTEM_H */
