/*
 *  Template MIB group interface - sysORTable.h
 *
 */
#ifndef _MIBGROUP_SYSORTABLE_H
#define _MIBGROUP_SYSORTABLE_H

config_require(util_funcs)

struct sysORTable {
   char *OR_descr;
   oid  *OR_oid;
   int  OR_oidlen;
   struct timeval OR_uptime;
   struct sysORTable *next;
};

extern void     init_sysORTable __P((void));
extern u_char	*var_sysORTable __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern void     register_sysORTable __P((oid *, int, char *));

#define	SYSORLASTCHANGE		        0
#define	SYSORTABLEINDEX		        1
#define	SYSORTABLEID		        2
#define	SYSORTABLEDESCR		        3
#define	SYSORTABLEUPTIME	        4

#ifdef IN_SNMP_VARS_C

struct variable2 sysORLastChange_variables[] = {
    { SYSORLASTCHANGE,   ASN_TIMETICKS, RONLY, var_sysORTable, 1, {1}},
};

struct variable2 sysORTable_variables[] = {
    { SYSORTABLEINDEX,   ASN_INTEGER,       RONLY, var_sysORTable, 1, {1}},
    { SYSORTABLEID,      ASN_OBJECT_ID,     RONLY, var_sysORTable, 1, {2}},
    { SYSORTABLEDESCR,   ASN_OCTET_STR,     RONLY, var_sysORTable, 1, {3}},
    { SYSORTABLEUPTIME,  ASN_TIMETICKS,     RONLY, var_sysORTable, 1, {4}}
};

config_load_mib(1.3.6.1.2.1.1.8, 8, sysORLastChange_variables)
config_load_mib(1.3.6.1.2.1.1.9.1, 9, sysORTable_variables)

#endif
#endif /* _MIBGROUP_SYSORTABLE_H */
