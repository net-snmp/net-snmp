/*
 * SNMPv3 View-based Access Control Model
 */

#ifndef _MIBGROUP_VACM_H
#define _MIBGROUP_VACM_H

config_require(util_funcs)
config_add_mib(SNMP-VIEW-BASED-ACM-MIB) 

void init_vacm_vars __P((void));
void vacm_free_security __P((void));
void vacm_free_group __P((void));
void vacm_free_access __P((void));
void vacm_free_view __P((void));
void vacm_parse_security __P((char *, char *));
void vacm_parse_group __P((char *, char *));
void vacm_parse_access __P((char *, char *));
void vacm_parse_view __P((char *, char *));

config_parse_dot_conf("com2sec", vacm_parse_security, vacm_free_security);
config_parse_dot_conf("group", vacm_parse_group, vacm_free_group);
config_parse_dot_conf("access", vacm_parse_access, vacm_free_access);
config_parse_dot_conf("view", vacm_parse_view, vacm_free_view);

int vacm_in_view __P((struct packet_info *, oid *, int));

extern u_char *var_vacm_sec2group __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern u_char *var_vacm_access __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
extern u_char *var_vacm_view __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#define OID_SNMPVACMMIB		SNMP_OID_SNMPMODULES, 13
#define OID_VACMMIBOBJECTS	OID_SNMPVACMMIB, 1

#define OID_VACMCONTEXTTABLE	OID_VACMMIBOBJECTS, 1
#define OID_VACMCONTEXTENTRY	OID_VACMCONTEXTTABLE, 1

#define OID_VACMGROUPTABLE	OID_VACMMIBOBJECTS, 2
#define OID_VACMGROUPENTRY	OID_VACMGROUPTABLE, 1

#define OID_VACMACCESSTABLE	OID_VACMMIBOBJECTS, 4
#define OID_VACMACCESSENTRY	OID_VACMACCESSTABLE, 1

#define OID_VACMMIBVIEWS	OID_VACMMIBOBJECTS, 5
#define OID_VACMVIEWTABLE	OID_VACMMIBVIEWS, 2
#define OID_VACMVIEWENTRY	OID_VACMVIEWTABLE, 1

#ifdef IN_SNMP_VARS_C

#include "vacm.h"

#define PRIVRW	(SNMPV2ANY | 0x5000)

struct variable2 vacm_sec2group[] = {
    {SECURITYMODEL, ASN_INTEGER, PRIVRW, var_vacm_sec2group, 1, {1}},
    {SECURITYNAME, ASN_OCTET_STR, PRIVRW, var_vacm_sec2group, 1, {2}},
    {SECURITYGROUP, ASN_OCTET_STR, PRIVRW, var_vacm_sec2group, 1, {3}},
    {SECURITYSTORAGE, ASN_INTEGER, PRIVRW, var_vacm_sec2group, 1, {4}},
    {SECURITYSTATUS, ASN_INTEGER, PRIVRW, var_vacm_sec2group, 1, {5}},
};

struct variable2 vacm_access[] = {
    {ACCESSPREFIX, ASN_OCTET_STR, PRIVRW, var_vacm_access, 1, {1}},
    {ACCESSMODEL, ASN_INTEGER, PRIVRW, var_vacm_access, 1, {2}},
    {ACCESSLEVEL, ASN_INTEGER, PRIVRW, var_vacm_access, 1, {3}},
    {ACCESSMATCH, ASN_INTEGER, PRIVRW, var_vacm_access, 1, {4}},
    {ACCESSREAD, ASN_OCTET_STR, PRIVRW, var_vacm_access, 1, {5}},
    {ACCESSWRITE, ASN_OCTET_STR, PRIVRW, var_vacm_access, 1, {6}},
    {ACCESSNOTIFY, ASN_OCTET_STR, PRIVRW, var_vacm_access, 1, {7}},
    {ACCESSSTORAGE, ASN_INTEGER, PRIVRW, var_vacm_access, 1, {8}},
    {ACCESSSTATUS, ASN_INTEGER, PRIVRW, var_vacm_access, 1, {9}},
};

struct variable2 vacm_view[] = {
    {VIEWNAME, ASN_OCTET_STR, PRIVRW, var_vacm_view, 1, {1}},
    {VIEWSUBTREE, ASN_OBJECT_ID, PRIVRW, var_vacm_view, 1, {2}},
    {VIEWMASK, ASN_OCTET_STR, PRIVRW, var_vacm_view, 1, {3}},
    {VIEWTYPE, ASN_INTEGER, PRIVRW, var_vacm_view, 1, {4}},
    {VIEWSTORAGE, ASN_INTEGER, PRIVRW, var_vacm_view, 1, {5}},
    {VIEWSTATUS, ASN_INTEGER, PRIVRW, var_vacm_view, 1, {6}},
};

config_load_mib(OID_VACMGROUPENTRY, 10, vacm_sec2group)
config_load_mib(OID_VACMACCESSENTRY, 10, vacm_access)
config_load_mib(OID_VACMVIEWENTRY, 11, vacm_view)

#endif /* IN_SNMP_VARS_C */

#endif /* _MIBGROUP_VACM_H */
