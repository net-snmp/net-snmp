/*
 * SNMPv3 View-based Access Control Model
 */

#ifndef _MIBGROUP_VACM_H
#define _MIBGROUP_VACM_H

config_require(util_funcs)
config_add_mib(SNMP-VIEW-BASED-ACM-MIB) 

void init_vacm_vars (void);
void vacm_free_security (void);
void vacm_free_group (void);
void vacm_free_access (void);
void vacm_free_view (void);
void vacm_parse_security (char *, char *);
void vacm_parse_group (char *, char *);
void vacm_parse_access (char *, char *);
void vacm_parse_view (char *, char *);

int vacm_in_view (struct packet_info *, oid *, int);

extern u_char *var_vacm_sec2group (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );
extern u_char *var_vacm_access (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );
extern u_char *var_vacm_view (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );

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

#endif /* _MIBGROUP_VACM_H */
