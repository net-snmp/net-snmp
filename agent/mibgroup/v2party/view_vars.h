/*
 *  Template MIB group interface - view_vars.h
 *
 */
#ifndef _MIBGROUP_VIEW_VARS_H
#define _MIBGROUP_VIEW_VARS_H

extern u_char *var_view (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int));
extern int write_view (int, u_char *, u_char, int, u_char *, oid *, int);

#include "view.h"

#define VIEWTABLE	PARTYMIB, 2, 4, 1, 1

#ifdef IN_SNMP_VARS_C

/* No access for community SNMP, RW possible for Secure SNMP */
#define PRIVRW   (SNMPV2ANY | 0x5000)
/* No access for community SNMP, RO possible for Secure SNMP */
#define PRIVRO   (SNMPV2ANY)

struct variable2 view_variables[] = {
    {VIEWMASK, ASN_OCTET_STR, PRIVRW, var_view, 1, {3}},
    {VIEWTYPE, ASN_INTEGER, PRIVRW, var_view, 1, {4}},
    {VIEWSTORAGETYPE, ASN_INTEGER, PRIVRW, var_view, 1, {5}},
    {VIEWSTATUS, ASN_INTEGER, PRIVRW, var_view, 1, {6}}
};

config_load_mib( VIEWTABLE, 11, view_variables)

#endif
#endif /* _MIBGROUP_VIEW_VARS_H */
