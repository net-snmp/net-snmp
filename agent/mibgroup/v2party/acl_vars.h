/*
 *  Template MIB group interface - acl_vars.h
 *
 */
#ifndef _MIBGROUP_ACL_VARS_H
#define _MIBGROUP_ACL_VARS_H

#include "acl.h"

extern u_char *var_acl (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int));
extern int write_acl (int, u_char *, u_char, int, u_char *, oid *, int);

#define ACLTABLE	PARTYMIB, 2, 3, 1, 1

#ifdef IN_SNMP_VARS_C

/* No access for community SNMP, RW possible for Secure SNMP */
#define PRIVRW   (SNMPV2ANY | 0x5000)
/* No access for community SNMP, RO possible for Secure SNMP */
#define PRIVRO   (SNMPV2ANY)

struct variable2 acl_variables[] = {
    {ACLPRIVELEGES, ASN_INTEGER, PRIVRW, var_acl, 1, {4}},
    {ACLSTORAGETYPE, ASN_INTEGER, PRIVRW, var_acl, 1, {5}},
    {ACLSTATUS, ASN_INTEGER, PRIVRW, var_acl, 1, {6}}
};

config_load_mib( ACLTABLE, 11, acl_variables)

#endif
#endif /* _MIBGROUP_ACL_VARS_H */
