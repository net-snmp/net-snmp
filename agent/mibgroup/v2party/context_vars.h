/*
 *  Template MIB group interface - context_vars.h
 *
 */
#ifndef _MIBGROUP_CONTEXT_VARS_H
#define _MIBGROUP_CONTEXT_VARS_H

extern u_char *var_context (struct variable *, oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *, oid *, int) );
extern int write_context (int, u_char *, u_char, int, u_char *, oid *, int);

#include "context.h"

#define CONTEXTTABLE	PARTYMIB, 2, 2, 1, 1

#ifdef IN_SNMP_VARS_C

struct variable2 context_variables[] = {
    {CONTEXTINDEX, ASN_INTEGER, RONLY, var_context, 1, {2}},
    {CONTEXTLOCAL, ASN_INTEGER, RONLY, var_context, 1, {3}},
    {CONTEXTVIEWINDEX, ASN_INTEGER, RONLY, var_context, 1, {4}},
    {CONTEXTLOCALENTITY, ASN_OCTET_STR, RWRITE, var_context, 1, {5}},
    {CONTEXTLOCALTIME, ASN_OBJECT_ID, RWRITE, var_context, 1, {6}},
    {CONTEXTDSTPARTYINDEX, ASN_OBJECT_ID, RWRITE, var_context, 1, {7}},
    {CONTEXTSRCPARTYINDEX, ASN_OBJECT_ID, RWRITE, var_context, 1, {8}},
    {CONTEXTPROXYCONTEXT, ASN_OBJECT_ID, RWRITE, var_context, 1, {9}},
    {CONTEXTSTORAGETYPE, ASN_INTEGER, RWRITE, var_context, 1, {10}},
    {CONTEXTSTATUS, ASN_INTEGER, RWRITE, var_context, 1, {11}}
};

config_load_mib( CONTEXTTABLE, 11, context_variables)

#endif
#endif /* _MIBGROUP_CONTEXT_VARS_H */
