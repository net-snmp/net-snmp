/*
 *  Template MIB group interface - party_vars.h
 *
 */
#ifndef _MIBGROUP_PARTY_VARS_H
#define _MIBGROUP_PARTY_VARS_H

u_char *var_party __UCD_P((struct variable *, oid *, int *, int, int *, int (**write) __UCD_P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
int write_party __UCD_P((int, u_char *, u_char, int, u_char *, oid *, int));
struct partyEntry *party_rowCreate __UCD_P((oid *, int));
void party_rowDelete __UCD_P((oid *, int));

#include "party.h"

#define PARTYTABLE	PARTYMIB, 2, 1, 1, 1

#ifdef IN_SNMP_VARS_C

struct variable2 party_variables[] = {
    {PARTYINDEX, INTEGER, RONLY, var_party, 1, {2}},
    {PARTYTDOMAIN, OBJID, RWRITE, var_party, 1, {3}},
    {PARTYTADDRESS, STRING, RWRITE, var_party, 1, {4}},
    {PARTYMAXMESSAGESIZE, INTEGER, RWRITE, var_party, 1, {5}},
    {PARTYLOCAL, INTEGER, RWRITE, var_party, 1, {6}},
    {PARTYAUTHPROTOCOL, OBJID, RWRITE, var_party, 1, {7}},
    {PARTYAUTHCLOCK, UINTEGER, RWRITE, var_party, 1, {8}},
    {PARTYAUTHPRIVATE, STRING, RWRITE, var_party, 1, {9}},
    {PARTYAUTHPUBLIC, STRING, RWRITE, var_party, 1, {10}},
    {PARTYAUTHLIFETIME, INTEGER, RWRITE, var_party, 1, {11}},
    {PARTYPRIVPROTOCOL, OBJID, RWRITE, var_party, 1, {12}},
    {PARTYPRIVPRIVATE, STRING, RWRITE, var_party, 1, {13}},
    {PARTYPRIVPUBLIC, STRING, RWRITE, var_party, 1, {14}},
    {PARTYCLONEFROM, OBJID, RONLY, var_party, 1, {15}},
    {PARTYSTORAGETYPE, INTEGER, RWRITE, var_party, 1, {16}},
    {PARTYSTATUS, INTEGER, RWRITE, var_party, 1, {17}}
};

config_load_mib( PARTYTABLE, 11, party_variables)

#endif
#endif /* _MIBGROUP_PARTY_VARS_H */
