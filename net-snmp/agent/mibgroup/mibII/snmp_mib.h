/*
 *  SNMP MIB group interface - snmp.h
 *
 */
#ifndef _MIBGROUP_SNMP_H
#define _MIBGROUP_SNMP_H

struct variable;

u_char	*var_snmp __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));
int	write_snmp __P((int, u_char *, u_char, int, u_char *, oid *, int));

extern int snmp_enableauthentraps;	/* 30 - current */
extern int snmp_silentdrops;		/* 31 - current */
extern int snmp_proxydrops;		/* 32 - current */

extern char *snmp_trapsink;
extern char *snmp_trapcommunity;


#define SNMPINPKTS		1
#define SNMPOUTPKTS		2
#define SNMPINBADVERSIONS	3
#define SNMPINBADCOMMUNITYNAMES	4
#define SNMPINBADCOMMUNITYUSES	5
#define SNMPINASNPARSEERRORS	6
#define SNMPINTOOBIGS		8
#define SNMPINNOSUCHNAMES	9
#define SNMPINBADVALUES		10
#define SNMPINREADONLYS		11
#define SNMPINGENERRS		12
#define SNMPINTOTALREQVARS	13
#define SNMPINTOTALSETVARS	14
#define SNMPINGETREQUESTS	15
#define SNMPINGETNEXTS		16
#define SNMPINSETREQUESTS	17
#define SNMPINGETRESPONSES	18
#define SNMPINTRAPS		19
#define SNMPOUTTOOBIGS		20
#define SNMPOUTNOSUCHNAMES	21
#define SNMPOUTBADVALUES	22
#define SNMPOUTGENERRS		24
#define SNMPOUTGETREQUESTS	25
#define SNMPOUTGETNEXTS		26
#define SNMPOUTSETREQUESTS	27
#define SNMPOUTGETRESPONSES	28
#define SNMPOUTTRAPS		29
#define SNMPENABLEAUTHENTRAPS	30

#ifdef IN_SNMP_VARS_C
struct variable2 snmp_variables[] = {
    {SNMPINPKTS, ASN_COUNTER, RONLY, var_snmp, 1, {1}},
    {SNMPOUTPKTS, ASN_COUNTER, RONLY, var_snmp, 1, {2}},
    {SNMPINBADVERSIONS, ASN_COUNTER, RONLY, var_snmp, 1, {3}},
    {SNMPINBADCOMMUNITYNAMES, ASN_COUNTER, RONLY, var_snmp, 1, {4}},
    {SNMPINBADCOMMUNITYUSES, ASN_COUNTER, RONLY, var_snmp, 1, {5}},
    {SNMPINASNPARSEERRORS, ASN_COUNTER, RONLY, var_snmp, 1, {6}},
    {SNMPINTOOBIGS, ASN_COUNTER, RONLY, var_snmp, 1, {8}},
    {SNMPINNOSUCHNAMES, ASN_COUNTER, RONLY, var_snmp, 1, {9}},
    {SNMPINBADVALUES, ASN_COUNTER, RONLY, var_snmp, 1, {10}},
    {SNMPINREADONLYS, ASN_COUNTER, RONLY, var_snmp, 1, {11}},
    {SNMPINGENERRS, ASN_COUNTER, RONLY, var_snmp, 1, {12}},
    {SNMPINTOTALREQVARS, ASN_COUNTER, RONLY, var_snmp, 1, {13}},
    {SNMPINTOTALSETVARS, ASN_COUNTER, RONLY, var_snmp, 1, {14}},
    {SNMPINGETREQUESTS, ASN_COUNTER, RONLY, var_snmp, 1, {15}},
    {SNMPINGETNEXTS, ASN_COUNTER, RONLY, var_snmp, 1, {16}},
    {SNMPINSETREQUESTS, ASN_COUNTER, RONLY, var_snmp, 1, {17}},
    {SNMPINGETRESPONSES, ASN_COUNTER, RONLY, var_snmp, 1, {18}},
    {SNMPINTRAPS, ASN_COUNTER, RONLY, var_snmp, 1, {19}},
    {SNMPOUTTOOBIGS, ASN_COUNTER, RONLY, var_snmp, 1, {20}},
    {SNMPOUTNOSUCHNAMES, ASN_COUNTER, RONLY, var_snmp, 1, {21}},
    {SNMPOUTBADVALUES, ASN_COUNTER, RONLY, var_snmp, 1, {22}},
    {SNMPOUTGENERRS, ASN_COUNTER, RONLY, var_snmp, 1, {24}},
    {SNMPOUTGETREQUESTS, ASN_COUNTER, RONLY, var_snmp, 1, {25}},
    {SNMPOUTGETNEXTS, ASN_COUNTER, RONLY, var_snmp, 1, {26}},
    {SNMPOUTSETREQUESTS, ASN_COUNTER, RONLY, var_snmp, 1, {27}},
    {SNMPOUTGETRESPONSES, ASN_COUNTER, RONLY, var_snmp, 1, {28}},
    {SNMPOUTTRAPS, ASN_COUNTER, RONLY, var_snmp, 1, {29}},
    {SNMPENABLEAUTHENTRAPS, ASN_INTEGER, RWRITE, var_snmp, 1, {30}}
};
config_load_mib(MIB.11, 7, snmp_variables)
#endif

#endif /* _MIBGROUP_SNMP_H */
