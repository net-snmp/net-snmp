/*
 *  SNMP MIB group interface - snmp.h
 *
 */
#ifndef _MIBGROUP_SNMP_H
#define _MIBGROUP_SNMP_H

extern void	init_snmpgroup();
extern u_char	*var_snmp();
extern int	write_snmp();

extern int snmp_inpkts;			/*  1 - current */
extern int snmp_outpkts;		/*  2 - obsolete */
extern int snmp_inbadversions;		/*  3 - current */
extern int snmp_inbadcommunitynames;	/*  4 - current */
extern int snmp_inbadcommunityuses;	/*  5 - current */
extern int snmp_inasnparseerrors;	/*  6 - current */
extern int snmp_intoobigs;		/*  8 - obsolete */
extern int snmp_innosuchnames;		/*  9 - obsolete */
extern int snmp_inbadvalues;		/* 10 - obsolete */
extern int snmp_inreadonlys;		/* 11 - obsolete */
extern int snmp_ingenerrs;		/* 12 - obsolete */
extern int snmp_intotalreqvars;		/* 13 - obsolete */
extern int snmp_intotalsetvars;		/* 14 - obsolete */
extern int snmp_ingetrequests;		/* 15 - obsolete */
extern int snmp_ingetnexts;		/* 16 - obsolete */
extern int snmp_insetrequests;		/* 17 - obsolete */
extern int snmp_ingetresponses;		/* 18 - obsolete */
extern int snmp_intraps;		/* 19 - obsolete */
extern int snmp_outtoobigs;		/* 20 - obsolete */
extern int snmp_outnosuchnames;		/* 21 - obsolete */
extern int snmp_outbadvalues;		/* 22 - obsolete */
extern int snmp_outgenerrs;		/* 24 - obsolete */
extern int snmp_outgetrequests;		/* 25 - obsolete */
extern int snmp_outgetnexts;		/* 26 - obsolete */
extern int snmp_outsetrequests;		/* 27 - obsolete */
extern int snmp_outgetresponses;	/* 28 - obsolete */
extern int snmp_outtraps;		/* 29 - obsolete */
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
    {SNMPINPKTS, COUNTER, RONLY, var_snmp, 1, {1}},
    {SNMPOUTPKTS, COUNTER, RONLY, var_snmp, 1, {2}},
    {SNMPINBADVERSIONS, COUNTER, RONLY, var_snmp, 1, {3}},
    {SNMPINBADCOMMUNITYNAMES, COUNTER, RONLY, var_snmp, 1, {4}},
    {SNMPINBADCOMMUNITYUSES, COUNTER, RONLY, var_snmp, 1, {5}},
    {SNMPINASNPARSEERRORS, COUNTER, RONLY, var_snmp, 1, {6}},
    {SNMPINTOOBIGS, COUNTER, RONLY, var_snmp, 1, {8}},
    {SNMPINNOSUCHNAMES, COUNTER, RONLY, var_snmp, 1, {9}},
    {SNMPINBADVALUES, COUNTER, RONLY, var_snmp, 1, {10}},
    {SNMPINREADONLYS, COUNTER, RONLY, var_snmp, 1, {11}},
    {SNMPINGENERRS, COUNTER, RONLY, var_snmp, 1, {12}},
    {SNMPINTOTALREQVARS, COUNTER, RONLY, var_snmp, 1, {13}},
    {SNMPINTOTALSETVARS, COUNTER, RONLY, var_snmp, 1, {14}},
    {SNMPINGETREQUESTS, COUNTER, RONLY, var_snmp, 1, {15}},
    {SNMPINGETNEXTS, COUNTER, RONLY, var_snmp, 1, {16}},
    {SNMPINSETREQUESTS, COUNTER, RONLY, var_snmp, 1, {17}},
    {SNMPINGETRESPONSES, COUNTER, RONLY, var_snmp, 1, {18}},
    {SNMPINTRAPS, COUNTER, RONLY, var_snmp, 1, {19}},
    {SNMPOUTTOOBIGS, COUNTER, RONLY, var_snmp, 1, {20}},
    {SNMPOUTNOSUCHNAMES, COUNTER, RONLY, var_snmp, 1, {21}},
    {SNMPOUTBADVALUES, COUNTER, RONLY, var_snmp, 1, {22}},
    {SNMPOUTGENERRS, COUNTER, RONLY, var_snmp, 1, {24}},
    {SNMPOUTGETREQUESTS, COUNTER, RONLY, var_snmp, 1, {25}},
    {SNMPOUTGETNEXTS, COUNTER, RONLY, var_snmp, 1, {26}},
    {SNMPOUTSETREQUESTS, COUNTER, RONLY, var_snmp, 1, {27}},
    {SNMPOUTGETRESPONSES, COUNTER, RONLY, var_snmp, 1, {28}},
    {SNMPOUTTRAPS, COUNTER, RONLY, var_snmp, 1, {29}},
    {SNMPENABLEAUTHENTRAPS, INTEGER, RWRITE, var_snmp, 1, {30}}
};
#define  SNMP_SUBTREE { \
    {MIB, 11}, 7, (struct variable *)snmp_variables, \
	 sizeof(snmp_variables)/sizeof(*snmp_variables), \
	 sizeof(*snmp_variables) }
#endif

#endif /* _MIBGROUP_SNMP_H */
