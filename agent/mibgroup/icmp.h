/*
 *  ICMP MIB group interface - icmp.h
 *
 */
#ifndef _MIBGROUP_ICMP_H
#define _MIBGROUP_ICMP_H

extern void	init_icmp __P((void));
extern u_char	*var_icmp __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char*, oid *, int)) ));

#define ICMPINMSGS	     0
#define ICMPINERRORS	     1
#define ICMPINDESTUNREACHS   2
#define ICMPINTIMEEXCDS      3
#define ICMPINPARMPROBS      4
#define ICMPINSRCQUENCHS     5
#define ICMPINREDIRECTS      6
#define ICMPINECHOS	     7
#define ICMPINECHOREPS	     8
#define ICMPINTIMESTAMPS     9
#define ICMPINTIMESTAMPREPS 10
#define ICMPINADDRMASKS     11
#define ICMPINADDRMASKREPS  12
#define ICMPOUTMSGS	    13
#define ICMPOUTERRORS	    14
#define ICMPOUTDESTUNREACHS 15
#define ICMPOUTTIMEEXCDS    16
#define ICMPOUTPARMPROBS    17
#define ICMPOUTSRCQUENCHS   18
#define ICMPOUTREDIRECTS    19
#define ICMPOUTECHOS	    20
#define ICMPOUTECHOREPS     21
#define ICMPOUTTIMESTAMPS   22
#define ICMPOUTTIMESTAMPREPS 23
#define ICMPOUTADDRMASKS    24
#define ICMPOUTADDRMASKREPS 25

#ifdef IN_SNMP_VARS_C

struct variable2 icmp_variables[] = {
    {ICMPINMSGS, COUNTER, RONLY, var_icmp, 1, {1}},
    {ICMPINERRORS, COUNTER, RONLY, var_icmp, 1, {2}},
    {ICMPINDESTUNREACHS, COUNTER, RONLY, var_icmp, 1, {3}},
    {ICMPINTIMEEXCDS, COUNTER, RONLY, var_icmp, 1, {4}},
    {ICMPINPARMPROBS, COUNTER, RONLY, var_icmp, 1, {5}},
    {ICMPINSRCQUENCHS, COUNTER, RONLY, var_icmp, 1, {6}},
    {ICMPINREDIRECTS, COUNTER, RONLY, var_icmp, 1, {7}},
    {ICMPINECHOS, COUNTER, RONLY, var_icmp, 1, {8}},
    {ICMPINECHOREPS, COUNTER, RONLY, var_icmp, 1, {9}},
    {ICMPINTIMESTAMPS, COUNTER, RONLY, var_icmp, 1, {10}},
    {ICMPINTIMESTAMPREPS, COUNTER, RONLY, var_icmp, 1, {11}},
    {ICMPINADDRMASKS, COUNTER, RONLY, var_icmp, 1, {12}},
    {ICMPINADDRMASKREPS, COUNTER, RONLY, var_icmp, 1, {13}},
    {ICMPOUTMSGS, COUNTER, RONLY, var_icmp, 1, {14}},
    {ICMPOUTERRORS, COUNTER, RONLY, var_icmp, 1, {15}},
    {ICMPOUTDESTUNREACHS, COUNTER, RONLY, var_icmp, 1, {16}},
    {ICMPOUTTIMEEXCDS, COUNTER, RONLY, var_icmp, 1, {17}},
    {ICMPOUTPARMPROBS, COUNTER, RONLY, var_icmp, 1, {18}},
    {ICMPOUTSRCQUENCHS, COUNTER, RONLY, var_icmp, 1, {19}},
    {ICMPOUTREDIRECTS, COUNTER, RONLY, var_icmp, 1, {20}},
    {ICMPOUTECHOS, COUNTER, RONLY, var_icmp, 1, {21}},
    {ICMPOUTECHOREPS, COUNTER, RONLY, var_icmp, 1, {22}},
    {ICMPOUTTIMESTAMPS, COUNTER, RONLY, var_icmp, 1, {23}},
    {ICMPOUTTIMESTAMPREPS, COUNTER, RONLY, var_icmp, 1, {24}},
    {ICMPOUTADDRMASKS, COUNTER, RONLY, var_icmp, 1, {25}},
    {ICMPOUTADDRMASKREPS, COUNTER, RONLY, var_icmp, 1, {26}}
};

config_load_mib(MIB.5, 7, icmp_variables)
#endif

#endif /* _MIBGROUP_ICMP_H */
