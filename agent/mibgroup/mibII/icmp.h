/*
 *  ICMP MIB group interface - icmp.h
 *
 */
#ifndef _MIBGROUP_ICMP_H
#define _MIBGROUP_ICMP_H

#ifdef linux
struct icmp_mib
{
 	unsigned long	IcmpInMsgs;
 	unsigned long	IcmpInErrors;
  	unsigned long	IcmpInDestUnreachs;
 	unsigned long	IcmpInTimeExcds;
 	unsigned long	IcmpInParmProbs;
 	unsigned long	IcmpInSrcQuenchs;
 	unsigned long	IcmpInRedirects;
 	unsigned long	IcmpInEchos;
 	unsigned long	IcmpInEchoReps;
 	unsigned long	IcmpInTimestamps;
 	unsigned long	IcmpInTimestampReps;
 	unsigned long	IcmpInAddrMasks;
 	unsigned long	IcmpInAddrMaskReps;
 	unsigned long	IcmpOutMsgs;
 	unsigned long	IcmpOutErrors;
 	unsigned long	IcmpOutDestUnreachs;
 	unsigned long	IcmpOutTimeExcds;
 	unsigned long	IcmpOutParmProbs;
 	unsigned long	IcmpOutSrcQuenchs;
 	unsigned long	IcmpOutRedirects;
 	unsigned long	IcmpOutEchos;
 	unsigned long	IcmpOutEchoReps;
 	unsigned long	IcmpOutTimestamps;
 	unsigned long	IcmpOutTimestampReps;
 	unsigned long	IcmpOutAddrMasks;
 	unsigned long	IcmpOutAddrMaskReps;
};
#endif

config_arch_require(solaris2, kernel_sunos5)

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
    {ICMPINMSGS, ASN_COUNTER, RONLY, var_icmp, 1, {1}},
    {ICMPINERRORS, ASN_COUNTER, RONLY, var_icmp, 1, {2}},
    {ICMPINDESTUNREACHS, ASN_COUNTER, RONLY, var_icmp, 1, {3}},
    {ICMPINTIMEEXCDS, ASN_COUNTER, RONLY, var_icmp, 1, {4}},
    {ICMPINPARMPROBS, ASN_COUNTER, RONLY, var_icmp, 1, {5}},
    {ICMPINSRCQUENCHS, ASN_COUNTER, RONLY, var_icmp, 1, {6}},
    {ICMPINREDIRECTS, ASN_COUNTER, RONLY, var_icmp, 1, {7}},
    {ICMPINECHOS, ASN_COUNTER, RONLY, var_icmp, 1, {8}},
    {ICMPINECHOREPS, ASN_COUNTER, RONLY, var_icmp, 1, {9}},
    {ICMPINTIMESTAMPS, ASN_COUNTER, RONLY, var_icmp, 1, {10}},
    {ICMPINTIMESTAMPREPS, ASN_COUNTER, RONLY, var_icmp, 1, {11}},
    {ICMPINADDRMASKS, ASN_COUNTER, RONLY, var_icmp, 1, {12}},
    {ICMPINADDRMASKREPS, ASN_COUNTER, RONLY, var_icmp, 1, {13}},
    {ICMPOUTMSGS, ASN_COUNTER, RONLY, var_icmp, 1, {14}},
    {ICMPOUTERRORS, ASN_COUNTER, RONLY, var_icmp, 1, {15}},
    {ICMPOUTDESTUNREACHS, ASN_COUNTER, RONLY, var_icmp, 1, {16}},
    {ICMPOUTTIMEEXCDS, ASN_COUNTER, RONLY, var_icmp, 1, {17}},
    {ICMPOUTPARMPROBS, ASN_COUNTER, RONLY, var_icmp, 1, {18}},
    {ICMPOUTSRCQUENCHS, ASN_COUNTER, RONLY, var_icmp, 1, {19}},
    {ICMPOUTREDIRECTS, ASN_COUNTER, RONLY, var_icmp, 1, {20}},
    {ICMPOUTECHOS, ASN_COUNTER, RONLY, var_icmp, 1, {21}},
    {ICMPOUTECHOREPS, ASN_COUNTER, RONLY, var_icmp, 1, {22}},
    {ICMPOUTTIMESTAMPS, ASN_COUNTER, RONLY, var_icmp, 1, {23}},
    {ICMPOUTTIMESTAMPREPS, ASN_COUNTER, RONLY, var_icmp, 1, {24}},
    {ICMPOUTADDRMASKS, ASN_COUNTER, RONLY, var_icmp, 1, {25}},
    {ICMPOUTADDRMASKREPS, ASN_COUNTER, RONLY, var_icmp, 1, {26}}
};

config_load_mib(MIB.5, 7, icmp_variables)
#endif

#endif /* _MIBGROUP_ICMP_H */
