/*
 *  ICMP MIB group interface - icmp.h
 *
 */
#ifndef _MIBGROUP_ICMP_H
#define _MIBGROUP_ICMP_H

config_arch_require(solaris2, kernel_sunos5)

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

extern void	init_icmp (void);
extern FindVarMethod var_icmp;

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

#endif /* _MIBGROUP_ICMP_H */
