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
 	unsigned long	icmpInMsgs;
 	unsigned long	icmpInErrors;
  	unsigned long	icmpInDestUnreachs;
 	unsigned long	icmpInTimeExcds;
 	unsigned long	icmpInParmProbs;
 	unsigned long	icmpInSrcQuenchs;
 	unsigned long	icmpInRedirects;
 	unsigned long	icmpInEchos;
 	unsigned long	icmpInEchoReps;
 	unsigned long	icmpInTimestamps;
 	unsigned long	icmpInTimestampReps;
 	unsigned long	icmpInAddrMasks;
 	unsigned long	icmpInAddrMaskReps;
 	unsigned long	icmpOutMsgs;
 	unsigned long	icmpOutErrors;
 	unsigned long	icmpOutDestUnreachs;
 	unsigned long	icmpOutTimeExcds;
 	unsigned long	icmpOutParmProbs;
 	unsigned long	icmpOutSrcQuenchs;
 	unsigned long	icmpOutRedirects;
 	unsigned long	icmpOutEchos;
 	unsigned long	icmpOutEchoReps;
 	unsigned long	icmpOutTimestamps;
 	unsigned long	icmpOutTimestampReps;
 	unsigned long	icmpOutAddrMasks;
 	unsigned long	icmpOutAddrMaskReps;
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
