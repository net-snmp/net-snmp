/*
 *  MIB statistics structures
 *	for HP-UX architecture
 *
 *  While HP-UX does support the "traditional" structures,
 *	it also provides a cleaner ioctl interface to these
 *	statistics via the device '/dev/netman'
 *  But it doesn't define accompanying structures for the
 *	groups of leaf objects, so we'll do that here.
 */

#ifndef _MIBGROUP_KERNEL_HPUX_H
#define _MIBGROUP_KERNEL_HPUX_H

struct ip_mib
{
 	unsigned int	ipForwarding;
 	unsigned int	ipDefaultTTL;
 	unsigned int	ipInReceives;
 	unsigned int	ipInHdrErrors;
 	unsigned int	ipInAddrErrors;
 	unsigned int	ipForwDatagrams;
 	unsigned int	ipInUnknownProtos;
 	unsigned int	ipInDiscards;
 	unsigned int	ipInDelivers;
 	unsigned int	ipOutRequests;
 	unsigned int	ipOutDiscards;
 	unsigned int	ipOutNoRoutes;
 	unsigned int	ipReasmTimeout;
 	unsigned int	ipReasmReqds;
 	unsigned int	ipReasmOKs;
 	unsigned int	ipReasmFails;
 	unsigned int	ipFragOKs;
 	unsigned int	ipFragFails;
 	unsigned int	ipFragCreates;
 	unsigned int	ipRoutingDiscards;
};

struct icmp_mib
{
 	unsigned int	icmpInMsgs;
 	unsigned int	icmpInErrors;
  	unsigned int	icmpInDestUnreachs;
 	unsigned int	icmpInTimeExcds;
 	unsigned int	icmpInParmProbs;
 	unsigned int	icmpInSrcQuenchs;
 	unsigned int	icmpInRedirects;
 	unsigned int	icmpInEchos;
 	unsigned int	icmpInEchoReps;
 	unsigned int	icmpInTimestamps;
 	unsigned int	icmpInTimestampReps;
 	unsigned int	icmpInAddrMasks;
 	unsigned int	icmpInAddrMaskReps;
 	unsigned int	icmpOutMsgs;
 	unsigned int	icmpOutErrors;
 	unsigned int	icmpOutDestUnreachs;
 	unsigned int	icmpOutTimeExcds;
 	unsigned int	icmpOutParmProbs;
 	unsigned int	icmpOutSrcQuenchs;
 	unsigned int	icmpOutRedirects;
 	unsigned int	icmpOutEchos;
 	unsigned int	icmpOutEchoReps;
 	unsigned int	icmpOutTimestamps;
 	unsigned int	icmpOutTimestampReps;
 	unsigned int	icmpOutAddrMasks;
 	unsigned int	icmpOutAddrMaskReps;
};

struct udp_mib
{
 	unsigned int	udpInDatagrams;
 	unsigned int	udpNoPorts;
 	unsigned int	udpInErrors;
 	unsigned int	udpOutDatagrams;
};

struct tcp_mib
{
 	unsigned int	tcpRtoAlgorithm;
 	unsigned int	tcpRtoMin;
 	unsigned int	tcpRtoMax;
 	unsigned int	tcpMaxConn;
 	unsigned int	tcpActiveOpens;
 	unsigned int	tcpPassiveOpens;
 	unsigned int	tcpAttemptFails;
 	unsigned int	tcpEstabResets;
 	unsigned int	tcpCurrEstab;
 	unsigned int	tcpInSegs;
 	unsigned int	tcpOutSegs;
 	unsigned int	tcpRetransSegs;
 	unsigned int	tcpInErrs;
 	unsigned int	tcpOutRsts;
};

long hpux_read_stat   (char *, int, int);

#endif /* _MIBGROUP_KERNEL_HPUX_H */
