/*
 * Definitions for the variables as defined in the MIB
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/

struct	mib_system {
    char    sysDescr[32];   /* textual description */
    u_char  sysObjectID[16];/* OBJECT IDENTIFIER of system */
    u_char  ObjIDLen;	    /* length of sysObjectID */
    u_long  sysUpTime;	    /* Uptime in 100/s of a second */    
};

struct mib_interface {
    long    ifNumber;	    /* number of interfaces */
};

struct mib_ifEntry {
    long    ifIndex;	    /* index of this interface	*/
    char    ifDescr[32];    /* english description of interface	*/
    long    ifType;	    /* network type of device	*/
    long    ifMtu;	    /* size of largest packet in bytes	*/
    u_long  ifSpeed;	    /* bandwidth in bits/sec	*/
    u_char  ifPhysAddress[11];	/* interface's address */
    u_char  PhysAddrLen;    /* length of physAddr */
    long    ifAdminStatus;  /* desired state of interface */
    long    ifOperStatus;   /* current operational status */
    u_long  ifLastChange;   /* value of sysUpTime when current state entered */
    u_long  ifInOctets;	    /* number of octets received on interface */
    u_long  ifInUcastPkts;  /* number of unicast packets delivered */
    u_long  ifInNUcastPkts; /* number of broadcasts or multicasts */
    u_long  ifInDiscards;   /* number of packets discarded with no error */
    u_long  ifInErrors;	    /* number of packets containing errors */
    u_long  ifInUnknownProtos;	/* number of packets with unknown protocol */
    u_long  ifOutOctets;    /* number of octets transmitted */
    u_long  ifOutUcastPkts; /* number of unicast packets sent */
    u_long  ifOutNUcastPkts;/* number of broadcast or multicast pkts */
    u_long  ifOutDiscards;  /* number of packets discarded with no error */
    u_long  ifOutErrors;    /* number of pkts discarded with an error */
    u_long  ifOutQLen;	    /* number of packets in output queue */
};

struct mib_atEntry {
    long    atIfIndex;	    /* interface on which this entry maps */
    u_char  atPhysAddress[11]; /* physical address of destination */
    u_char  PhysAddressLen; /* length of atPhysAddress */
    u_long  atNetAddress;   /* IP address of physical address */
};

struct mib_ip {
    long    ipForwarding;   /* 1 if gateway, 2 if host */
    long    ipDefaultTTL;   /* default TTL for pkts originating here */
    u_long  ipInReceives;   /* no. of IP packets received from interfaces */
    u_long  ipInHdrErrors;  /* number of pkts discarded due to header errors */
    u_long  ipInAddrErrors; /* no. of pkts discarded due to bad address */
    u_long  ipForwDatagrams;/* number pf pkts forwarded through this entity */
    u_long  ipInUnknownProtos;/* no. of local-addressed pkts w/unknown proto */
    u_long  ipInDiscards;   /* number of error-free packets discarded */
    u_long  ipInDelivers;   /* number of datagrams delivered to upper level */
    u_long  ipOutRequests;  /* number of IP datagrams originating locally */
    u_long  ipOutDiscards;  /* number of error-free output IP pkts discarded */
    u_long  ipOutNoRoutes;  /* number of IP pkts discarded due to no route */
    long    ipReasmTimeout; /* seconds fragment is held awaiting reassembly */
    u_long  ipReasmReqds;   /* no. of fragments needing reassembly (here) */
    u_long  ipReasmOKs;	    /* number of fragments reassembled */
    u_long  ipReasmFails;   /* number of failures in IP reassembly */
    u_long  ipFragOKs;	    /* number of datagrams fragmented here */
    u_long  ipFragFails;    /* no. pkts unable to be fragmented here */
    u_long  ipFragCreates;  /* number of IP fragments created here */
};

struct mib_ipAddrEntry {
    u_long  ipAdEntAddr;    /* IP address of this entry */
    long    ipAdEntIfIndex; /* IF for this entry */
    u_long  ipAdEntNetMask; /* subnet mask of this entry */
    long    ipAdEntBcastAddr;/* read the MIB for this one */
};

struct mib_ipRouteEntry {
    u_long  ipRouteDest;    /* destination IP addr for this route */
    long    ipRouteIfIndex; /* index of local IF for this route */
    long    ipRouteMetric1; /* Primary routing metric */
    long    ipRouteMetric2; /* Alternate routing metric */
    long    ipRouteMetric3; /* Alternate routing metric */
    long    ipRouteMetric4; /* Alternate routing metric */
    u_long  ipRouteNextHop; /* IP addr of next hop */
    long    ipRouteType;    /* Type of this route */
    long    ipRouteProto;   /* How this route was learned */
    long    ipRouteAge;	    /* No. of seconds since updating this route */
};

struct mib_icmp {
    u_long  icmpInMsgs;	    /* Total of ICMP msgs received */
    u_long  icmpInErrors;   /* Total of ICMP msgs received with errors */
    u_long  icmpInDestUnreachs;
    u_long  icmpInTimeExcds;
    u_long  icmpInParmProbs;
    u_long  icmpInSrcQuenchs;
    u_long  icmpInRedirects;
    u_long  icmpInEchos;
    u_long  icmpInEchoReps;
    u_long  icmpInTimestamps;
    u_long  icmpInTimestampReps;
    u_long  icmpInAddrMasks;
    u_long  icmpInAddrMaskReps;
    u_long  icmpOutMsgs;
    u_long  icmpOutErrors;
    u_long  icmpOutDestUnreachs;
    u_long  icmpOutTimeExcds;
    u_long  icmpOutParmProbs;
    u_long  icmpOutSrcQuenchs;
    u_long  icmpOutRedirects;
    u_long  icmpOutEchos;
    u_long  icmpOutEchoReps;
    u_long  icmpOutTimestamps;
    u_long  icmpOutTimestampReps;
    u_long  icmpOutAddrMasks;
    u_long  icmpOutAddrMaskReps;
};

struct	mib_tcp {
    long    tcpRtoAlgorithm;	/* retransmission timeout algorithm */
    long    tcpRtoMin;		/* minimum retransmission timeout (mS) */
    long    tcpRtoMax;		/* maximum retransmission timeout (mS) */ 
    long    tcpMaxConn;		/* maximum tcp connections possible */
    u_long  tcpActiveOpens;	/* number of SYN-SENT -> CLOSED transitions */
    u_long  tcpPassiveOpens;	/* number of SYN-RCVD -> LISTEN transitions */
    u_long  tcpAttemptFails;/*(SYN-SENT,SYN-RCVD)->CLOSED or SYN-RCVD->LISTEN*/
    u_long  tcpEstabResets;	/* (ESTABLISHED,CLOSE-WAIT) -> CLOSED */
    u_long  tcpCurrEstab;	/* number in ESTABLISHED or CLOSE-WAIT state */
    u_long  tcpInSegs;		/* number of segments received */
    u_long  tcpOutSegs;		/* number of segments sent */
    u_long  tcpRetransSegs;	/* number of retransmitted segments */
};

struct mib_tcpConnEntry {
    long    tcpConnState;	/* State of this connection */
    u_long  tcpConnLocalAddress;/* local IP address for this connection */
    long    tcpConnLocalPort;	/* local port for this connection */
    u_long  tcpConnRemAddress;	/* remote IP address for this connection */
    long    tcpConnRemPort;	/* remote port for this connection */
};

struct mib_udp {
    u_long  udpInDatagrams; /* No. of UDP datagrams delivered to users */
    u_long  udpNoPorts;	    /* No. of UDP datagrams to port with no listener */
    u_long  udpInErrors;    /* No. of UDP datagrams unable to be delivered */
    u_long  udpOutDatagrams;/* No. of UDP datagrams sent from this entity */
};

struct	mib_egp {
    u_long  egpInMsgs;	/* No. of EGP msgs received without error */
    u_long  egpInErrors;/* No. of EGP msgs received with error */
    u_long  egpOutMsgs;	/* No. of EGP msgs sent */
    u_long  egpOutErrors;/* No. of (outgoing) EGP msgs dropped due to error */
};

struct	mib_egpNeighEntry {
    long    egpNeighState;  /* local EGP state with this entry's neighbor */
    u_long  egpNeighAddr;   /* IP address of this entry's neighbor */
};

#define MIB 1, 3, 6, 1, 2, 1

#define MIB_IFTYPE_OTHER		    1
#define MIB_IFTYPE_REGULAR1822		    2
#define MIB_IFTYPE_HDH1822		    3
#define MIB_IFTYPE_DDNX25		    4
#define MIB_IFTYPE_RFC877X25		    5
#define MIB_IFTYPE_ETHERNETCSMACD	    6
#define MIB_IFTYPE_ISO88023CSMACD	    7
#define MIB_IFTYPE_ISO88024TOKENBUS	    8
#define MIB_IFTYPE_ISO88025TOKENRING	    9
#define MIB_IFTYPE_ISO88026MAN		    10
#define MIB_IFTYPE_STARLAN		    11
#define MIB_IFTYPE_PROTEON10MBIT	    12
#define MIB_IFTYPE_PROTEON80MBIT	    13
#define MIB_IFTYPE_HYPERCHANNEL		    14
#define MIB_IFTYPE_FDDI			    15
#define MIB_IFTYPE_LAPB			    16
#define MIB_IFTYPE_SDLC			    17
#define MIB_IFTYPE_T1CARRIER		    18
#define MIB_IFTYPE_CEPT			    19
#define MIB_IFTYPE_BASICISDN		    20
#define MIB_IFTYPE_PRIMARYISDN		    21
#define MIB_IFTYPE_PROPPOINTTOPOINTSERIAL   22

#define MIB_IFSTATUS_UP		1
#define MIB_IFSTATUS_DOWN	2
#define MIB_IFSTATUS_TESTING	3

#define MIB_FORWARD_GATEWAY	1
#define MIB_FORWARD_HOST	2

#define MIB_IPROUTETYPE_OTHER	1
#define MIB_IPROUTETYPE_INVALID	2
#define MIB_IPROUTETYPE_DIRECT	3
#define MIB_IPROUTETYPE_REMOTE	4

#define MIB_IPROUTEPROTO_OTHER	    1
#define MIB_IPROUTEPROTO_LOCAL	    2
#define MIB_IPROUTEPROTO_NETMGMT    3
#define MIB_IPROUTEPROTO_ICMP	    4
#define MIB_IPROUTEPROTO_EGP	    5
#define MIB_IPROUTEPROTO_GGP	    6
#define MIB_IPROUTEPROTO_HELLO	    7
#define MIB_IPROUTEPROTO_RIP	    8
#define MIB_IPROUTEPROTO_ISIS	    9
#define MIB_IPROUTEPROTO_ESIS	    10
#define MIB_IPROUTEPROTO_CISCOIGRP  11
#define MIB_IPROUTEPROTO_BBNSPFIGP  12
#define MIB_IPROUTEPROTO_OIGP	    13

#define MIB_TCPRTOALG_OTHER	1
#define MIB_TCPRTOALG_CONSTANT	2
#define MIB_TCPRTOALG_RSRE	3
#define MIB_TCPRTOALG_VANJ	4

#define MIB_TCPCONNSTATE_CLOSED		1
#define MIB_TCPCONNSTATE_LISTEN		2
#define MIB_TCPCONNSTATE_SYNSENT	3
#define MIB_TCPCONNSTATE_SYNRECEIVED	4
#define MIB_TCPCONNSTATE_ESTABLISHED	5
#define MIB_TCPCONNSTATE_FINWAIT1	6
#define MIB_TCPCONNSTATE_FINWAIT2	7
#define MIB_TCPCONNSTATE_CLOSEWAIT	8
#define MIB_TCPCONNSTATE_LASTACK	9
#define MIB_TCPCONNSTATE_CLOSING	10
#define MIB_TCPCONNSTATE_TIMEWAIT	11

#define MIB_EGPNEIGHSTATE_IDLE		1
#define MIB_EGPNEIGHSTATE_AQUISITION	2
#define MIB_EGPNEIGHSTATE_DOWN		3
#define MIB_EGPNEIGHSTATE_UP		4
#define MIB_EGPNEIGHSTATE_CEASE		5



