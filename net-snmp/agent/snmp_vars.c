/*
 * snmp_vars.c - return a pointer to the named variable.
 *
 *
 */
/***********************************************************
	Copyright 1988, 1989, 1990 by Carnegie Mellon University
	Copyright 1989	TGV, Incorporated

		      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU and TGV not be used
in advertising or publicity pertaining to distribution of the software
without specific, written prior permission.

CMU AND TGV DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL CMU OR TGV BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF
USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
******************************************************************/

#define USE_NAME_AS_DESCRIPTION /*"se0" instead of text */
#define GATEWAY			/* MultiNet is always configured this way! */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
/* #include <sys/time.h> */
#include <sys/param.h>
#include <sys/dir.h>
#include <sys/user.h>
#include <sys/proc.h>
#include <sys/types.h>
/*
  #include <machine/pte.h>
  */
#include <sys/vm.h>
#include <netinet/in.h>
#include <syslog.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/route.h>
#include <netinet/in_pcb.h>
#include <netinet/if_ether.h>
#include <netinet/in_systm.h>
#ifndef sunV3
#include <netinet/in_var.h>
#endif
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_fsm.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp_var.h>
#include <nlist.h>
#include <sys/protosw.h>

#ifndef NULL
#define NULL 0
#endif
#ifndef  MIN
#define  MIN(a,b)                     (((a) < (b)) ? (a) : (b)) 
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "mib.h"
#include "snmp_vars.h"

#include "m2m.h"
#include "snmp_vars_m2m.h"
#include "alarm.h"
#include "event.h"

#define PROCESSSLOTINDEX  0
#define PROCESSID         4
#define PROCESSCOMMAND    8
 
#include "party.h"
#include "context.h"
#include "acl.h"
#include "view.h"

#ifdef vax11c
#define ioctl socket_ioctl
#define perror socket_perror
#endif vax11c

extern  int swap, mem;
extern char *Lookup_Device_Annotation();

#define  KNLookup(nl_which, buf, s)   (klookup((int) nl[nl_which].n_value, buf, s))


#define N_IPSTAT	0
#define N_IPFORWARDING	1
#define N_TCP_TTL	2
#define N_UDPSTAT	3
#define N_IN_INTERFACES 4
#define N_ICMPSTAT	5
#define N_IFNET		6
#define N_TCPSTAT	7
#define N_TCB		8
#define N_ARPTAB_SIZE	9
#define N_ARPTAB        10
#define N_IN_IFADDR     11
#define N_BOOTTIME	12
#define N_PROC		13
#define N_NPROC		14
#define N_DMMIN		15
#define N_DMMAX		16
#define N_NSWAP		17
#define N_USRPTMAP	18
#define N_USRPT		19

static struct nlist nl[] = {
#ifndef hpux
	{ "_ipstat"},  
	{ "_ipforwarding" },
	{ "_tcp_ttl"},
	{ "_udpstat" },
	{ "_in_interfaces" },
	{ "_icmpstat" },
	{ "_ifnet" },
	{ "_tcpstat" },
	{ "_tcb" },
	{ "arptab_size" }, 
	{ "arptab" },      
	{ "_in_ifaddr" },
	{ "_boottime" },
	{ "_proc" },
	{ "_nproc" },
	{ "_dmmin" },
	{ "_dmmax" },
	{ "_nswap" },
 	{ "_Usrptmap" },
	{ "_usrpt" },
#else
	{ "ipstat"},  
	{ "ipforwarding" },
	{ "tcpDefaultTTL"},
	{ "udpstat" },
	{ "in_interfaces" },
	{ "icmpstat" },
	{ "ifnet" },
	{ "tcpstat" },
	{ "tcb" },
	{ "arptab_nb" }, 
	{ "arphd" },      
	{ "in_ifaddr" },
	{ "boottime" },
	{ "proc" },
	{ "nproc" },
	{ "dmmin" },
	{ "dmmax" },
	{ "nswap" },
        { "mpid" },
        { "hz"},
#endif
#ifdef ibm032
#define N_USERSIZE	20
	{ "_userSIZE" },
#endif
	{ 0 },
};

/*
 *	Each variable name is placed in the variable table, without the
 * terminating substring that determines the instance of the variable.  When
 * a string is found that is lexicographicly preceded by the input string,
 * the function for that entry is called to find the method of access of the
 * instance of the named variable.  If that variable is not found, NULL is
 * returned, and the search through the table continues (it will probably
 * stop at the next entry).  If it is found, the function returns a character
 * pointer and a length or a function pointer.  The former is the address
 * of the operand, the latter is a write routine for the variable.
 *
 * u_char *
 * findVar(name, length, exact, var_len, write_method)
 * oid	    *name;	    IN/OUT - input name requested, output name found
 * int	    length;	    IN/OUT - number of sub-ids in the in and out oid's
 * int	    exact;	    IN - TRUE if an exact match was requested.
 * int	    len;	    OUT - length of variable or 0 if function returned.
 * int	    write_method;   OUT - pointer to function to set variable,
 *                                otherwise 0
 *
 *     The writeVar function is returned to handle row addition or complex
 * writes that require boundary checking or executing an action.
 * This routine will be called three times for each varbind in the packet.
 * The first time for each varbind, action is set to RESERVE1.  The type
 * and value should be checked during this pass.  If any other variables
 * in the MIB depend on this variable, this variable will be stored away
 * (but *not* committed!) in a place where it can be found by a call to
 * writeVar for a dependent variable, even in the same PDU.  During
 * the second pass, action is set to RESERVE2.  If this variable is dependent
 * on any other variables, it will check them now.  It must check to see
 * if any non-committed values have been stored for variables in the same
 * PDU that it depends on.  Sometimes resources will need to be reserved
 * in the first two passes to guarantee that the operation can proceed
 * during the third pass.  During the third pass, if there were no errors
 * in the first two passes, writeVar is called for every varbind with action
 * set to COMMIT.  It is now that the values should be written.  If there
 * were errors during the first two passes, writeVar is called in the third
 * pass once for each varbind, with the action set to FREE.  An opportunity
 * is thus provided to free those resources reserved in the first two passes.
 * 
 * writeVar(action, var_val, var_val_type, var_val_len, statP, name, name_len)
 * int	    action;	    IN - RESERVE1, RESERVE2, COMMIT, or FREE
 * u_char   *var_val;	    IN - input or output buffer space
 * u_char   var_val_type;   IN - type of input buffer
 * int	    var_val_len;    IN - input and output buffer len
 * u_char   *statP;	    IN - pointer to local statistic
 * oid      *name           IN - pointer to name requested
 * int      name_len        IN - number of sub-ids in the name
 */

long		long_return;
#ifndef ibm032
u_char		return_buf[258];  
#else
u_char		return_buf[256]; /* nee 64 */
#endif
 
init_snmp()
{
  int ret;
#ifdef hpux
  if ((ret = nlist("/hp-ux",nl)) == -1) {
    ERROR("nlist");
    exit(1);
  }
  for(ret = 0; nl[ret].n_name != NULL; ret++) {
    if (nl[ret].n_type == 0) {
      fprintf(stderr, "nlist err:  %s not found\n",nl[ret].n_name);
    }
  }
#else
  nlist("/vmunix",nl);
#endif
  init_kmem("/dev/kmem"); 
  init_routes();
}

#define CMUMIB 1, 3, 6, 1, 4, 1, 3
#define       CMUUNIXMIB  CMUMIB, 2, 2

#define SNMPV2 			1, 3, 6, 1, 6
#define SNMPV2M2M		SNMPV2, 3, 2
#define SNMPV2ALARMNEXTINDEX	SNMPV2M2M, 1, 1, 1
#define SNMPV2ALARMENTRY	SNMPV2M2M, 1, 1, 2, 1
#define SNMPV2EVENTNEXTINDEX	SNMPV2M2M, 1, 2, 1
#define SNMPV2EVENTENTRY	SNMPV2M2M, 1, 2, 2, 1
#define SNMPV2EVENTNOTIFYMININT	SNMPV2M2M, 1, 2, 3
#define SNMPV2EVENTNOTIFYMAXRET	SNMPV2M2M, 1, 2, 4
#define SNMPV2EVENTNOTIFYENTRY	SNMPV2M2M, 1, 2, 5, 1

#define SNMPV2ALARMEVENTS	SNMPV2M2M, 1, 1, 3

#define RMONMIB 1, 3, 6, 1, 2, 1, 16

#define HOST                    RMONMIB, 4
#define HOSTCONTROL             HOST, 1, 1                      /* hostControlEntry */
#define HOSTTAB                 HOST, 2, 1                      /* hostEntry */
#define HOSTTIMETAB             HOST, 3, 1                      /* hostTimeEntry */
#define HOSTTOPN                RMONMIB, 5
#define HOSTTOPNCONTROL HOSTTOPN, 1, 1          /* hostTopNControlEntry */
#define HOSTTOPNTAB             HOSTTOPN, 2, 1          /* hostTopNEntry */
#define HOSTTIMETABADDRESS                                      1
#define HOSTTIMETABCREATIONORDER                        2
#define HOSTTIMETABINDEX                                        3
#define HOSTTIMETABINPKTS                                       4
#define HOSTTIMETABOUTPKTS                                      5
#define HOSTTIMETABINOCTETS                                     6
#define HOSTTIMETABOUTOCTETS                            7
#define HOSTTIMETABOUTERRORS                            8
#define HOSTTIMETABOUTBCASTPKTS                         9
#define HOSTTIMETABOUTMCASTPKTS                         10

#if 0
#define RMONMIB 1, 3, 6, 1, 2, 1, 16

#define ALARM                   RMONMIB, 3
#define ALARMTAB                ALARM, 1, 1                 /* alarmEntry */
#define EVENT                   RMONMIB, 9
#define EVENTTAB                EVENT, 1, 1                 /* eventEntry */
#endif

#define PARTYMIB 	SNMPV2, 3, 3
#define PARTYTABLE	PARTYMIB, 2, 1, 1, 1
#define CONTEXTTABLE	PARTYMIB, 2, 2, 1, 1
#define ACLTABLE	PARTYMIB, 2, 3, 1, 1
#define VIEWTABLE	PARTYMIB, 2, 4, 1, 1

/* various OIDs that are needed throughout the agent */
Export oid alarmVariableOid[] = {SNMPV2ALARMENTRY, ALARMTABVARIABLE};
Export int alarmVariableOidLen = sizeof(alarmVariableOid) / sizeof(oid);
Export oid alarmSampleTypeOid[] = {SNMPV2ALARMENTRY, ALARMTABSAMPLETYPE};
Export int alarmSampleTypeOidLen = sizeof(alarmSampleTypeOid) / sizeof(oid);
Export oid alarmValueOid[] = {SNMPV2ALARMENTRY, ALARMTABVALUE};
Export int alarmValueOidLen = sizeof(alarmValueOid) / sizeof(oid);
Export oid alarmFallingThreshOid[] = {SNMPV2ALARMENTRY, ALARMTABFALLINGTHRESH};
Export int alarmFallingThreshOidLen = sizeof(alarmFallingThreshOid)/sizeof(oid);
Export oid alarmRisingThreshOid[] = {SNMPV2ALARMENTRY, ALARMTABRISINGTHRESH};
Export int alarmRisingThreshOidLen = sizeof(alarmRisingThreshOid)/sizeof(oid);

Export oid sysUpTimeOid[] = {1,3,6,1,2,1,1,3,0};
Export int sysUpTimeOidLen = sizeof(sysUpTimeOid)/sizeof(oid);
Export oid eventIdOid[] = {SNMPV2EVENTENTRY, EVENTTABID};
Export int eventIdOidLen = sizeof(eventIdOid)/sizeof(oid);
Export oid trapRisingAlarmOid[] = {SNMPV2ALARMEVENTS, 1};
Export int trapRisingAlarmOidLen = sizeof(trapRisingAlarmOidLen)/sizeof(oid);
Export oid trapFallingAlarmOid[] = {SNMPV2ALARMEVENTS, 2};
Export int trapFallingAlarmOidLen = sizeof(trapFallingAlarmOidLen)/sizeof(oid);
Export oid trapObjUnavailAlarmOid[] = {SNMPV2ALARMEVENTS, 3};
Export int trapObjUnavailAlarmOidLen = sizeof(trapObjUnavailAlarmOidLen)/sizeof(oid);


#include "var_struct.h"

/*
 * ##############################################################
 * IMPORTANT NOTE:
 * ##############################################################
 *
 * The format of the acl word in these entries has changed.  It is still
 * 2 bits per community, offset from the right by the index of the community.
 * The leftmost two bits denotes read access, and the rightmost denotes
 * write access.
 * The change is that the rightmost two bits are now reserved for the object's
 * max-access.  This is the minimum of what makes "protocol sense" for the
 * object and whether set support was implemented for that object.
 * These two bits will not map to any community.  The first community
 * entry will map to the 3rd and 4th bits.
 */

#define MTRBIGNUMBER	1
#define MTRNSAPADDRESS	2
#define MTRBITSTRING	3

struct variable2 demo_variables[] = {
    {MTRBIGNUMBER, COUNTER64, RONLY, var_demo, 1, {1}},
    {MTRNSAPADDRESS, NSAP, RONLY, var_demo, 1, {2}},
    {MTRBITSTRING, BITSTRING, RONLY, var_demo, 1, {3}}
};

struct variable4 interface_variables[] = {
    {IFNUMBER, INTEGER, RONLY, var_system, 1, {1}},
    {IFINDEX, INTEGER, RONLY, var_ifEntry, 3, {2, 1, 1}},
    {IFDESCR, STRING, RONLY, var_ifEntry, 3, {2, 1, 2}},
    {IFTYPE, INTEGER, RONLY, var_ifEntry, 3, {2, 1, 3}},
    {IFMTU, INTEGER, RONLY, var_ifEntry, 3, {2, 1, 4}},
    {IFSPEED, GAUGE, RONLY, var_ifEntry, 3, {2, 1, 5}},
    {IFPHYSADDRESS, STRING, RONLY, var_ifEntry, 3, {2, 1, 6}},
    {IFADMINSTATUS, INTEGER, RWRITE, var_ifEntry, 3, {2, 1, 7}},
    {IFOPERSTATUS, INTEGER, RONLY, var_ifEntry, 3, {2, 1, 8}},
    {IFLASTCHANGE, TIMETICKS, RONLY, var_ifEntry, 3, {2, 1, 9}},
    {IFINOCTETS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 10}},
    {IFINUCASTPKTS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 11}},
    {IFINNUCASTPKTS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 12}},
    {IFINDISCARDS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 13}},
    {IFINERRORS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 14}},
    {IFINUNKNOWNPROTOS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 15}},
    {IFOUTOCTETS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 16}},
    {IFOUTUCASTPKTS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 17}},
    {IFOUTNUCASTPKTS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 18}},
    {IFOUTDISCARDS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 19}},
    {IFOUTERRORS, COUNTER, RONLY, var_ifEntry, 3, {2, 1, 20}},
    {IFOUTQLEN, GAUGE, RONLY, var_ifEntry, 3, {2, 1, 21}}
};

struct variable2 system_variables[] = {
    {VERSION_DESCR, STRING, RWRITE, var_system, 1, {1}},
    {VERSION_ID, OBJID, RONLY, var_system, 1, {2}},
    {UPTIME, TIMETICKS, RONLY, var_system, 1, {3}},
    {SYSCONTACT, STRING, RWRITE, var_system, 1, {4}},
    {SYSNAME, STRING, RWRITE, var_system, 1, {5}},
    {SYSLOCATION, STRING, RWRITE, var_system, 1, {6}},
    {SYSSERVICES, INTEGER, RONLY, var_system, 1, {7}}
};

struct variable2 at_variables[] = {
    {ATIFINDEX, INTEGER, RONLY, var_atEntry, 1, {1}},
    {ATPHYSADDRESS, STRING, RONLY, var_atEntry, 1, {2}},
    {ATNETADDRESS, IPADDRESS, RONLY, var_atEntry, 1, {3}}
};

struct variable4 ip_variables[] = {
    {IPFORWARDING, INTEGER, RONLY, var_ip, 1, {1 }},
    {IPDEFAULTTTL, INTEGER, RONLY, var_ip, 1, {2 }},
#ifndef sunV3
    {IPINRECEIVES, COUNTER, RONLY, var_ip, 1, {3 }},
#endif
    {IPINHDRERRORS, COUNTER, RONLY, var_ip, 1, {4 }},
#ifndef sunV3
    {IPINADDRERRORS, COUNTER, RONLY, var_ip, 1, {5 }},
    {IPFORWDATAGRAMS, COUNTER, RONLY, var_ip, 1, {6 }},
#endif
    {IPINUNKNOWNPROTOS, COUNTER, RONLY, var_ip, 1, {7 }},
#ifndef sunV3
    {IPINDISCARDS, COUNTER, RONLY, var_ip, 1, {8 }},
    {IPINDELIVERS, COUNTER, RONLY, var_ip, 1, {9 }},
#endif
    {IPOUTREQUESTS, COUNTER, RONLY, var_ip, 1, {10 }},
    {IPOUTDISCARDS, COUNTER, RONLY, var_ip, 1, {11 }},
    {IPOUTNOROUTES, COUNTER, RONLY, var_ip, 1, {12 }},
    {IPREASMTIMEOUT, INTEGER, RONLY, var_ip, 1, {13 }},
#ifndef sunV3
    {IPREASMREQDS, COUNTER, RONLY, var_ip, 1, {14 }},
    {IPREASMOKS, COUNTER, RONLY, var_ip, 1, {15 }},
    {IPREASMFAILS, COUNTER, RONLY, var_ip, 1, {16 }},
#endif
    {IPFRAGOKS, COUNTER, RONLY, var_ip, 1, {17 }},
    {IPFRAGFAILS, COUNTER, RONLY, var_ip, 1, {18 }},
    {IPFRAGCREATES, COUNTER, RONLY, var_ip, 1, {19 }},
    {IPADADDR, IPADDRESS, RONLY, var_ipAddrEntry, 3, {20, 1, 1}},
    {IPADIFINDEX, INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 2}},
#ifndef sunV3
    {IPADNETMASK, IPADDRESS, RONLY, var_ipAddrEntry, 3, {20, 1, 3}},
#endif
    {IPADBCASTADDR, INTEGER, RONLY, var_ipAddrEntry, 3, {20, 1, 4}},
    {IPROUTEDEST, IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 1}},
    {IPROUTEIFINDEX, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 2}},
    {IPROUTEMETRIC1, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 3}},
    {IPROUTEMETRIC2, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 4}},
    {IPROUTEMETRIC3, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 5}},
    {IPROUTEMETRIC4, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 6}},
    {IPROUTENEXTHOP, IPADDRESS, RONLY, var_ipRouteEntry, 3, {21, 1, 7}},
    {IPROUTETYPE, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 8}},
    {IPROUTEPROTO, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 9}},
    {IPROUTEAGE, INTEGER, RONLY, var_ipRouteEntry, 3, {21, 1, 10}}
};

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

struct variable13 tcp_variables[] = {
    {TCPRTOALGORITHM, INTEGER, RONLY, var_tcp, 1, {1}},
    {TCPRTOMIN, INTEGER, RONLY, var_tcp, 1, {2}},
#ifndef sunV3
    {TCPRTOMAX, INTEGER, RONLY, var_tcp, 1, {3}},
#endif
    {TCPMAXCONN, INTEGER, RONLY, var_tcp, 1, {4}},
#ifndef sunV3
    {TCPACTIVEOPENS, COUNTER, RONLY, var_tcp, 1, {5}},
    {TCPPASSIVEOPENS, COUNTER, RONLY, var_tcp, 1, {6}},
    {TCPATTEMPTFAILS, COUNTER, RONLY, var_tcp, 1, {7}},
    {TCPESTABRESETS, COUNTER, RONLY, var_tcp, 1, {8}},
#endif
    {  TCPCURRESTAB, GAUGE, RONLY, var_tcp, 1, {9}},
#ifndef sunV3
    {TCPINSEGS, COUNTER, RONLY, var_tcp, 1, {10}},
    {TCPOUTSEGS, COUNTER, RONLY, var_tcp, 1, {11} },
    {TCPRETRANSSEGS, COUNTER, RONLY, var_tcp, 1, {12}},
#endif
    {TCPCONNSTATE, INTEGER, RONLY, var_tcp, 3, {13, 1, 1}},
    {TCPCONNLOCALADDRESS, IPADDRESS, RONLY, var_tcp, 3, {13, 1, 2}},
    {TCPCONNLOCALPORT, INTEGER, RONLY, var_tcp, 3, {13, 1, 3}},
    {TCPCONNREMADDRESS, IPADDRESS, RONLY, var_tcp, 3, {13, 1, 4}},
    {TCPCONNREMPORT, INTEGER, RONLY, var_tcp, 3, {13, 1, 5}}
};

struct variable2 udp_variables[] = {
    {UDPINDATAGRAMS, COUNTER, RONLY, var_udp, 1, {1}},
    {UDPNOPORTS, COUNTER, RONLY, var_udp, 1, {2}},
    {UDPINERRORS, COUNTER, RONLY, var_udp, 1, {3}},
    {UDPOUTDATAGRAMS, COUNTER, RONLY, var_udp, 1, {4}}
};

#ifndef hpux
#ifndef sparc
struct variable2 process_variables[] = {
    {PROCESSSLOTINDEX, INTEGER, RONLY, var_process, 1, {1}},
    {PROCESSID, INTEGER, RONLY, var_process, 1, {2}},
    {PROCESSCOMMAND, STRING, RONLY, var_process, 1, {3}}
};
#endif
#endif

/*
 * Note that the name field must be larger than any name that might
 * match that object.  For these variable length (objid) indexes
 * this might seem to be hard, but placing MAXINT in the first
 * subid of the index denotes an obcenely long objid, thereby ensuring that
 * none slip through.
 */
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

struct variable2 context_variables[] = {
    {CONTEXTINDEX, INTEGER, RONLY, var_context, 1, {2}},
    {CONTEXTLOCAL, INTEGER, RONLY, var_context, 1, {3}},
    {CONTEXTVIEWINDEX, INTEGER, RONLY, var_context, 1, {4}},
    {CONTEXTLOCALENTITY, STRING, RWRITE, var_context, 1, {5}},
    {CONTEXTLOCALTIME, OBJID, RWRITE, var_context, 1, {6}},
    {CONTEXTDSTPARTYINDEX, OBJID, RWRITE, var_context, 1, {7}},
    {CONTEXTSRCPARTYINDEX, OBJID, RWRITE, var_context, 1, {8}},
    {CONTEXTPROXYCONTEXT, OBJID, RWRITE, var_context, 1, {9}},
    {CONTEXTSTORAGETYPE, INTEGER, RWRITE, var_context, 1, {10}},
    {CONTEXTSTATUS, INTEGER, RWRITE, var_context, 1, {11}}
};

/* No access for community SNMP, RW possible for Secure SNMP */
#define PRIVRW   0x0003  
/* No access for community SNMP, RO possible for Secure SNMP */
#define PRIVRO   0x0002

struct variable2 acl_variables[] = {
    {ACLPRIVELEGES, INTEGER, PRIVRW, var_acl, 1, {4}},
    {ACLSTORAGETYPE, INTEGER, PRIVRW, var_acl, 1, {5}},
    {ACLSTATUS, INTEGER, PRIVRW, var_acl, 1, {6}}
};

struct variable2 view_variables[] = {
    {VIEWMASK, STRING, PRIVRW, var_view, 1, {3}},
    {VIEWTYPE, INTEGER, PRIVRW, var_view, 1, {4}},
    {VIEWSTORAGETYPE, INTEGER, PRIVRW, var_view, 1, {5}},
    {VIEWSTATUS, INTEGER, PRIVRW, var_view, 1, {6}}
};

u_char *var_hosttimetab();

struct variable2 hosttimetab_variables[] = {
        {HOSTTIMETABADDRESS, STRING, RONLY, var_hosttimetab, 1,
                {1 }},
        {HOSTTIMETABCREATIONORDER, INTEGER, RONLY, var_hosttimetab, 1,
                {2 }},
        {HOSTTIMETABINDEX, INTEGER, RONLY, var_hosttimetab, 1,
                {3 }},
        {HOSTTIMETABINPKTS, COUNTER, RONLY, var_hosttimetab, 1,
                {4 }},
        {HOSTTIMETABOUTPKTS, COUNTER, RONLY, var_hosttimetab, 1,
                {5 }},
        {HOSTTIMETABINOCTETS, COUNTER, RONLY, var_hosttimetab, 1,
                {6 }},
        {HOSTTIMETABOUTOCTETS, COUNTER, RONLY, var_hosttimetab, 1,
                {7 }},
        {HOSTTIMETABOUTERRORS, COUNTER, RONLY, var_hosttimetab, 1,
                {8}},
        {HOSTTIMETABOUTBCASTPKTS, COUNTER, RONLY, var_hosttimetab, 1,
                {9}},
        {HOSTTIMETABOUTMCASTPKTS, COUNTER, RONLY, var_hosttimetab, 1,
                {10}}
};

struct variable2 alarmnextindex_variables[] = {
    {ALARMNEXTINDEX, INTEGER, RONLY, var_alarmnextindex, 1, {0}}
};

struct variable2 alarm_variables[] = {
    {ALARMTABVARIABLE, OBJID, RWRITE, var_alarmtab, 1, {2 }},
    {ALARMTABINTERVAL, INTEGER, RWRITE, var_alarmtab, 1, {3 }},
    {ALARMTABSAMPLETYPE, INTEGER, RWRITE, var_alarmtab, 1, {4 }},
    {ALARMTABVALUE, INTEGER, RONLY, var_alarmtab, 1, {5 }},
    {ALARMTABSTARTUPALARM, INTEGER, RWRITE, var_alarmtab, 1, {6 }},
    {ALARMTABRISINGTHRESH, INTEGER, RWRITE, var_alarmtab, 1, {7 }},
    {ALARMTABFALLINGTHRESH, INTEGER, RWRITE, var_alarmtab, 1, {8 }},
    {ALARMTABRISINGINDEX, INTEGER, RWRITE, var_alarmtab, 1, {9}},
    {ALARMTABFALLINGINDEX, INTEGER, RWRITE, var_alarmtab, 1, {10 }},
    {ALARMTABUNAVAILABLEINDEX, INTEGER, RWRITE, var_alarmtab, 1, {11 }},
    {ALARMTABSTATUS, INTEGER, RWRITE, var_alarmtab, 1, {12 }}
};

struct variable2 eventnextindex_variables[] = {
    {EVENTNEXTINDEX, INTEGER, RONLY, var_eventnextindex, 1, {0}}
};

struct variable2 eventtab_variables[] = {
        {EVENTTABID, OBJID, RWRITE, var_eventtab, 1, {2 }},
        {EVENTTABDESCRIPTION, STRING, RWRITE, var_eventtab, 1, {3 }},
        {EVENTTABEVENTS, COUNTER, RONLY, var_eventtab, 1, {4 }},
        {EVENTTABLASTTIMESENT, TIMETICKS, RONLY, var_eventtab, 1, {5 }},
        {EVENTTABSTATUS, INTEGER, RWRITE, var_eventtab, 1, {6 }}
};

struct variable2 eventmininterval_variables[] = {
    {EVENTMININTERVAL, INTEGER, RONLY, var_eventnotifyvars, 1, {0}}
};

struct variable2 eventmaxretrans_variables[] = {
    {EVENTMAXRETRANS, INTEGER, RONLY, var_eventnotifyvars, 1, {0}}
};

struct variable2 eventnotifytab_variables[] = {
        {EVENTNOTIFYTABINTERVAL, INTEGER, RWRITE, var_eventnotifytab, 1, {1 }},
        {EVENTNOTIFYTABRETRANSMISSIONS, INTEGER, RWRITE, var_eventnotifytab, 1, {2 }},
        {EVENTNOTIFYTABLIFETIME, INTEGER, RWRITE, var_eventnotifytab, 1, {3 }},
        {EVENTNOTIFYTABSTATUS, INTEGER, RWRITE, var_eventnotifytab, 1, {4 }},
};

struct subtree subtrees[] = {
    {{MIB, 1}, 7, (struct variable *)system_variables,
	 sizeof(system_variables)/sizeof(*system_variables),
	 sizeof(*system_variables)},
    {{MIB, 2}, 7, (struct variable *)interface_variables,
	 sizeof(interface_variables)/sizeof(*interface_variables),
	 sizeof(*interface_variables)},
    {{MIB, 3, 1, 1}, 9, (struct variable *)at_variables,
	 sizeof(at_variables)/sizeof(*at_variables),
	 sizeof(*at_variables)},
    {{MIB, 4}, 7, (struct variable *)ip_variables,
	 sizeof(ip_variables)/sizeof(*ip_variables),
	 sizeof(*ip_variables)},
    {{MIB, 5}, 7, (struct variable *)icmp_variables,
	 sizeof(icmp_variables)/sizeof(*icmp_variables),
	 sizeof(*icmp_variables)},
    {{MIB, 6}, 7, (struct variable *)tcp_variables,
	 sizeof(tcp_variables)/sizeof(*tcp_variables),
	 sizeof(*tcp_variables)},
    {{MIB, 7}, 7, (struct variable *)udp_variables,
	 sizeof(udp_variables)/sizeof(*udp_variables),
	 sizeof(*udp_variables)},
#ifdef testing
    {{HOSTTIMETAB}, 10, (struct variable *)hosttimetab_variables,
	 sizeof(hosttimetab_variables) / sizeof(*hosttimetab_variables),
	 sizeof(*hosttimetab_variables)},
#endif
    {{SNMPV2ALARMNEXTINDEX}, 10, (struct variable *)alarmnextindex_variables,
	 sizeof(alarmnextindex_variables) / sizeof(*alarmnextindex_variables),
	 sizeof(*alarmnextindex_variables)},
    {{SNMPV2ALARMENTRY}, 11, (struct variable *)alarm_variables,
	 sizeof(alarm_variables) / sizeof(*alarm_variables),
	 sizeof(*alarm_variables)},
    {{SNMPV2EVENTNEXTINDEX}, 10, (struct variable *)eventnextindex_variables,
	 sizeof(eventnextindex_variables) / sizeof(*eventnextindex_variables),
	 sizeof(*eventnextindex_variables)},
    {{SNMPV2EVENTENTRY}, 11, (struct variable *)eventtab_variables,
	 sizeof(eventtab_variables) / sizeof(*eventtab_variables),
	 sizeof(*eventtab_variables)},
    {{SNMPV2EVENTNOTIFYMININT}, 10, (struct variable *)eventmininterval_variables,
	 sizeof(eventmininterval_variables) / sizeof(*eventmininterval_variables),
	 sizeof(*eventmininterval_variables)},
    {{SNMPV2EVENTNOTIFYMAXRET}, 10, (struct variable *)eventmaxretrans_variables,
	 sizeof(eventmaxretrans_variables) / sizeof(*eventmaxretrans_variables),
	 sizeof(*eventmaxretrans_variables)},
    {{SNMPV2EVENTNOTIFYENTRY}, 11, (struct variable *)eventnotifytab_variables,
	 sizeof(eventnotifytab_variables) / sizeof(*eventnotifytab_variables),
	 sizeof(*eventnotifytab_variables)},
    {{PARTYTABLE}, 11, (struct variable *)party_variables,
	 sizeof(party_variables)/sizeof(*party_variables),
	 sizeof(*party_variables)},
    {{CONTEXTTABLE}, 11, (struct variable *)context_variables,
	 sizeof(context_variables)/sizeof(*context_variables),
	 sizeof(*context_variables)},
    {{ACLTABLE}, 11, (struct variable *)acl_variables,
	 sizeof(acl_variables)/sizeof(*acl_variables),
	 sizeof(*acl_variables)},
    {{VIEWTABLE}, 11, (struct variable *)view_variables,
	 sizeof(view_variables)/sizeof(*view_variables),
	 sizeof(*view_variables)},
    {{2, 6, 6, 200, 5, 1}, 6, (struct variable *)demo_variables,
	 sizeof(demo_variables)/sizeof(*demo_variables),
	 sizeof(*demo_variables)}
};

extern int in_view();
/*
 * getStatPtr - return a pointer to the named variable, as well as it's
 * type, length, and access control list.
 *
 * If an exact match for the variable name exists, it is returned.  If not,
 * and exact is false, the next variable lexicographically after the
 * requested one is returned.
 *
 * If no appropriate variable can be found, NULL is returned.
 */
u_char	*
getStatPtr(name, namelen, type, len, acl, exact, write_method, pi,
	   noSuchObject)
    oid		*name;	    /* IN - name of var, OUT - name matched */
    int		*namelen;   /* IN -number of sub-ids in name, OUT - subid-is in matched name */
    u_char	*type;	    /* OUT - type of matched variable */
    int		*len;	    /* OUT - length of matched variable */
    u_short	*acl;	    /* OUT - access control list */
    int		exact;	    /* IN - TRUE if exact match wanted */
    int	       (**write_method)(); /* OUT - pointer to function called to set variable, otherwise 0 */
    struct packet_info *pi; /* IN - relevant auth info re PDU */
    int		*noSuchObject;
{
    register struct subtree	*tp;
    register struct variable *vp;
    struct variable	compat_var, *cvp = &compat_var;
    register int	x;
    int			y;
    register u_char	*access = NULL;
    int			result, treeresult;
    oid 		*suffix;
    int			suffixlen;
    int 		found = FALSE;
    oid			save[MAX_NAME_LEN];
    int			savelen;

    if (!exact){
	bcopy(name, save, *namelen * sizeof(oid));
	savelen = *namelen;
    }
    *write_method = NULL;
    for (y = 0, tp = subtrees; y < sizeof(subtrees)/sizeof(struct subtree);
	 tp++, y++){
	treeresult = compare_tree(name, *namelen, tp->name, (int)tp->namelen);
	/* if exact and treerresult == 0
	   if next  and treeresult <= 0 */
	if (treeresult == 0 || (!exact && treeresult < 0)){
	    result = treeresult;
	    suffixlen = *namelen - tp->namelen;
	    suffix = name + tp->namelen;
	    /* the following is part of the setup for the compatability
	       structure below that has been moved out of the main loop.
	     */
	    bcopy((char *)tp->name, (char *)cvp->name,
		  tp->namelen * sizeof(oid));

	    for(x = 0, vp = tp->variables; x < tp->variables_len;
		vp =(struct variable *)((char *)vp +tp->variables_width), x++){
		/* if exact and ALWAYS
		   if next  and result >= 0 */
		if (exact || result >= 0){
		    result = compare_tree(suffix, suffixlen, vp->name,
				     (int)vp->namelen);
		}
		/* if exact and result == 0
		   if next  and result <= 0 */
		if ((!exact && (result <= 0)) || (exact && (result == 0))){
		    /* builds an old (long) style variable structure to retain
		       compatability with var_* functions written previously.
		     */
		    bcopy((char *)vp->name, (char *)(cvp->name + tp->namelen),
			  vp->namelen * sizeof(oid));
		    cvp->namelen = tp->namelen + vp->namelen;
		    cvp->type = vp->type;
		    cvp->magic = vp->magic;
		    cvp->acl = vp->acl;
		    cvp->findVar = vp->findVar;
		    access = (*(vp->findVar))(cvp, name, namelen, exact,
						  len, write_method);
		    if (write_method)
			*acl = vp->acl;
		    if (access && (pi->version == SNMP_VERSION_2)
			&& !in_view(name, *namelen,
				    pi->cxp->contextViewIndex)){
			access = NULL;
			*write_method = NULL;
			/*
			  if (in_view(vp->name, vp->namelen,
			      pi->dstParty, pi->dstPartyLength)
			      found = TRUE;
			 */
		    } else if (exact){
			found = TRUE;
		    }
		    /* this code is incorrect if there is
		       a view configuration that exludes a particular
		       instance of a variable.  It would return noSuchObject,
		       which would be an error */
		    if (access != NULL)
			break;
		}
		/* if exact and result <= 0 */
		if (exact && (result  <= 0)){
	            *type = vp->type;
		    *acl = vp->acl;
		    if (found)
			*noSuchObject = FALSE;
		    else
			*noSuchObject = TRUE;
		    return NULL;
		}
	    }
	    if (access != NULL)
		break;
	}
    }
    if (y == sizeof(subtrees)/sizeof(struct subtree)){
	if (!access && !exact){
	    bcopy(save, name, savelen * sizeof(oid));
	    *namelen = savelen;
	}
	if (found)
	    *noSuchObject = FALSE;
	else
	    *noSuchObject = TRUE;
        return NULL;
    }
    /* vp now points to the approprate struct */
    *type = vp->type;
    *acl = vp->acl;
    return access;
}

/*
{
  *write_method = NULL;
  for(tp = first; tp < end; tp = next){
      if ((in matches tp) or (in < tp)){
	  inlen -= tp->length;
	  for(vp = tp->vp; vp < end; vp = next){
	      if ((in < vp) || (exact && (in == vp))){
		  cobble up compatable vp;
		  call findvar;
		  if (it returns nonzero)
		      break both loops;
	      }
	      if (exact && (in < vp)) ???
		  return NULL;
	  }
      }      
  }
}
*/

int
compare(name1, len1, name2, len2)
    register oid	    *name1, *name2;
    register int	    len1, len2;
{
    register int    len;

    /* len = minimum of len1 and len2 */
    if (len1 < len2)
	len = len1;
    else
	len = len2;
    /* find first non-matching byte */
    while(len-- > 0){
	if (*name1 < *name2)
	    return -1;
	if (*name2++ < *name1++)
	    return 1;
    }
    /* bytes match up to length of shorter string */
    if (len1 < len2)
	return -1;  /* name1 shorter, so it is "less" */
    if (len2 < len1)
	return 1;
    return 0;	/* both strings are equal */
}

int
compare_tree(name1, len1, name2, len2)
    register oid	    *name1, *name2;
    register int	    len1, len2;
{
    register int    len;

    /* len = minimum of len1 and len2 */
    if (len1 < len2)
	len = len1;
    else
	len = len2;
    /* find first non-matching byte */
    while(len-- > 0){
	if (*name1 < *name2)
	    return -1;
	if (*name2++ < *name1++)
	    return 1;
    }
    /* bytes match up to length of shorter string */
    if (len1 < len2)
	return -1;  /* name1 shorter, so it is "less" */
    /* name1 matches name2 for length of name2, or they are equal */
    return 0;
}


#ifdef hpux
char version_descr[128] = "HP-UX";
#else
char version_descr[128] = "Unknown";
#endif

char sysContact[128] = "Unknown";
char sysName[128] = "Unknown";
char sysLocation[128] = "Unknown";

#ifdef hpux
oid version_id[] = {1, 3, 6, 1, 4, 1, 11, 2, 3, 2, 5};
#else
oid version_id[] = {1, 3, 6, 1, 4, 1, 3, 1, 1};
#endif

u_long
sysUpTime(){
    struct timeval now, boottime;
    
    if (KNLookup(N_BOOTTIME, (char *)&boottime, sizeof(boottime)) == NULL) {
	return(0);
    }
    gettimeofday(&now, (struct timezone *)0);
    return (u_long) ((now.tv_sec - boottime.tv_sec) * 100
			    + (now.tv_usec - boottime.tv_usec) / 10000);
}

Export u_char *
var_hosttimetab(vp, name, length, exact, var_len, write_method)
        register struct variable *vp;   /* IN - pointer to variable entry that
                                                                        ** points here
                                                                        */
        register oid *name;             /* IN/OUT - input name requested,
                                                        ** output name found
                                                        */
        register int *length;   /* IN/OUT - length of input and output oid's */
        int exact;              /* IN - TRUE if an exact match was requested. */
        int *var_len;   /* OUT - length of variable or 0 if function returned. */
        int                     (**write_method)(); /* OUT - pointer to function to set
                                                                        ** variable, otherwise 0
                                                                        */
{
        oid newname[MAX_NAME_LEN];
        int result, zero = 0;
	int creationOrder;

        bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
        *write_method = 0;

	newname[vp->namelen] = (oid)1;

	if (exact){
	    creationOrder = name[vp->namelen + 1];
	    if (creationOrder > 2000)
		return NULL;
	    newname[vp->namelen + 1] = creationOrder;
	} else if (*length == vp->namelen + 2){
	    creationOrder = name[vp->namelen + 1] + 1;
	    if (creationOrder > 2000){
		if ((vp->name[vp->namelen - 1] != name[vp->namelen - 1])){
		    creationOrder = 1;
		} else {
		    return NULL;
		}
	    }
	    newname[vp->namelen + 1] = creationOrder;
	} else {
	    printf("Slow code\n");
	    creationOrder = 1;
	    while (creationOrder < 2000) {
		newname[vp->namelen + 1] = (oid)creationOrder++;
		result = compare(name, *length, newname, (int)vp->namelen + 2);
		if ((exact && (result == 0)) || (!exact && (result < 0))) {
		    break;
		}
	    }
	    if (creationOrder == 2002) {
                return NULL;
	    }
	}
        bcopy((char *)newname, (char *)name,
	      ((int)vp->namelen + 2) * sizeof(oid));
        *length = vp->namelen + 2;
        *var_len = sizeof(u_long);

        switch (vp->magic) {
                case HOSTTIMETABADDRESS:
/*                  *var_len = sizeof(struct ether_addr); */
                  *var_len = 6*sizeof(u_char);
                  return (u_char *) "RMONRULES";
                case HOSTTIMETABCREATIONORDER:
			long_return = creationOrder;
			return (u_char *) &long_return;
                case HOSTTIMETABINDEX:
                case HOSTTIMETABINPKTS:
                case HOSTTIMETABOUTPKTS:
                case HOSTTIMETABINOCTETS:
                case HOSTTIMETABOUTOCTETS:
                case HOSTTIMETABOUTERRORS:
                case HOSTTIMETABOUTBCASTPKTS:
                case HOSTTIMETABOUTMCASTPKTS:
                        return (u_char *) &zero;
                default:
                        ERROR("");
        }

        return NULL;
}

u_char *
var_system(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    extern int writeVersion(), writeSystem();
    oid newname[MAX_NAME_LEN];
    int result;

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[8] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
	return NULL;
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    switch (vp->magic){
	case VERSION_DESCR:
	    *var_len = strlen(version_descr);
	    *write_method = writeVersion;
	    return (u_char *)version_descr;
	case VERSION_ID:
	    *var_len = sizeof(version_id);
	    return (u_char *)version_id;
	case UPTIME:
	    long_return = (u_long)  sysUpTime();
	    return (u_char *)&long_return;
	case IFNUMBER:
	    long_return = Interface_Scan_Get_Count();
	    return (u_char *) &long_return;
	case SYSCONTACT:
	    *var_len = strlen(sysContact);
	    *write_method = writeSystem;
	    return (u_char *)sysContact;
        case SYSNAME:
	    *var_len = strlen(sysName);
	    *write_method = writeSystem;
	    return (u_char *)sysName;
        case SYSLOCATION:
	    *var_len = strlen(sysLocation);
	    *write_method = writeSystem;
	    return (u_char *)sysLocation;
	case SYSSERVICES:
	    long_return = 72;
	    return (u_char *)&long_return;
	default:
	    ERROR("");
    }
    return NULL;
}

u_char *
var_demo(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    oid newname[MAX_NAME_LEN];
    int result;
    static u_char bitstring[64] = {0, 0x83, 0};
    int bitstringlength = 3;
    static u_char nsap[128] = {0x14, 0x47, 0x00, 0x05, 0x80, 0xff, 0xff, 0x00,
				   0x00, 0x00, 0x01, 0x23, 0x01, 0x23, 0x01,
				   0x23, 0x45, 0x67, 0x89, 0xab, 0x01};
    int nsaplength = 21;
    static struct counter64 counter;

    counter.high = 0xFA202E75;
    counter.low = 0x4FE92915;

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[7] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
	return NULL;
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    switch (vp->magic){
	case MTRBITSTRING:
	    *var_len = bitstringlength;
	    return (u_char *)bitstring;
	case MTRNSAPADDRESS:
	    *var_len = nsaplength;
	    return (u_char *)nsap;
	case MTRBIGNUMBER:
	    *var_len = sizeof(counter);
	    return (u_char *) &counter;
	default:
	    ERROR("");
    }
    return NULL;
}

#include <ctype.h>
int
writeVersion(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
    int bigsize = 1000;
    u_char buf[sizeof(version_descr)], *cp;
    int count, size;

    if (var_val_type != STRING){
	printf("not string\n");
	return SNMP_ERR_WRONGTYPE;
    }
    if (var_val_len > sizeof(version_descr)-1){
	printf("bad length\n");
	return SNMP_ERR_WRONGLENGTH;
    }
    size = sizeof(buf);
    asn_parse_string(var_val, &bigsize, &var_val_type, buf, &size);
    for(cp = buf, count = 0; count < size; count++, cp++){
	if (!isprint(*cp)){
	    printf("not print %x\n", *cp);
	    return SNMP_ERR_WRONGVALUE;
	}
    }
    buf[size] = 0;
    if (action == COMMIT){
	strcpy(version_descr, buf);
	
    }
    return SNMP_ERR_NOERROR;
}


int
writeSystem(action, var_val, var_val_type, var_val_len, statP, name, name_len)
   int      action;
   u_char   *var_val;
   u_char   var_val_type;
   int      var_val_len;
   u_char   *statP;
   oid      *name;
   int      name_len;
{
    int bigsize = 1000;
    u_char buf[sizeof(version_descr)], *cp;
    int count, size;

    if (var_val_type != STRING){
	printf("not string\n");
	return SNMP_ERR_WRONGTYPE;
    }
    if (var_val_len > sizeof(version_descr)-1){
	printf("bad length\n");
	return SNMP_ERR_WRONGLENGTH;
    }
    size = sizeof(buf);
    asn_parse_string(var_val, &bigsize, &var_val_type, buf, &size);
    for(cp = buf, count = 0; count < size; count++, cp++){
	if (!isprint(*cp)){
	    printf("not print %x\n", *cp);
	    return SNMP_ERR_WRONGVALUE;
	}
    }
    buf[size] = 0;
    if (action == COMMIT){
	switch((char)name[7]){
	  case 1:
	    strcpy(version_descr, buf);
	    break;
	  case 4:
	    strcpy(sysContact, buf);
	    break;
	  case 5:
	    strcpy(sysName, buf);
	    break;
	  case 6:
	    strcpy(sysLocation, buf);
	    break;
	}
    }
    return SNMP_ERR_NOERROR;
}


u_char *
var_ifEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    oid			newname[MAX_NAME_LEN];
    register int	interface;
    int result, count;
    static struct ifnet ifnet;
#ifndef sunV3
    static struct in_ifaddr in_ifaddr;
#endif sunV3
    static char Name[16];
    register char *cp;

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    /* find "next" interface */
    count = Interface_Scan_Get_Count();
    for(interface = 1; interface <= count; interface++){
	newname[10] = (oid)interface;
	result = compare(name, *length, newname, (int)vp->namelen + 1);
	if ((exact && (result == 0)) || (!exact && (result < 0)))
	    break;
    }
    if (interface > count)
	return NULL;

    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);

#ifdef sunV3
    Interface_Scan_By_Index(interface, Name, &ifnet);   
#else 
    Interface_Scan_By_Index(interface, Name, &ifnet, &in_ifaddr);
#endif
    switch (vp->magic){
	case IFINDEX:
	    long_return = interface;
	    return (u_char *) &long_return;
	case IFDESCR:
#define USE_NAME_AS_DESCRIPTION
#ifdef USE_NAME_AS_DESCRIPTION
	    cp = Name;
#else  USE_NAME_AS_DESCRIPTION
	    cp = Lookup_Device_Annotation(Name, "snmp-descr");
	    if (!cp)
		cp = Lookup_Device_Annotation(Name, 0);
	    if (!cp) cp = Name;
#endif USE_NAME_AS_DESCRIPTION
	    *var_len = strlen(cp);
	    return (u_char *)cp;
	case IFTYPE:
#if 0
	    cp = Lookup_Device_Annotation(Name, "snmp-type");
	    if (cp) long_return = atoi(cp);
	    else
#endif
		long_return = 1;	/* OTHER */
	    return (u_char *) &long_return;
	case IFMTU: {
	    long_return = (long) ifnet.if_mtu;
	    return (u_char *) &long_return;
	}
	case IFSPEED:
#if 0
	    cp = Lookup_Device_Annotation(Name, "snmp-speed");
	    if (cp) long_return = atoi(cp);
	    else
#endif
	    long_return = (u_long)  1;	/* OTHER */
	    return (u_char *) &long_return;
	case IFPHYSADDRESS:
#if 0
	    if (Lookup_Device_Annotation(Name, "ethernet-device")) {
		Interface_Get_Ether_By_Index(interface, return_buf);
		*var_len = 6;
		return(u_char *) return_buf;
	    } else {
		long_return = 0;
		return (u_char *) long_return;
	    }
#endif
		Interface_Get_Ether_By_Index(interface, return_buf);
		*var_len = 6;
		return(u_char *) return_buf;
	case IFADMINSTATUS:
	    long_return = ifnet.if_flags & IFF_RUNNING ? 1 : 2;
	    return (u_char *) &long_return;
	case IFOPERSTATUS:
	    long_return = ifnet.if_flags & IFF_UP ? 1 : 2;
	    return (u_char *) &long_return;
	case IFLASTCHANGE:
	    long_return = 0; /* XXX */
	    return (u_char *) &long_return;
	case IFINOCTETS:
	    long_return = (u_long)  ifnet.if_ipackets * 308; /* XXX */
	    return (u_char *) &long_return;
	case IFINUCASTPKTS:
	    long_return = (u_long)  ifnet.if_ipackets;
	    return (u_char *) &long_return;
	case IFINNUCASTPKTS:
	    long_return = (u_long)  0; /* XXX */
	    return (u_char *) &long_return;
	case IFINDISCARDS:
	    long_return = (u_long)  0; /* XXX */
	    return (u_char *) &long_return;
	case IFINERRORS:
	    return (u_char *) &ifnet.if_ierrors;
	case IFINUNKNOWNPROTOS:
	    long_return = (u_long)  0; /* XXX */
	    return (u_char *) &long_return;
	case IFOUTOCTETS:
	    long_return = (u_long)  ifnet.if_opackets * 308; /* XXX */
	    return (u_char *) &long_return;
	case IFOUTUCASTPKTS:
	    long_return = (u_long)  ifnet.if_opackets;
	    return (u_char *) &long_return;
	case IFOUTNUCASTPKTS:
	    long_return = (u_long)  0; /* XXX */
	    return (u_char *) &long_return;
	case IFOUTDISCARDS:
	    return (u_char *) &ifnet.if_snd.ifq_drops;
	case IFOUTERRORS:
	    return (u_char *) &ifnet.if_oerrors;
	case IFOUTQLEN:
	    return (u_char *) &ifnet.if_snd.ifq_len;
	default:
	    ERROR("");
    }
    return NULL;
}

/*
 * Read the ARP table
 */

u_char *
var_atEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;	/* IN - pointer to variable entry that points here */
    register oid	    *name;	/* IN/OUT - input name requested, output name found */
    register int	    *length;	/* IN/OUT - length of input and output oid's */
    int			    exact;	/* IN - TRUE if an exact match was requested. */
    int			    *var_len;	/* OUT - length of variable or 0 if function returned. */
    int			    (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.3.1.1.1.interface.1.A.B.C.D,  where A.B.C.D is IP address.
     * Interface is at offset 10,
     * IPADDR starts at offset 12.
     */
    u_char		    *cp;
    oid			    *op;
    oid			    lowest[16];
    oid			    current[16];
    static char		    PhysAddr[6], LowPhysAddr[6];
    u_long		    Addr, LowAddr;

    /* fill in object part of name for current (less sizeof instance part) */

    bcopy((char *)vp->name, (char *)current, (int)vp->namelen * sizeof(oid));

    LowAddr = -1;      /* Don't have one yet */
    ARP_Scan_Init();
    for (;;) {
	if (ARP_Scan_Next(&Addr, PhysAddr) == 0) break;
	current[10] = 1;	/* IfIndex == 1 (ethernet???) XXX */
	current[11] = 1;
	cp = (u_char *)&Addr;
	op = current + 12;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;

	if (exact){
	    if (compare(current, 16, name, *length) == 0){
		bcopy((char *)current, (char *)lowest, 16 * sizeof(oid));
		LowAddr = Addr;
		bcopy(PhysAddr, LowPhysAddr, sizeof(PhysAddr));
		break;	/* no need to search further */
	    }
	} else {
	    if ((compare(current, 16, name, *length) > 0) &&
		 ((LowAddr == -1) || (compare(current, 16, lowest, 16) < 0))){
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, save this one as the "next" one.
		 */
		bcopy((char *)current, (char *)lowest, 16 * sizeof(oid));
		LowAddr = Addr;
		bcopy(PhysAddr, LowPhysAddr, sizeof(PhysAddr));
	    }
	}
    }
    if (LowAddr == -1) return(NULL);

    bcopy((char *)lowest, (char *)name, 16 * sizeof(oid));
    *length = 16;
    *write_method = 0;
    switch(vp->magic){
	case ATIFINDEX:
	    *var_len = sizeof long_return;
	    long_return = 1; /* XXX */
	    return (u_char *)&long_return;
	case ATPHYSADDRESS:
	    *var_len = sizeof(LowPhysAddr);
	    return (u_char *)LowPhysAddr;
	case ATNETADDRESS:
	    *var_len = sizeof long_return;
	    long_return = LowAddr;
	    return (u_char *)&long_return;
	default:
	    ERROR("");
   }
   return NULL;
}

u_char *
var_ip(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    static struct ipstat ipstat;
    oid newname[MAX_NAME_LEN];
    int result, i;

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[8] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
	return NULL;
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    /*
     *	Get the IP statistics from the kernel...
     */

    KNLookup(N_IPSTAT, (char *)&ipstat, sizeof (ipstat));

    switch (vp->magic){
	case IPFORWARDING:
#ifndef sparc	  
	    KNLookup( N_IPFORWARDING, (char *) &i, sizeof(i));
	    fflush(stderr);
	    if (i) {
		long_return = 1;		/* GATEWAY */
	    } else {
		long_return = 2;	    /* HOST    */
	    }
#else
	    long_return = 0;
#endif

	    return (u_char *) &long_return;
	case IPDEFAULTTTL:
	    /*
	     *	Allow for a kernel w/o TCP.
	     */
	    if (nl[N_TCP_TTL].n_value) {
		KNLookup( N_TCP_TTL, (char *) &long_return, sizeof(long_return));
	    } else long_return = 60;	    /* XXX */
	    return (u_char *) &long_return;
	case IPINRECEIVES:
	    return (u_char *) &ipstat.ips_total;
	case IPINHDRERRORS:
	    long_return = ipstat.ips_badsum + ipstat.ips_tooshort +
			  ipstat.ips_toosmall + ipstat.ips_badhlen +
			  ipstat.ips_badlen;
	    return (u_char *) &long_return;
	case IPINADDRERRORS:
	    return (u_char *) &ipstat.ips_cantforward;

	case IPFORWDATAGRAMS:
	    return (u_char *) &ipstat.ips_forward;

	case IPINUNKNOWNPROTOS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPINDISCARDS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPINDELIVERS:

	    long_return = ipstat.ips_total -
			 (ipstat.ips_badsum + ipstat.ips_tooshort +
			  ipstat.ips_toosmall + ipstat.ips_badhlen +
			  ipstat.ips_badlen);
	    return (u_char *) &long_return;

	case IPOUTREQUESTS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPOUTDISCARDS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPOUTNOROUTES:
	    return (u_char *) &ipstat.ips_cantforward;

	case IPREASMTIMEOUT:
	    long_return = IPFRAGTTL;
	    return (u_char *) &long_return;
	case IPREASMREQDS:
	    return (u_char *) &ipstat.ips_fragments;

	case IPREASMOKS:
	    return (u_char *) &ipstat.ips_fragments;

	case IPREASMFAILS:
	    long_return = ipstat.ips_fragdropped + ipstat.ips_fragtimeout;
	    return (u_char *) &long_return;

	case IPFRAGOKS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPFRAGFAILS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case IPFRAGCREATES:
	    long_return = 0;
	    return (u_char *) &long_return;
	default:
	    ERROR("");
    }
    return NULL;
}



u_char *
var_ipAddrEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    /*
     * object identifier is of form:
     * 1.3.6.1.2.1.4.20.1.?.A.B.C.D,  where A.B.C.D is IP address.
     * IPADDR starts at offset 10.
     */
    oid			    lowest[14];
    oid			    current[14], *op;
    u_char		    *cp;
    int			    interface, lowinterface=0;
    static struct ifnet ifnet, lowin_ifnet;
#ifndef sunV3
    static struct in_ifaddr in_ifaddr, lowin_ifaddr;
#endif sunV3

    /* fill in object part of name for current (less sizeof instance part) */

    bcopy((char *)vp->name, (char *)current, (int)vp->namelen * sizeof(oid));

    Interface_Scan_Init();
    for (;;) {

#ifdef sunV3
	if (Interface_Scan_Next(&interface, (char *)0, &ifnet) == 0) break;
	cp = (u_char *)&(((struct sockaddr_in *) &(ifnet.if_addr))->sin_addr.s_addr);
#else
	if (Interface_Scan_Next(&interface, (char *)0, &ifnet, &in_ifaddr) == 0) break;
	cp = (u_char *)&(((struct sockaddr_in *) &(in_ifaddr.ia_addr))->sin_addr.s_addr);
#endif

	op = current + 10;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	*op++ = *cp++;
	if (exact){
	    if (compare(current, 14, name, *length) == 0){
		bcopy((char *)current, (char *)lowest, 14 * sizeof(oid));
		lowinterface = interface;
#ifdef sunV3
		lowin_ifnet = ifnet;
#else
		lowin_ifaddr = in_ifaddr;
#endif
		break;	/* no need to search further */
	    }
	} else {
	    if ((compare(current, 14, name, *length) > 0) &&
		 (!lowinterface || (compare(current, 14, lowest, 14) < 0))){
		/*
		 * if new one is greater than input and closer to input than
		 * previous lowest, save this one as the "next" one.
		 */
		lowinterface = interface;
#ifdef sunV3
		lowin_ifnet = ifnet;
#else
		lowin_ifaddr = in_ifaddr;
#endif
		bcopy((char *)current, (char *)lowest, 14 * sizeof(oid));
	    }
	}
    }

    if (!lowinterface) return(NULL);
    bcopy((char *)lowest, (char *)name, 14 * sizeof(oid));
    *length = 14;
    *write_method = 0;
    *var_len = sizeof(long_return);
    switch(vp->magic){
	case IPADADDR:
#ifdef sunV3
            return(u_char *) &((struct sockaddr_in *) &lowin_ifnet.if_addr)->sin_addr.s_addr;
#else
	    return(u_char *) &((struct sockaddr_in *) &lowin_ifaddr.ia_addr)->sin_addr.s_addr;
#endif
	case IPADIFINDEX:
	    long_return = lowinterface;
	    return(u_char *) &long_return;
	case IPADNETMASK:
#ifndef sunV3
	    long_return = ntohl(lowin_ifaddr.ia_subnetmask);
#endif
	    return(u_char *) &long_return;
	case IPADBCASTADDR:
	    
#ifdef sunV3
	    long_return = ntohl(((struct sockaddr_in *) &lowin_ifnet.ifu_broadaddr)->sin_addr.s_addr) & 1;
#else
	    long_return = ntohl(((struct sockaddr_in *) &lowin_ifaddr.ia_addr)->sin_addr.s_addr) & 1;
#endif
	    return(u_char *) &long_return;	   
	default:
	    ERROR("");
    }
    return NULL;
}


u_char *
var_icmp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    register int i;
    static struct icmpstat icmpstat;
    oid newname[MAX_NAME_LEN];
    int result;

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[8] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return NULL;
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long); /* all following variables are sizeof long */

    /*
     *	Get the UDP statistics from the kernel...
     */

    KNLookup( N_ICMPSTAT, (char *)&icmpstat, sizeof (icmpstat));

    switch (vp->magic){
	case ICMPINMSGS:
	    long_return = icmpstat.icps_badcode + icmpstat.icps_tooshort +
			  icmpstat.icps_checksum + icmpstat.icps_badlen;
	    for (i=0; i <= ICMP_MAXTYPE; i++)
		long_return += icmpstat.icps_inhist[i];
	    return (u_char *)&long_return;
	case ICMPINERRORS:
	    long_return = icmpstat.icps_badcode + icmpstat.icps_tooshort +
			  icmpstat.icps_checksum + icmpstat.icps_badlen;
	    return (u_char *)&long_return;
	case ICMPINDESTUNREACHS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_UNREACH];
	case ICMPINTIMEEXCDS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_TIMXCEED];
	case ICMPINPARMPROBS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_PARAMPROB];
	case ICMPINSRCQUENCHS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_SOURCEQUENCH];
	case ICMPINREDIRECTS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_REDIRECT];
	case ICMPINECHOS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_ECHO];
	case ICMPINECHOREPS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_ECHOREPLY];
	case ICMPINTIMESTAMPS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_TSTAMP];
	case ICMPINTIMESTAMPREPS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_TSTAMPREPLY];
	case ICMPINADDRMASKS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_MASKREQ];
	case ICMPINADDRMASKREPS:
	    return (u_char *) &icmpstat.icps_inhist[ICMP_MASKREPLY];
	case ICMPOUTMSGS:
	    long_return = icmpstat.icps_oldshort + icmpstat.icps_oldicmp;
	    for (i=0; i <= ICMP_MAXTYPE; i++)
		long_return += icmpstat.icps_outhist[i];
	    return (u_char *)&long_return;
	case ICMPOUTERRORS:
	    long_return = icmpstat.icps_oldshort + icmpstat.icps_oldicmp;
	    return (u_char *)&long_return;
	case ICMPOUTDESTUNREACHS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_UNREACH];
	case ICMPOUTTIMEEXCDS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_TIMXCEED];
	case ICMPOUTPARMPROBS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_PARAMPROB];
	case ICMPOUTSRCQUENCHS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_SOURCEQUENCH];
	case ICMPOUTREDIRECTS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_REDIRECT];
	case ICMPOUTECHOS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_ECHO];
	case ICMPOUTECHOREPS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_ECHOREPLY];
	case ICMPOUTTIMESTAMPS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_TSTAMP];
	case ICMPOUTTIMESTAMPREPS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_TSTAMPREPLY];
	case ICMPOUTADDRMASKS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_MASKREQ];
	case ICMPOUTADDRMASKREPS:
	    return (u_char *) &icmpstat.icps_outhist[ICMP_MASKREPLY];
	default:
	    ERROR("");
    }
    return NULL;
}


u_char *
var_udp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    static struct udpstat udpstat;
    oid newname[MAX_NAME_LEN];
    int result;

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[8] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return NULL;
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default length */
    /*
     *	Get the IP statistics from the kernel...
     */

    KNLookup( N_UDPSTAT, (char *)&udpstat, sizeof (udpstat));

    switch (vp->magic){
	case UDPINDATAGRAMS:
	case UDPNOPORTS:
	case UDPOUTDATAGRAMS:
	    long_return = 0;
	    return (u_char *) &long_return;
	case UDPINERRORS:
	    long_return = udpstat.udps_hdrops + udpstat.udps_badsum +
			  udpstat.udps_badlen;
	    return (u_char *) &long_return;
	default:
	    ERROR("");
    }
    return NULL;
}

u_char *
var_tcp(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    int i;
    static struct tcpstat tcpstat;
    oid newname[MAX_NAME_LEN], lowest[MAX_NAME_LEN], *op;
    u_char *cp;
    int State, LowState;
    static struct inpcb inpcb, Lowinpcb;
    int result;

    /*
     *	Allow for a kernel w/o TCP
     */

    if (nl[N_TCPSTAT].n_value == 0) return(NULL);

    if (vp->magic < TCPCONNSTATE) {

	bcopy((char *)vp->name, (char *)newname,
	      (int)vp->namelen * sizeof(oid));
	newname[8] = 0;
	result = compare(name, *length, newname, (int)vp->namelen + 1);
	if ((exact && (result != 0)) || (!exact && (result >= 0)))
	    return NULL;
	bcopy((char *)newname, (char *)name,
	      ((int)vp->namelen + 1) * sizeof(oid));
	*length = vp->namelen + 1;

	*write_method = 0;
	*var_len = sizeof(long);    /* default length */
	/*
	 *  Get the TCP statistics from the kernel...
	 */

	KNLookup( N_TCPSTAT, (char *)&tcpstat, sizeof (tcpstat));

	switch (vp->magic){
	    case TCPRTOALGORITHM:
		long_return = 4;	/* Van Jacobsen's algorithm */	/* XXX */
		return (u_char *) &long_return;
	    case TCPRTOMIN:
		long_return = TCPTV_MIN / PR_SLOWHZ * 1000;
		return (u_char *) &long_return;
	    case TCPRTOMAX:
		long_return = TCPTV_REXMTMAX / PR_SLOWHZ * 1000;

		return (u_char *) &long_return;
	    case TCPMAXCONN:
		long_return = -1;
		return (u_char *) &long_return;
	    case TCPACTIVEOPENS:

		return (u_char *) &tcpstat.tcps_connattempt;

	    case TCPPASSIVEOPENS:

		return (u_char *) &tcpstat.tcps_accepts;

	    case TCPATTEMPTFAILS:
		return (u_char *) &tcpstat.tcps_conndrops;

	    case TCPESTABRESETS:
		return (u_char *) &tcpstat.tcps_drops;

	    case TCPCURRESTAB:
		long_return = TCP_Count_Connections();
		return (u_char *) &long_return;
	    case TCPINSEGS:
		return (u_char *) &tcpstat.tcps_rcvtotal;

	    case TCPOUTSEGS:
		return (u_char *) &tcpstat.tcps_sndtotal;
	    case TCPRETRANSSEGS:
		return (u_char *) &tcpstat.tcps_sndrexmitpack;
	    default:
		ERROR("");
	}
    } else {	/* Info about a particular connection */
	bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
	/* find "next" connection */
Again:
LowState = -1;	    /* Don't have one yet */
	TCP_Scan_Init();
	for (;;) {
	    if ((i = TCP_Scan_Next(&State, &inpcb)) < 0) goto Again;
	    if (i == 0) break;	    /* Done */
	    cp = (u_char *)&inpcb.inp_laddr.s_addr;
	    op = newname + 10;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    
	    newname[14] = ntohs(inpcb.inp_lport);

	    cp = (u_char *)&inpcb.inp_faddr.s_addr;
	    op = newname + 15;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    *op++ = *cp++;
	    
	    newname[19] = ntohs(inpcb.inp_fport);

	    if (exact){
		if (compare(newname, 20, name, *length) == 0){
		    bcopy((char *)newname, (char *)lowest, 20 * sizeof(oid));
		    LowState = State;
		    Lowinpcb = inpcb;
		    break;  /* no need to search further */
		}
	    } else {
		if ((compare(newname, 20, name, *length) > 0) &&
		     ((LowState < 0) || (compare(newname, 20, lowest, 20) < 0))){
		    /*
		     * if new one is greater than input and closer to input than
		     * previous lowest, save this one as the "next" one.
		     */
		    bcopy((char *)newname, (char *)lowest, 20 * sizeof(oid));
		    LowState = State;
		    Lowinpcb = inpcb;
		}
	    }
	}
	if (LowState < 0) return(NULL);
	bcopy((char *)lowest, (char *)name, ((int)vp->namelen + 10) * sizeof(oid));
	*length = vp->namelen + 10;
	*write_method = 0;
	*var_len = sizeof(long);
	switch (vp->magic) {
	    case TCPCONNSTATE: {
		static int StateMap[]={1, 2, 3, 4, 5, 8, 6, 10, 9, 7, 11};
		return (u_char *) &StateMap[LowState];
	    }
	    case TCPCONNLOCALADDRESS:
		return (u_char *) &Lowinpcb.inp_laddr.s_addr;
	    case TCPCONNLOCALPORT:
		long_return = ntohs(Lowinpcb.inp_lport);
		return (u_char *) &long_return;
	    case TCPCONNREMADDRESS:
		return (u_char *) &Lowinpcb.inp_faddr.s_addr;
	    case TCPCONNREMPORT:
		long_return = ntohs(Lowinpcb.inp_fport);
		return (u_char *) &long_return;
	}
    }
    return NULL;
}

/*
 *	Print INTERNET connections
 */

static int TCP_Count_Connections()
{
	int Established;
	struct inpcb cb;
	register struct inpcb *prev, *next;
	struct inpcb inpcb;
	struct tcpcb tcpcb;

Again:	/*
	 *	Prepare to scan the control blocks
	 */
	Established = 0;

	KNLookup( N_TCB, (char *)&cb, sizeof(struct inpcb));
	inpcb = cb;
	prev = (struct inpcb *) nl[N_TCB].n_value;
	/*
	 *	Scan the control blocks
	 */
	while (inpcb.inp_next != (struct inpcb *) nl[N_TCB].n_value) {
		next = inpcb.inp_next;

		klookup( (int)next, (char *)&inpcb, sizeof (inpcb));
		if (inpcb.inp_prev != prev) {	    /* ??? */
			sleep(1);
			goto Again;
		}
		if (inet_lnaof(inpcb.inp_laddr) == INADDR_ANY) {
			prev = next;
			continue;
		}
		klookup( (int)inpcb.inp_ppcb, (char *)&tcpcb, sizeof (tcpcb));

		if ((tcpcb.t_state == TCPS_ESTABLISHED) ||
		    (tcpcb.t_state == TCPS_CLOSE_WAIT))
		    Established++;
		prev = next;
	}
	return(Established);
}


static struct inpcb inpcb, *prev;

static TCP_Scan_Init()
{
    KNLookup( N_TCB, (char *)&inpcb, sizeof(inpcb));
    prev = (struct inpcb *) nl[N_TCB].n_value;
}

static int TCP_Scan_Next(State, RetInPcb)
int *State;
struct inpcb *RetInPcb;
{
	register struct inpcb *next;
	struct tcpcb tcpcb;

	if (inpcb.inp_next == (struct inpcb *) nl[N_TCB].n_value) {
	    return(0);	    /* "EOF" */
	}

	next = inpcb.inp_next;

	klookup( (int)next, (char *)&inpcb, sizeof (inpcb));
	if (inpcb.inp_prev != prev)	   /* ??? */
		return(-1); /* "FAILURE" */

	klookup ( (int)inpcb.inp_ppcb, (char *)&tcpcb, sizeof (tcpcb));
	*State = tcpcb.t_state;
	*RetInPcb = inpcb;
	prev = next;
	return(1);	/* "OK" */
}

static int arptab_size, arptab_current;
static struct arptab *at=0;
static ARP_Scan_Init()
{
	extern char *malloc();

	if (!at) {
	    KNLookup( N_ARPTAB_SIZE, (char *)&arptab_size, sizeof arptab_size);
	    at = (struct arptab *) malloc(arptab_size * sizeof(struct arptab));
	}

	KNLookup( N_ARPTAB, (char *)at, arptab_size * sizeof(struct arptab));
	arptab_current = 0;
}

static int ARP_Scan_Next(IPAddr, PhysAddr)
u_long *IPAddr;
char *PhysAddr;
{
	register struct arptab *atab;

	while (arptab_current < arptab_size) {
		atab = &at[arptab_current++];
		if (!(atab->at_flags & ATF_COM)) continue;
		*IPAddr = atab->at_iaddr.s_addr;
#if defined (sunV3) || defined(sparc)
		bcopy((char *) &atab->at_enaddr, PhysAddr, sizeof(atab->at_enaddr));
#endif
#if defined(mips) || defined(ibm032) 
		bcopy((char *)  atab->at_enaddr, PhysAddr, sizeof(atab->at_enaddr));
#endif
	return(1);
	}
	return(0);	    /* "EOF" */
}


#ifndef sunV3
static struct in_ifaddr savein_ifaddr;
#endif
static struct ifnet *ifnetaddr, saveifnet, *saveifnetaddr;
static int saveIndex=0;
static char saveName[16];

Interface_Scan_Init()
{
    KNLookup (N_IFNET, (char *)&ifnetaddr, sizeof(ifnetaddr));
    saveIndex=0;
}



#ifdef sunV3
/*
**  4.2 BSD doesn't have ifaddr
**  
*/
int Interface_Scan_Next(Index, Name, Retifnet)
int *Index;
char *Name;
struct ifnet *Retifnet;
{
	struct ifnet ifnet;
	register char *cp;
	extern char *index();

	while (ifnetaddr) {
	    /*
	     *	    Get the "ifnet" structure and extract the device name
	     */
	    klookup((int)ifnetaddr, (char *)&ifnet, sizeof ifnet);
	    klookup((int)ifnet.if_name, (char *)saveName, 16);
	    if (strcmp(saveName, "ip") == 0) {
		ifnetaddr = ifnet.if_next;
		continue;
	    }



 	    saveName[15] = '\0';
	    cp = index(saveName, '\0');
	    *cp++ = ifnet.if_unit + '0';
	    *cp = '\0';
	    if (1 || strcmp(saveName,"lo0") != 0) {  /* XXX */

		if (Index)
		    *Index = ++saveIndex;
		if (Retifnet)
		    *Retifnet = ifnet;
		if (Name)
		    strcpy(Name, saveName);
		saveifnet = ifnet;
		saveifnetaddr = ifnetaddr;
		ifnetaddr = ifnet.if_next;

		return(1);	/* DONE */
	    } 
	    ifnetaddr = ifnet.if_next;
	}
	return(0);	    /* EOF */
}


#else

int Interface_Scan_Next(Index, Name, Retifnet, Retin_ifaddr)
int *Index;
char *Name;
struct ifnet *Retifnet;
struct in_ifaddr *Retin_ifaddr;
{
	struct ifnet ifnet;
	struct in_ifaddr *ia, in_ifaddr;
	register char *cp;
	extern char *index();

	while (ifnetaddr) {
	    /*
	     *	    Get the "ifnet" structure and extract the device name
	     */
	    klookup((int)ifnetaddr, (char *)&ifnet, sizeof ifnet);
	    klookup((int)ifnet.if_name, (char *)saveName, 16);

	    saveName[15] = '\0';
	    cp = index(saveName, '\0');
	    *cp++ = ifnet.if_unit + '0';
	    *cp = '\0';
	    if (1 || strcmp(saveName,"lo0") != 0) {  /* XXX */
		/*
		 *  Try to find an address for this interface
		 */

		KNLookup(N_IN_IFADDR, (char *)&ia, sizeof(ia));
		while (ia) {
		    klookup((int)ia ,  (char *)&in_ifaddr, sizeof(in_ifaddr));
		    if (in_ifaddr.ia_ifp == ifnetaddr) break;
		    ia = in_ifaddr.ia_next;
		}

		ifnet.if_addrlist = (struct ifaddr *)ia;     /* WRONG DATA TYPE; ONLY A FLAG */
/*		ifnet.if_addrlist = (struct ifaddr *)&ia->ia_ifa;   */  /* WRONG DATA TYPE; ONLY A FLAG */

		if (Index)
		    *Index = ++saveIndex;
		if (Retifnet)
		    *Retifnet = ifnet;
		if (Retin_ifaddr)
		    *Retin_ifaddr = in_ifaddr;
		if (Name)
		    strcpy(Name, saveName);
		saveifnet = ifnet;
		saveifnetaddr = ifnetaddr;
		savein_ifaddr = in_ifaddr;
		ifnetaddr = ifnet.if_next;

		return(1);	/* DONE */
	    }
	    ifnetaddr = ifnet.if_next;
	}
	return(0);	    /* EOF */
}


#endif sunV3




#ifdef sunV3

static int Interface_Scan_By_Index(Index, Name, Retifnet)
int Index;
char *Name;
struct ifnet *Retifnet;
{
	int i;

	if (saveIndex != Index) {	/* Optimization! */
	    Interface_Scan_Init();
	    while (Interface_Scan_Next(&i, Name, Retifnet)) {
		if (i == Index) break;
	    }
	    if (i != Index) return(-1);     /* Error, doesn't exist */
	} else {
	    if (Retifnet)
		*Retifnet = saveifnet;
	    if (Name)
		strcpy(Name, saveName);
	}
	return(0);	/* DONE */
}

#else

static int Interface_Scan_By_Index(Index, Name, Retifnet, Retin_ifaddr)
int Index;
char *Name;
struct ifnet *Retifnet;
struct in_ifaddr *Retin_ifaddr;
{
	int i;

	if (saveIndex != Index) {	/* Optimization! */
	    Interface_Scan_Init();
	    while (Interface_Scan_Next(&i, Name, Retifnet, Retin_ifaddr)) {
		if (i == Index) break;
	    }
	    if (i != Index) return(-1);     /* Error, doesn't exist */
	} else {
	    if (Retifnet)
		*Retifnet = saveifnet;
	    if (Retin_ifaddr)
		*Retin_ifaddr = savein_ifaddr;
	    if (Name)
		strcpy(Name, saveName);
	}
	return(0);	/* DONE */
}

#endif


static int Interface_Count=0;

static int Interface_Scan_Get_Count()
{

	if (!Interface_Count) {
	    Interface_Scan_Init();
#ifdef sunV3
	    while (Interface_Scan_Next((int *)0, (char *)0, (struct ifnet *)0) != 0) {
#else
	    while (Interface_Scan_Next((int *)0, (char *)0, (struct ifnet *)0, (struct in_ifaddr *)0) != 0) {
#endif
		Interface_Count++;
	    }
	}
	return(Interface_Count);
}


static int Interface_Get_Ether_By_Index(Index, EtherAddr)
int Index;
u_char *EtherAddr;
{
	int i;
	struct arpcom arpcom;

	if (saveIndex != Index) {	/* Optimization! */

	    Interface_Scan_Init();

#ifdef sunV3
	    while (Interface_Scan_Next((int *)&i, (char *)0, (struct ifnet *)0) != 0) {
#else
	    while (Interface_Scan_Next((int *)&i, (char *)0, (struct ifnet *)0, (struct in_ifaddr *)0) != 0) {
#endif
		if (i == Index) break;
	    }
	    if (i != Index) return(-1);     /* Error, doesn't exist */
	}

	/*
	 *  the arpcom structure is an extended ifnet structure which
	 *  contains the ethernet address.
	 */
	klookup((int)saveifnetaddr, (char *)&arpcom, sizeof (struct arpcom));
	if (strncmp("lo", saveName, 2) == 0) {
	    /*
	     *  Loopback doesn't have a HW addr, so return 00:00:00:00:00:00
	     */
	    bzero(EtherAddr, sizeof(arpcom.ac_enaddr));

	} else {
#if defined(sunV3) || defined(sparc)
	    bcopy((char *) &arpcom.ac_enaddr, EtherAddr, sizeof (arpcom.ac_enaddr));
#endif
#ifdef mips
	    bcopy((char *)  arpcom.ac_enaddr, EtherAddr, sizeof (arpcom.ac_enaddr));
#endif


	}
	return(0);	/* DONE */
}



#if defined(mips) || defined(ibm032) || defined(sunV3) || defined(hpuxx)


/*
**  Lets read the process table in blocks so as to 
**  minimize sys calls
*/
#define PROCBLOC 16
struct proc procbuf[PROCBLOC];


u_char *var_process(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;   /* IN - pointer to variable entry that points here */
    register oid	*name;	    /* IN/OUT - input name requested, output name found */
    register int	*length;    /* IN/OUT - length of input and output oid's */
    int			exact;	    /* IN - TRUE if an exact match was requested. */
    int			*var_len;   /* OUT - length of variable or 0 if function returned. */
    int			(**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
    oid			newname[MAX_NAME_LEN];
    register int	slotindex;
    register int        numread, i;
    int result, count;
    off_t   procp;
    struct proc	*proc;


    /* NOW BROKEN 6/92 */
    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    bzero(return_buf, 256);

    /* find "next" process */



    if (KNLookup(N_PROC,  (char *)&procp, sizeof(procp)) == NULL) {
	return (NULL);
    }
    if (KNLookup(N_NPROC, (char *)&count, sizeof(count)) == NULL) {
	return (NULL);
    }

    proc = NULL;
    slotindex = 0;
    while ((!proc) && (slotindex < count)) {
      
        numread = MIN(count - slotindex, PROCBLOC);
        if (klookup((int)procp, (char *)procbuf,
		    numread * sizeof(struct proc)) == NULL) {
	    return(NULL);
	}
	procp += sizeof(struct proc) * numread;

	for (i=0; i < numread; i++) {
	    slotindex++;

	    if ((procbuf[i].p_stat == 0) || (procbuf[i].p_stat == SZOMB)) {
	        continue;
	    }
	    newname[13] = (oid) slotindex;
	    result = compare(name, *length, newname, (int)vp->namelen);
	    if ((exact && (result == 0)) || (!exact && (result < 0))) {
	        proc = &procbuf[i];
	        break;
	    }
	}
    }


    if (!proc) {
	return NULL;
    }

    bcopy((char *)newname, (char *)name, (int)vp->namelen * sizeof(oid));
    *length = vp->namelen;
    *write_method = 0;
    *var_len = sizeof(long);

    switch (vp->magic){
	case PROCESSSLOTINDEX:
	    long_return = slotindex;
	    return (u_char *) &long_return;
	case PROCESSID:
	    long_return = proc->p_pid;
	    return (u_char *) &long_return;
	case PROCESSCOMMAND:
	    *var_len = get_command(proc, return_buf);
	    return (u_char *)return_buf;
	default:
	    ERROR("");
    }
    return NULL;
}







get_command(proc, buf)
     struct proc *proc;
     char *buf;
{

#if defined(ibm032) 
    struct user u;
struct userx
{
        char userfill[UPAGES*NBPG-sizeof (struct user)];
	struct user user;
};

#ifdef BSD4_3
#define REDSIZE CLSIZE*2		/* red zone size plus reserved page */
#else
#define REDSIZE CLSIZE			/* red zone size */
#endif BSD4_3

union {
        struct	userx userx;
	char	upages[UPAGES][NBPG];
} user;
#define U	user.userx.user
#else

#define REDSIZE 0		/* red zone size */

union {
	struct	user user;
	char	upages[UPAGES][NBPG];
} user;
#define u	user.user
#endif 

    struct pte *pteaddr, apte;
    struct	pte *Usrptmap, *usrpt;

#ifdef mips
    struct pte arguutl[UPAGES];
    struct pte wpte[UPAGES];
#endif
#ifdef sunV3
    struct pte uutl[UPAGES];
    struct pte arguutl[UPAGES];
#endif


    union {
	    char	argc[CLSIZE*NBPG];
	    int 	argi[CLSIZE*NBPG/sizeof (int)];
    } argspac;



    int	argaddr;
    struct dblock db;
    register char *cp;
    register int *ip;
    char c;
    int ncl;
    int    i;
    int usersize, size;
    long addr;
    int  nbad;

    /*
     *  Handle the 2 system procs now so 
     *  we don't have to worry about them latter
     */
    if (proc->p_pid == 0){
	strcpy(buf, "swapper");
	return strlen(buf);
    }
    if (proc->p_pid == 2){
	strcpy(buf, "pagedaemon");
	return strlen(buf);
    }


#ifdef ibm032
        size = ctob(UPAGES);
#endif
#ifdef mips
	size = sizeof (struct user);
#endif
#ifdef sunV3
	size = roundup(sizeof (struct user), DEV_BSIZE);
#endif

    /*
     *  We don't deal with Zombies and the like...
     */
    if (proc->p_stat == SZOMB || proc->p_flag & (SSYS | SWEXIT)){
	strcpy((char *)buf, "");
	return strlen(buf);
    }

#ifdef ibm032

    if (KNLookup(N_USERSIZE, (char *)&usersize, sizeof(usersize)) == NULL) {
	return(0);
    }
#endif

    usrpt = (struct pte *)nl[N_USRPT].n_value;
    Usrptmap = (struct pte *)nl[N_USRPTMAP].n_value;

    /*
     *  Is our target proc in core??
     */
    if ((proc->p_flag & SLOAD) == 0){
      /*
       *  Not in core -- poke (peek, actually [hopefully]) around swap for u. struct 
       */
	lseek(swap, (long)dtob(proc->p_swaddr), 0);

	if (read(swap, (char *)user.upages, size) != size) {
	        ERROR("");
		return (0);
	}
#ifdef ibm032
	if ((i = usersize - sizeof (struct user)) > 0)
	    bcopy(((char *) &U) - i, (char *) &u, sizeof (struct user));	
	   /* fake the location of the u structure */
	else
	    u = U;   /* added 8-9-85 for consistency */ 
#endif
	argaddr = 0;
    } else {




#ifdef sunV3
	pteaddr = &Usrptmap[btokmx(sptopte(proc, CLSIZE-1))];
#endif sunV3
#ifdef ibm032
	pteaddr = &Usrptmap[btokmx(proc->p_p0br) + proc->p_szpt - 1];
#endif ibm032
#ifdef mips
	pteaddr = &Usrptmap[btokmx(proc->p_stakbr)+proc->p_stakpt-1];
#endif mips

	if (klookup((long)pteaddr, (char *)&apte, sizeof(apte)) == NULL) {
	    ERROR("");
	    return(0);
	}

#ifdef sunV3
	addr = (long)ctob(apte.pg_pfnum) + (((int)sptopte(proc, CLSIZE-1))&PGOFSET);     
#endif sunV3
#ifdef ibm032
	addr = (long)ctob(apte.pg_pfnum+1) - (UPAGES+CLSIZE+REDSIZE) * sizeof (struct pte);     
#endif ibm032
#ifdef mips
	addr = (long)ctob(apte.pg_pfnum) + NBPG - ((REDZONEPAGES+1) * sizeof(struct pte));
#endif mips

	lseek(mem, addr, 0);  
#ifdef sunV3
	if (read(mem, (char *)arguutl, sizeof(struct pte)) != sizeof(struct pte)) {
#else 
	if (read(mem, (char *)arguutl, sizeof(arguutl)) != sizeof(arguutl)) {
#endif
		printf("can't read page table for u of pid %d from /dev/mem\n",
		    proc->p_pid);
		return (0);
	}


	if (arguutl[0].pg_fod == 0 && arguutl[0].pg_pfnum) {
		argaddr = ctob(arguutl[0].pg_pfnum);
	} else {
		argaddr = 0;
	}



#ifdef mips
	if (klookup((long)proc->p_addr, (char *)wpte, sizeof(wpte)) == NULL) {
	    return(0);
	}
#endif mips



#ifdef sunV3

	pteaddr = &Usrptmap[btokmx(proc->p_addr)];
	if (klookup((long)pteaddr, (char *)&apte, sizeof(apte)) == NULL) {
	    return(0);
	}
	addr = (long)ctob(apte.pg_pfnum) + (((int)proc->p_addr)&PGOFSET);
	lseek(mem, addr, 0); 
	if (read(mem, (char *)uutl, sizeof(uutl)) != sizeof(uutl)) {
		printf("cant read page table for u of pid %d from /dev/mem\n",
		    proc->p_pid);
		return (0);
	}

#endif sunV3
	

	ncl = (size + NBPG*CLSIZE - 1) / (NBPG*CLSIZE);

	while (--ncl >= 0) {
		i = ncl * CLSIZE;
#ifdef ibm032
		addr = (long)ctob(arguutl[CLSIZE+REDSIZE+i].pg_pfnum);

		if (addr == 0) {
			bzero((char *) &u, sizeof (struct user));
			return(1);	/* faked for swapper */
		}
#endif
#ifdef mips
		addr = (long)ctob(wpte[i].pg_pfnum);
#endif mips
#ifdef sunV3
		addr = (long)ctob(uutl[i].pg_pfnum);
#endif sunV3

		lseek(mem, addr, 0);
		if (read(mem, user.upages[i], CLSIZE*NBPG) != CLSIZE*NBPG) {
			printf("cant read page from /dev/mem\n");
			return(0);
		}
	}
#ifdef ibm032
	if ((i = usersize - sizeof (struct user)) > 0)
	    bcopy(((char *) &U) - i, (char *) &u, sizeof (struct user));	
	    /* fake the location of the u structure */
	else
	  u = U;	/* return the structure */
#endif

    }


#ifdef sunV3
    if (u.u_ssize == 0) {
	(void) strcpy(buf, " (");
	(void) strncat(buf, u.u_comm, sizeof (u.u_comm));
	(void) strcat(buf, ")");
	return strlen(buf);
    }
#endif sunV3

    if ((proc->p_flag & SLOAD) == 0 || argaddr == 0){
#if !defined(ibm032) || !defined(BSD4_3)
	vstodb(0, CLSIZE, &u.u_smap, &db, 1);
#else
	vstodb(CLSIZE, CLSIZE, &u.u_smap, &db, 1);
#endif

	lseek(swap, (long)dtob(db.db_base), 0);
 	if (read(swap, (char *)&argspac, sizeof(argspac)) != sizeof(argspac)) {
	  ERROR("");
	}
    } else {
        lseek(mem, (long)argaddr, 0);
        if (read(mem, (char *)&argspac, sizeof(argspac)) != sizeof(argspac)) {
	  ERROR("");
	}
    }

#if defined(ibm032) && defined(NFL) && !defined(BSD4_3)
        ip = &argspac.argi[CLSIZE*NBPG/sizeof (int)];
	ip -= sizeof (struct fp_mach) / sizeof (int);
        ip -= 2;		/* last arg word and .long 0 */
#endif ibm032
#ifdef sunV3
        ip = &argspac.argi[CLSIZE*NBPG/sizeof (int)];
        ip -= 2;
#endif
#ifdef mips
	ip = &argspac.argi[(CLSIZE*NBPG-EA_SIZE)/sizeof (int)];
        while (*--ip == 0) {
	    if (ip == argspac.argi) {
		(void) strcpy(buf, " (");
		(void) strncat(buf, u.u_comm, sizeof (u.u_comm));
 		(void) strcat(buf, ")");
		return strlen(buf);
	    }
	}
#endif mips

    while (*--ip)
	    if (ip == argspac.argi){
		(void) strcpy(buf, " (");
		(void) strncat(buf, u.u_comm, sizeof (u.u_comm));
		(void) strcat(buf, ")");
		return strlen(buf);
	    }
    *(char *)ip = ' ';
    ip++;

    nbad = 0;

#ifndef mips
      for (cp = (char *)ip; cp < &argspac.argc[CLSIZE*NBPG]; cp++) {
#else
      for (cp = (char *)ip; cp < &argspac.argc[CLSIZE*NBPG-EA_SIZE]; cp++) {
#endif mips    
	c = *cp & 0177;
	if (c == 0) {
	  *cp = ' ';
	} else if (c < ' ' || c > 0176) {
	  if (++nbad >= 5) {
	    *cp++ = ' ';
	    break;
	  }
	  *cp = '?';
	} else if (c == '=') {
	  while (*--cp != ' ')
	    if (cp <= (char *)ip) {
	      break;
	    }
	  break;
	}
      }
      
      *cp = 0;
      while (*--cp == ' ') {
	*cp = 0;
      }
      cp = (char *)ip;
      strncpy(buf, cp, &argspac.argc[CLSIZE*NBPG] - cp);
      if (cp[0] == '-' || cp[0] == '?' || cp[0] <= ' ') {
	(void) strcat(buf, " (");
	(void) strncat(buf, u.u_comm, sizeof(u.u_comm));
	(void) strcat(buf, ")");
      }
      return strlen(buf);
}





vstodb(vsbase, vssize, dmp, dbp, rev)
	register int vsbase;
	int vssize;
	struct dmap *dmp;
	register struct dblock *dbp;
{
	int	dmmin, dmmax, nswap;
	register int blk;
	register swblk_t *ip = dmp->dm_map;

	if (KNLookup(N_DMMIN, (char *)&dmmin, sizeof(dmmin)) == NULL ||
	    KNLookup(N_DMMAX, (char *)&dmmax, sizeof(dmmax)) == NULL ||
	    KNLookup(N_NSWAP, (char *)&nswap, sizeof(nswap)) == NULL) {
	    ERROR("");
	    return(0);
	}

	blk = dmmin;
	vsbase = ctod(vsbase);
	vssize = ctod(vssize);
	if (vsbase < 0 || vsbase + vssize > dmp->dm_size) {
	    ERROR("vstodb\n");
	    return(0);
	}
	while (vsbase >= blk) {
	    vsbase -= blk;
	    if (blk < dmmax) {
	    	blk *= 2;
	    }
	    ip++;
	}
	if (*ip <= 0 || *ip + blk > nswap) {
	    ERROR("vstodb *ip\n");
	    return(0);
	}
	dbp->db_size = (vssize < (blk - vsbase)) ?  vssize : (blk - vsbase);
	dbp->db_base = *ip + (rev ? blk - (vsbase + dbp->db_size) : vsbase);
}

#endif 





