/****************************************************************
	Copyright 1989, 1991, 1992 by Carnegie Mellon University

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
/*
 * Copyright (c) 1983,1988 Regents of the University of California.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms are permitted
 * provided that this notice is preserved and that due credit is given
 * to the University of California at Berkeley. The name of the University
 * may not be used to endorse or promote products derived from this
 * software without specific prior written permission. This software
 * is provided ``as is'' without express or implied warranty.
 */

#include <config.h>

#if STDC_HEADERS
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#endif

#include <stdio.h>

#include <sys/param.h>
#include <sys/socket.h>

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <netdb.h>

#include "main.h"
#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"

extern	int aflag;
extern	int nflag;
extern	char *plural __P((int));
extern	struct snmp_session *Session;
extern	struct variable_list *getvarbyname __P((struct snmp_session *, oid *, int));
void tcp_stats __P((void));
void ip_stats __P((void));
void icmp_stats __P((void));

char	*inetname __P((struct in_addr));
void	inetprint __P((struct in_addr *,u_short, char *));

struct stat_table {
    int	    entry;  /* entry number in table */
    /* format string to printf(description, value, plural(value)); */
    /* warning: the %d must be before the %s */
    char    description[80];
};

static oid oid_ipstats[] = {1, 3, 6, 1, 2, 1, 4, 0, 0};
struct stat_table ip_stattab[] = {
    {3, "%d total datagram%s received"},
    {4, "%d datagram%s with header errors"},
    {5, "%d datagram%s with an invalid destination address"},
    {6, "%d datagram%s forwarded"},
    {7, "%d datagram%s with unknown protocol"},
    {8, "%d datagram%s discarded"},
    {9, "%d datagram%s delivered"},
    {10, "%d output datagram request%s"},
    {11, "%d output datagram%s discarded"},
    {12, "%d datagram%s with no route"},
    {14, "%d fragment%s received"},
    {15, "%d datagram%s reassembled"},
    {16, "%d reassembly failure%s"},
    {17, "%d datagram%s fragmented"},
    {18, "%d fragmentation failure%s"},
    {19, "%d fragment%s created"}
};

static oid oid_udpstats[] = {1, 3, 6, 1, 2, 1, 7, 0, 0};
struct stat_table udp_stattab[] = {
    {1, "%d total datagram%s received"},
    {2, "%d datagram%s to invalid port"},
    {3, "%d datagram%s dropped due to errors"},
    {4, "%d output datagram request%s"}
};

static oid oid_tcpstats[] = {1, 3, 6, 1, 2, 1, 6, 0, 0};
struct stat_table tcp_stattab[] = {
    {5, "%d active open%s"},
    {6, "%d passive open%s"},
    {7, "%d failed attempt%s"},
    {8, "%d reset%s of established connections"},
    {9, "%d current established connection%s"},
    {10, "%d segment%s received"},
    {11, "%d segment%s sent"},
    {12, "%d segment%s retransmitted"}
};

static oid oid_icmpstats[] = {1, 3, 6, 1, 2, 1, 5, 0, 0};
struct stat_table icmp_stattab[] = {
    {1, "%d total message%s received"},
    {2, "%d message%s dropped due to errors"},
    {14, "%d ouput message request%s"},
    {15, "%d output message%s discarded"}
};

struct stat_table icmp_inhistogram[] = {
    {3, "Destination unreachable: %d"},
    {4, "Time Exceeded: %d"},
    {5, "Parameter Problem: %d"},
    {6, "Source Quench: %d"},
    {7, "Redirect: %d"},
    {8, "Echo Request: %d"},
    {9, "Echo Reply: %d"},
    {10, "Timestamp Request: %d"},
    {11, "Timestamp Reply: %d"},
    {12, "Address Mask Request: %d"},
    {13, "Addrss Mask Reply:%d"},
};

struct stat_table icmp_outhistogram[] = {
    {16, "Destination unreachable: %d"},
    {17, "Time Exceeded: %d"},
    {18, "Parameter Problem: %d"},
    {19, "Source Quench: %d"},
    {20, "Redirect: %d"},
    {21, "Echo Request: %d"},
    {22, "Echo Reply: %d"},
    {23, "Timestamp Request: %d"},
    {24, "Timestamp Reply: %d"},
    {25, "Address Mask Request: %d"},
    {26, "Addrss Mask Reply:%d"},
};

struct tcpconn_entry {
    oid	    instance[10];
    struct in_addr  localAddress;
    int	    locAddrSet;
    u_short localPort;
    int	    locPortSet;
    struct in_addr  remoteAddress;
    int	    remAddrSet;
    u_short remotePort;
    int	    remPortSet;
    int	    state;
    int	    stateSet;
    struct tcpconn_entry *next;
};

#define TCPCONN_STATE	1
#define TCPCONN_LOCADDR	2
#define TCPCONN_LOCPORT	3
#define TCPCONN_REMADDR	4
#define TCPCONN_REMPORT	5



static oid oid_tcpconntable[] = {1, 3, 6, 1, 2, 1, 6, 13, 1};
#define ENTRY 9

char *tcpstates[] = {
    "",		    "CLOSED",	    "LISTEN",   "SYNSENT",
    "SYNRECEIVED",  "ESTABLISHED",  "FINWAIT1", "FINWAIT2",
    "CLOSEWAIT",    "LASTACK",	    "CLOSING",	"TIMEWAIT"
};
#define TCP_NSTATES 11

/*
 * Print a summary of connections related to an Internet
 * protocol (currently only TCP).  For TCP, also give state of connection.
 */
void
protopr __P((void))
{
    struct tcpconn_entry *tcpconn = NULL, *tp, *newp;
    struct snmp_pdu *request, *response;
    struct variable_list *vp;
    oid *instance;
    int first, status;

    request = snmp_pdu_create(GETNEXT_REQ_MSG);

    snmp_add_null_var(request, oid_tcpconntable, sizeof(oid_tcpconntable)/sizeof(oid));

    while(1){
	status = snmp_synch_response(Session, request, &response);
	if (status != STAT_SUCCESS || response->errstat != SNMP_ERR_NOERROR){
	    fprintf(stderr, "SNMP request failed\n");
	    break;
	}
	vp = response->variables;
	if (vp->name_length != 20 ||
          memcmp(vp->name, oid_tcpconntable, sizeof(oid_tcpconntable))){
		break;
	}
	
	request = snmp_pdu_create(GETNEXT_REQ_MSG);
	snmp_add_null_var(request, vp->name, vp->name_length);

	instance = vp->name + 10;
	for(tp = tcpconn; tp != NULL; tp = tp->next){
          if (!memcmp(instance, tp->instance, sizeof(tp->instance)))
		    break;
	}
	if (tp == NULL){
	    newp = (struct tcpconn_entry *)malloc(sizeof(struct tcpconn_entry));
	    if (tcpconn == NULL){
		tcpconn = newp;
	    } else {
		for(tp = tcpconn; tp->next != NULL; tp = tp->next)
		    ;
		tp->next = newp;
	    }
	    tp = newp;
          memset(tp, 0, sizeof(*tp));
	    tp->next = NULL;
          memmove(tp->instance, instance, sizeof(tp->instance));
	}

	if (vp->name[ENTRY] == TCPCONN_STATE){
	    tp->state = *vp->val.integer;
	    tp->stateSet = 1;

	}

	if (vp->name[ENTRY] == TCPCONN_LOCADDR){
          memmove(&tp->localAddress, vp->val.string, sizeof(u_long));
	    tp->locAddrSet = 1;

	}

	if (vp->name[ENTRY] == TCPCONN_LOCPORT){
	    tp->localPort = *vp->val.integer;
	    tp->locPortSet = 1;

	}

	if (vp->name[ENTRY] == TCPCONN_REMADDR){
          memmove(&tp->remoteAddress, vp->val.string, sizeof(u_long));
	    tp->remAddrSet = 1;

	}

	if (vp->name[ENTRY] == TCPCONN_REMPORT){
	    tp->remotePort = *vp->val.integer;
	    tp->remPortSet = 1;

	}

    }

    for(first = 1, tp = tcpconn; tp != NULL; tp = tp->next){
	if (!(tp->stateSet && tp->locAddrSet
	    && tp->locPortSet && tp->remAddrSet && tp->remPortSet)){
		printf("incomplete entry\n");
		continue;
	}
	if (!aflag && tp->state == MIB_TCPCONNSTATE_LISTEN)
		    continue;
	if (first){
	    printf("Active Internet Connections");
	    if (aflag)
		printf(" (including servers)");
	    putchar('\n');
	    printf("%-5.5s %-6.6s %-6.6s  %-22.22s %-22.22s %s\n",
		    "Proto", "Recv-Q", "Send-Q",
		    "Local Address", "Foreign Address", "(state)");
	    first = 0;
	}
	printf("%-5.5s %6d %6d ", "tcp", 0, 0);
	inetprint(&tp->localAddress, tp->localPort, "tcp");
	inetprint(&tp->remoteAddress, tp->remotePort, "tcp");
	if (tp->state < 1 || tp->state > TCP_NSTATES)
	    printf(" %d", tp->state);
	else
	    printf(" %s", tcpstates[tp->state]);
	putchar('\n');
    }

}


/*
 * Dump UDP statistics structure.
 */
void
udp_stats __P((void))
{
    oid varname[MAX_NAME_LEN], *udpentry;
    int varname_len;
    struct variable_list *var;
    int count;
    struct stat_table *sp = udp_stattab;

    memmove(varname, oid_udpstats, sizeof(oid_udpstats));
    varname_len = sizeof(oid_udpstats) / sizeof(oid);
    udpentry = varname + 7;
    printf("udp:\n");
    count = sizeof(udp_stattab) / sizeof (struct stat_table);
    while (count--){
	*udpentry = sp->entry;
	var = getvarbyname(Session, varname, varname_len);
	if (var){
	    putchar('\t');
	    printf(sp->description, *var->val.integer, plural((int)*var->val.integer));
	    putchar('\n');
	}
	sp++;
    }

}

/*
 * Dump TCP statistics structure.
 */
void
tcp_stats __P((void))
{
    oid varname[MAX_NAME_LEN], *tcpentry;
    int varname_len;
    struct variable_list *var;
    int count;
    struct stat_table *sp = tcp_stattab;

    memmove(varname, oid_tcpstats, sizeof(oid_tcpstats));
    varname_len = sizeof(oid_tcpstats) / sizeof(oid);
    tcpentry = varname + 7;
    printf("tcp:\n");
    count = sizeof(tcp_stattab) / sizeof (struct stat_table);
    while (count--){
	*tcpentry = sp->entry;
	var = getvarbyname(Session, varname, varname_len);
	if (var){
	    putchar('\t');
	    printf(sp->description, *var->val.integer, plural((int)*var->val.integer));
	    putchar('\n');
	}
	sp++;
    }

}

/*
 * Dump IP statistics structure.
 */
void
ip_stats __P((void))
{
    oid varname[MAX_NAME_LEN], *ipentry;
    int varname_len;
    struct variable_list *var;
    int count;
    struct stat_table *sp = ip_stattab;

    memmove(varname, oid_ipstats, sizeof(oid_ipstats));
    varname_len = sizeof(oid_ipstats) / sizeof(oid);
    ipentry = varname + 7;
    printf("ip:\n");
    count = sizeof(ip_stattab) / sizeof (struct stat_table);
    while (count--){
	*ipentry = sp->entry;
	var = getvarbyname(Session, varname, varname_len);
	if (var){
	    putchar('\t');
	    printf(sp->description, *var->val.integer, plural((int)*var->val.integer));
	    putchar('\n');
	}
	sp++;
    }

}

/*
 * Dump ICMP statistics.
 */
void
icmp_stats __P((void))
{
    oid varname[MAX_NAME_LEN], *icmpentry;
    int varname_len;
    struct variable_list *var;
    int count, first;
    struct stat_table *sp;

    memmove(varname, oid_icmpstats, sizeof(oid_icmpstats));
    varname_len = sizeof(oid_icmpstats) / sizeof(oid);
    icmpentry = varname + 7;
    printf("icmp:\n");
    sp = icmp_stattab;
    count = sizeof(icmp_stattab) / sizeof (struct stat_table);
    while (count--){
	*icmpentry = sp->entry;
	var = getvarbyname(Session, varname, varname_len);
	if (var){
	    putchar('\t');
	    printf(sp->description, *var->val.integer, plural((int)*var->val.integer));
	    putchar('\n');
	}
	sp++;
    }

    sp = icmp_outhistogram;
    first = 1;
    count = sizeof(icmp_outhistogram) / sizeof (struct stat_table);
    while (count--){
	*icmpentry = sp->entry;
	var = getvarbyname(Session, varname, varname_len);
	if (var && *var->val.integer != 0){
	    if (first){
		printf("\tOutput Histogram:\n");
		first = 0;
	    }
	    printf("\t\t");
	    printf(sp->description, *var->val.integer, plural((int)*var->val.integer));
	    putchar('\n');
	}
	sp++;
    }

    sp = icmp_inhistogram;
    first = 1;
    count = sizeof(icmp_inhistogram) / sizeof (struct stat_table);
    while (count--){
	*icmpentry = sp->entry;
	var = getvarbyname(Session, varname, varname_len);
	if (var && *var->val.integer != 0){
	    if (first){
		printf("\tInput Histogram:\n");
		first = 0;
	    }
	    printf("\t\t");
	    printf(sp->description, *var->val.integer, plural((int)*var->val.integer));
	    putchar('\n');
	}
	sp++;
    }
}

/*
 * Pretty print an Internet address (net address + port).
 * If the nflag was specified, use numbers instead of names.
 */
void
inetprint(in, port, proto)
	register struct in_addr *in;
	u_short port; 
	char *proto;
{
	struct servent *sp = 0;
	char line[80], *cp;
	int width;

	sprintf(line, "%.*s.", 16, inetname(*in));
	cp = (char *) strchr(line, '\0');
	if (!nflag && port)
		sp = getservbyport((int)port, proto);
	if (sp || port == 0)
		sprintf(cp, "%.8s", sp ? sp->s_name : "*");
	else
		sprintf(cp, "%d", ntohs((u_short)port));
	width = 22;
	printf(" %-*.*s", width, width, line);
}

/*
 * Construct an Internet address representation.
 * If the nflag has been supplied, give 
 * numeric value, otherwise try for symbolic name.
 */
char *
inetname(in)
	struct in_addr in;
{
	register char *cp;
	static char line[50];
	struct hostent *hp;
	struct netent *np;
	static char domain[MAXHOSTNAMELEN + 1];
	static int first = 1;

	if (first && !nflag) {
		first = 0;
		if (gethostname(domain, MAXHOSTNAMELEN) == 0 &&
		    (cp = (char *) strchr(domain, '.')))
			(void) strcpy(domain, cp + 1);
		else
			domain[0] = 0;
	}
	cp = 0;
	if (!nflag && in.s_addr != INADDR_ANY) {
		u_long net = inet_netof(in);
		u_long lna = inet_lnaof(in);

		if (lna == INADDR_ANY) {
			np = getnetbyaddr(net, AF_INET);
			if (np)
				cp = np->n_name;
		}
		if (cp == 0) {
			hp = gethostbyaddr((char *)&in, sizeof (in), AF_INET);
			if (hp) {
				if ((cp = (char *) strchr(hp->h_name, '.')) &&
				    !strcmp(cp + 1, domain))
					*cp = 0;
				cp = hp->h_name;
			}
		}
	}
	if (in.s_addr == INADDR_ANY)
		strcpy(line, "*");
	else if (cp)
		strcpy(line, cp);
	else {
		in.s_addr = ntohl(in.s_addr);
#define C(x)	(unsigned)((x) & 0xff)
		sprintf(line, "%u.%u.%u.%u", C(in.s_addr >> 24),
			C(in.s_addr >> 16), C(in.s_addr >> 8), C(in.s_addr));
	}
	return (line);
}
