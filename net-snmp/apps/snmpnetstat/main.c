/******************************************************************
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

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1983 Regents of the University of California.\n\
 All rights reserved.\n";
#endif not lint

#include <sys/types.h>
#include <sys/param.h>

#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>

#include <ctype.h>
#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <netinet/in.h>
#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "party.h"
#include "context.h"
#include "view.h"
#include "acl.h"

/* internet protocols */
extern	int protopr();
extern	int tcp_stats(), udp_stats(), ip_stats(), icmp_stats();

#define NULLPROTOX	((struct protox *) 0)
struct protox {
	u_char	pr_wanted;		/* 1 if wanted, 0 otherwise */
	int	(*pr_cblocks)();	/* control blocks printing routine */
	int	(*pr_stats)();		/* statistics printing routine */
	char	*pr_name;		/* well-known name */
} protox[] = {
	{ 1,	protopr,    tcp_stats,	"tcp" },
	{ 1,	0,	    udp_stats,	"udp" },
	{ 1,	0,	    ip_stats,	"ip" },
	{ 1,	0,	    icmp_stats,	"icmp" },
	{ 0,	0,	    0,		0 }
};

int	aflag;
int	iflag;
int	nflag;
int	pflag;
int	rflag;
int	sflag;
int	interval;
char	*interface;

int debug = 0;


extern	char *malloc();

struct snmp_session *Session;
int snmp_dump_packet = 0;
int print_errors = 0;
usage(){
    fprintf(stderr, "Usage: snmpnetstat -v 1 hostname community [ -ainrs ] [-p proto] [-I interface] [ interval ]      or:\n");
    fprintf(stderr, "Usage: snmpnetstat [-v 2 ] hostname noAuth [ -ainrs ] [-p proto] [-I interface] [ interval ]      or:\n");
    fprintf(stderr, "Usage: snmpnetstat [-v 2 ] hostname srcParty dstParty context [ -ainrs ] [-p proto] [-I interface] [ interval ]\n");
}

main(argc, argv)
	int argc;
	char *argv[];
{
    char *cp, *name;
    char *hostname;
    register struct protoent *p;
    register struct protox *tp;	/* for printing cblocks & stats */
    struct protox *name2protox();	/* for -p */
    char *community;
    struct snmp_session session;
    
    int port_flag = 0;
    int dest_port = 0;
    int clock_flag = 0;
    u_long	srcclock, dstclock;
    int version = 2;
    struct partyEntry *pp;
    struct contextEntry *cxp;
    oid src[MAX_NAME_LEN], dst[MAX_NAME_LEN], context[MAX_NAME_LEN];
    int srclen = 0, dstlen = 0, contextlen = 0;
    int trivialSNMPv2 = FALSE;
    struct hostent *hp;
    u_long destAddr;
    int arg;
    
    init_mib();
    /*
     * Usage: snmpnetstatwalk -v 1 hostname community ...      or:
     * Usage: snmpnetstat [-v 2 ] hostname noAuth     ...      or:
     * Usage: snmpnetstat [-v 2 ] hostname srcParty dstParty context ...
     */
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
	      case 'd':
		snmp_dump_packet++;
		break;
	      case 'p':
		port_flag++;
		dest_port = atoi(argv[++arg]);
		break;
	      case 'c':
		clock_flag++;
		srcclock = atoi(argv[++arg]);
		dstclock = atoi(argv[++arg]);
		break;
	      case 'v':
		version = atoi(argv[++arg]);
		if (version < 1 || version > 2){
		    fprintf(stderr, "Invalid version: %d\n", version);
		    usage();
		    exit(1);
		}
		break;
                case 'a':
                        aflag++;
                        break;

                case 'i':
                        iflag++;
                        break;

                case 'n':
                        nflag++;
                        break;

                case 'r':
                        rflag++;
                        break;

                case 's':
                        sflag++;
                        break;

                case 'P':
                        argv++;
                        argc--;
                        if (argc == 0){
                                usage();
				exit(1);
			}
                        if ((tp = name2protox(*argv)) == NULLPROTOX) {
                                fprintf(stderr, "%s: unknown or uninstrumented protocol\n",
                                        *argv);
                                exit(10);
                        }
                        pflag++;
                        break;

                case 'I':
                        iflag++;
                        if (*(interface = cp + 1) == 0) {
                                if ((interface = argv[1]) == 0)
                                        break;
                                argv++;
                                argc--;
                        }
                        for (cp = interface; *cp; cp++)
                                ;
                        cp--;
                        break;

	      default:
		printf("invalid option: -%c\n", argv[arg][1]);
		break;
	    }
	    continue;
	}
	if (hostname == NULL){
	    hostname = argv[arg];
	} else if (version == 1 && community == NULL){
	    community = argv[arg]; 
	} else if (version == 2 && srclen == 0 && !trivialSNMPv2){
	    if (read_party_database("/etc/party.conf") > 0){
		fprintf(stderr,
			"Couldn't read party database from /etc/party.conf\n");
		exit(0);
	    }
	    if (read_context_database("/etc/context.conf") > 0){
		fprintf(stderr,
			"Couldn't read context database from /etc/context.conf\n");
		exit(0);
	    }
	    if (read_acl_database("/etc/acl.conf") > 0){
		fprintf(stderr,
			"Couldn't read access control database from /etc/acl.conf\n");
		exit(0);
	    }
	    
	    if (!strcasecmp(argv[arg], "noauth")){
		trivialSNMPv2 = TRUE;
	    } else {
		party_scanInit();
		for(pp = party_scanNext(); pp; pp = party_scanNext()){
		    if (!strcasecmp(pp->partyName, argv[arg])){
			srclen = pp->partyIdentityLen;
			bcopy(pp->partyIdentity, src, srclen * sizeof(oid));
			break;
		    }
		}
		if (!pp){
		    srclen = MAX_NAME_LEN;
		    if (!read_objid(argv[arg], src, &srclen)){
			printf("Invalid source party: %s\n", argv[arg]);
			srclen = 0;
			usage();
			exit(1);
		    }
		}
	    }
	} else if (version == 2 && dstlen == 0 && !trivialSNMPv2){
	    dstlen = MAX_NAME_LEN;
	    party_scanInit();
	    for(pp = party_scanNext(); pp; pp = party_scanNext()){
		if (!strcasecmp(pp->partyName, argv[arg])){
		    dstlen = pp->partyIdentityLen;
		    bcopy(pp->partyIdentity, dst, dstlen * sizeof(oid));
		    break;
		}
	    }
	    if (!pp){
		if (!read_objid(argv[arg], dst, &dstlen)){
		    printf("Invalid destination party: %s\n", argv[arg]);
		    dstlen = 0;
		    usage();
		    exit(1);
		}
	    }
	} else if (version == 2 && contextlen == 0 && !trivialSNMPv2){
	    contextlen = MAX_NAME_LEN;
	    context_scanInit();
	    for(cxp = context_scanNext(); cxp; cxp = context_scanNext()){
		if (!strcasecmp(cxp->contextName, argv[arg])){
		    contextlen = cxp->contextIdentityLen;
		    bcopy(cxp->contextIdentity, context,
			  contextlen * sizeof(oid));
		    break;
		}
	    }
	    if (!cxp){
		if (!read_objid(argv[arg], context, &contextlen)){
		    printf("Invalid context: %s\n", argv[arg]);
		    contextlen = 0;
		    usage();
		    exit(1);
		}
	    }
	} else if (isdigit(argv[0][0])) {
            interval = atoi(argv[0]);
            if (interval <= 0){
		usage();
		exit(1);
	    }
	    iflag++;
	} else {
	    usage();
	    exit(1);
	}
    }
    
    if (!hostname || (version < 1) || (version > 2)
	|| (version == 1 && !community)
	|| (version == 2 && (!srclen || !dstlen || !contextlen)
	    && !trivialSNMPv2)){
	usage();
	exit(1);
    }
    
    if (trivialSNMPv2){
	if ((destAddr = inet_addr(hostname)) == -1){
	    hp = gethostbyname(hostname);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", hostname);
		exit(1);
	    } else {
		bcopy((char *)hp->h_addr, (char *)&destAddr,
		      hp->h_length);
	    }
	}
	srclen = dstlen = contextlen = MAX_NAME_LEN;
	ms_party_init(destAddr, src, &srclen, dst, &dstlen,
		      context, &contextlen);
    }
    
    if (clock_flag){
	pp = party_getEntry(src, srclen);
	if (pp){
            pp->partyAuthClock = srcclock;
            gettimeofday(&pp->tv, (struct timezone *)0);
            pp->tv.tv_sec -= pp->partyAuthClock;
	}
	pp = party_getEntry(dst, dstlen);
	if (pp){
            pp->partyAuthClock = dstclock;
            gettimeofday(&pp->tv, (struct timezone *)0);
            pp->tv.tv_sec -= pp->partyAuthClock;
	}
    }
    
    
    bzero((char *)&session, sizeof(struct snmp_session));
    session.peername = hostname;
    if (port_flag)
        session.remote_port = dest_port;
    if (version == 1){
        session.version = SNMP_VERSION_1;
        session.community = (u_char *)community;
        session.community_len = strlen((char *)community);
    } else if (version == 2){
        session.version = SNMP_VERSION_2;
        session.srcParty = src;
        session.srcPartyLen = srclen;
        session.dstParty = dst;
        session.dstPartyLen = dstlen;
        session.context = context;
        session.contextLen = contextlen;
    }

    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.authenticator = NULL;
    snmp_synch_setup(&session);
    Session = snmp_open(&session);
    if (Session == NULL){
	printf("Couldn't open snmp\n");
	exit(-1);
    }
    if (pflag) {
	if (tp->pr_stats)
	    (*tp->pr_stats)();
	else
	    printf("%s: no stats routine\n", tp->pr_name);
	exit(0);
    }
    
    
    
    /*
     * Keep file descriptors open to avoid overhead
     * of open/close on each call to get* routines.
     */
    sethostent(1);
    setnetent(1);
    if (iflag) {
	intpr(interval);
	exit(0);
    }
    if (rflag) {
	if (sflag)
	    rt_stats();
	else
	    routepr();
	exit(0);
    }
    
    setprotoent(1);
    setservent(1);
    while (p = getprotoent()) {
	
	for (tp = protox; tp->pr_name; tp++)
	    if (strcmp(tp->pr_name, p->p_name) == 0)
		break;
	if (tp->pr_name == 0 || tp->pr_wanted == 0)
	    continue;
	if (sflag) {
	    if (tp->pr_stats)
		(*tp->pr_stats)();
	} else
	    if (tp->pr_cblocks)
		(*tp->pr_cblocks)();
    }
    endprotoent();
    exit(0);
}

char *
plural(n)
	int n;
{

	return (n != 1 ? "s" : "");
}

/*
 * Find the protox for the given "well-known" name.
 */
struct protox *
knownname(name)
	char *name;
{
	struct protox *tp;
	
	for (tp = protox; tp->pr_name; tp++)
		if (strcmp(tp->pr_name, name) == 0)
			return(tp);
	return(NULLPROTOX);
}

/*
 * Find the protox corresponding to name.
 */
struct protox *
name2protox(name)
	char *name;
{
	struct protox *tp;
	char **alias;			/* alias from p->aliases */
	struct protoent *p;
	
	/*
	 * Try to find the name in the list of "well-known" names. If that
	 * fails, check if name is an alias for an Internet protocol.
	 */
	if (tp = knownname(name))
		return(tp);
		
	setprotoent(1);			/* make protocol lookup cheaper */
	while (p = getprotoent()) {
		/* assert: name not same as p->name */
		for (alias = p->p_aliases; *alias; alias++)
			if (strcmp(name, *alias) == 0) {
				endprotoent();
				return(knownname(p->p_name));
			}
	}
	endprotoent();
	return(NULLPROTOX);
}
