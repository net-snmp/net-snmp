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

#include <config.h>

#ifndef lint
char copyright[] =
"@(#) Copyright (c) 1983 Regents of the University of California.\n\
 All rights reserved.\n";
#endif not lint

#ifdef STDC_HEADERS
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#endif

#include <sys/types.h>
#include <sys/param.h>

#include <sys/socket.h>
#include <sys/time.h>
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#include <netdb.h>

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "asn1.h"
#include "mib.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "party.h"
#include "context.h"
#include "view.h"
#include "acl.h"
#include "version.h"

#include "netstat.h"

int main __P((int, char **));

#define NULLPROTOX	((struct protox *) 0)
struct protox {
	u_char	pr_wanted;		/* 1 if wanted, 0 otherwise */
	void	(*pr_cblocks) __P((void));	/* control blocks printing routine */
	void	(*pr_stats) __P((void));	/* statistics printing routine */
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
int	oflag;
int	nflag;
int	rflag;
int	sflag;
int	interval;
char	*interface;

struct snmp_session *Session;
int print_errors = 0;

void
usage __P((void))
{
    fprintf(stderr, "Usage: snmpnetstat -v 1 [-q] hostname community [-ainrs] [-p proto] [-I interface] [interval]      or:\n");
    fprintf(stderr, "Usage: snmpnetstat [-v 2] [-q] hostname noAuth [-ainrs] [-p proto] [-I interface] [interval]       or:\n");
    fprintf(stderr, "Usage: snmpnetstat [-v 2] [-q] hostname srcParty dstParty context [-ainrs] [-p proto] [-I interface] [interval]\n");
}

int
main(argc, argv)
	int argc;
	char *argv[];
{
    char *hostname = NULL;
    register struct protoent *p;
    register struct protox *tp = NULL;	/* for printing cblocks & stats */
    char *community = NULL;
    struct snmp_session session;
    
    int dest_port = SNMP_PORT;
    int clock_flag = 0;
    u_long	srcclock = 0, dstclock = 0;
    int version = 2;
    struct partyEntry *pp;
    struct contextEntry *cxp;
    oid src[MAX_NAME_LEN], dst[MAX_NAME_LEN], context[MAX_NAME_LEN];
    int srclen = 0, dstlen = 0, contextlen = 0;
    int trivialSNMPv2 = FALSE;
    struct hostent *hp;
    in_addr_t destAddr;
    int arg;
#ifdef _DEBUG_MALLOC_INC
    unsigned long histid1, histid2, orig_size, current_size;
#endif
    
    init_mib();
    /*
     * Usage: snmpnetstatwalk -v 1 [-q] hostname community ...      or:
     * Usage: snmpnetstat [-v 2 ] [-q] hostname noAuth     ...      or:
     * Usage: snmpnetstat [-v 2 ] [-q] hostname srcParty dstParty context ...
     */
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
              case 'V':
                fprintf(stderr,"UCD-snmp version: %s\n", VersionInfo);
                exit(0);
                break;
	      case 'd':
		snmp_set_dump_packet(1);
		break;
	      case 'q':
		snmp_set_quick_print(1);
		break;
	      case 'p':
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

                case 'o':
                        oflag++;
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
                        arg++;
                        if ((tp = name2protox(argv [arg])) == NULLPROTOX) {
                                fprintf(stderr, "%s: unknown or uninstrumented protocol\n",
                                        argv [arg]);
                                exit(1);
                        }
                        break;

                case 'I':
                        iflag++;
                        if (*(interface = argv[arg] + 2) == 0) {
                                arg++;
                                if ((interface = argv[arg]) == 0)
                                        break;
                        }
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
		exit(1);
	    }
	    if (read_context_database("/etc/context.conf") > 0){
		fprintf(stderr,
			"Couldn't read context database from /etc/context.conf\n");
		exit(1);
	    }
	    if (read_acl_database("/etc/acl.conf") > 0){
		fprintf(stderr,
			"Couldn't read access control database from /etc/acl.conf\n");
		exit(1);
	    }
	    
	    if (!strcasecmp(argv[arg], "noauth")){
		trivialSNMPv2 = TRUE;
	    } else {
		party_scanInit();
		for(pp = party_scanNext(); pp; pp = party_scanNext()){
		    if (!strcasecmp(pp->partyName, argv[arg])){
			srclen = pp->partyIdentityLen;
			memmove(src, pp->partyIdentity, srclen * sizeof(oid));
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
		    memmove(dst, pp->partyIdentity, dstlen * sizeof(oid));
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
		    memmove(context, cxp->contextIdentity,
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
	} else if (isdigit(argv[arg][0])) {
            interval = atoi(argv[arg]);
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
              memmove(&destAddr, hp->h_addr, hp->h_length);
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
    
    
    memset(&session, 0, sizeof(struct snmp_session));
    session.peername = hostname;
    session.remote_port = dest_port;
    if (version == 1){
        session.version = SNMP_VERSION_1;
        session.community = (u_char *)community;
        session.community_len = strlen((char *)community);
    } else if (version == 2){
        session.version = SNMP_VERSION_2p;
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
	exit(1);
    }

#ifdef _DEBUG_MALLOC_INC
    orig_size = malloc_inuse(&histid1);
#endif
    
    /*
     * Keep file descriptors open to avoid overhead
     * of open/close on each call to get* routines.
     */
    sethostent(1);
    setnetent(1);
    setprotoent(1);
    setservent(1);

    if (tp) {
	if (tp->pr_stats)
	    (*tp->pr_stats)();
	else {
	    printf("%s: no stats routine\n", tp->pr_name);
	    exit(1);
	}
    }
    if (iflag) {
	intpr(interval);
    }
    if (oflag) {
	intpro(interval);
    }
    if (rflag) {
	if (sflag)
	    rt_stats();
	else
	    routepr();
    }
    
    if (tp || iflag || rflag || oflag)
	exit(0);

    while ((p = getprotoent())) {
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
    endservent();
    endnetent();
    endhostent();

    snmp_close(Session);

#ifdef _DEBUG_MALLOC_INC
    current_size = malloc_inuse(&histid2);
    if (current_size != orig_size) malloc_list(2, histid1, histid2);
#endif

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
	if ((tp = knownname(name)))
		return(tp);
		
	setprotoent(1);			/* make protocol lookup cheaper */
	while ((p = getprotoent())) {
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
