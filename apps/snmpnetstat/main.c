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
#endif /* not lint */

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <sys/types.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#include "winstub.h"
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif

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
#include "version.h"
#include "snmp_debug.h"
#include "system.h"

#include "netstat.h"

#define NULLPROTOX	((struct protox *) 0)
struct protox {
	u_char	pr_wanted;		/* 1 if wanted, 0 otherwise */
	void	(*pr_cblocks) (const char *);	/* control blocks printing routine */
	void	(*pr_stats) (void);	/* statistics printing routine */
	const char	*pr_name;	/* well-known name */
} protox[] = {
	{ 0,	protopr,    tcp_stats,	"tcp" },
	{ 0,	protopr,    udp_stats,	"udp" },
	{ 0,	0,	    ip_stats,	"ip" },
	{ 0,	0,	    icmp_stats,	"icmp" },
	{ 0,	0,	    0,		0 }
};

int	aflag;
int	iflag;
int	oflag;
int	nflag;
int	rflag;
int	sflag;
int	interval;
char	*intrface;

struct snmp_session *Session;
int print_errors = 0;

void usage(void)
{
    fprintf(stderr, "Usage: snmpnetstat [-v 1 | -v 2c] [-q] [-D] hostname community [-ainrs] [-P proto] [-I interface] [interval]      or:\n");
    fprintf(stderr, "Usage: snmpnetstat [-v 2p] [-q] [-D] hostname noAuth [-ainrs] [-P proto] [-I interface] [interval]       or:\n");
    fprintf(stderr, "Usage: snmpnetstat [-v 2p] [-q] [-D] hostname srcParty dstParty context [-ainrs] [-P proto] [-I interface] [interval]\n");
}

int main(int argc, char *argv[])
{
    char *hostname = NULL;
    struct protoent *p;
    struct protox *tp = NULL;	/* for printing cblocks & stats */
    int allprotos = 1;
    char *community = NULL;
    struct snmp_session session;
    int dest_port = SNMP_PORT;
    int clock_flag = 0;
    u_long	srcclock = 0, dstclock = 0;
    int version = SNMP_VERSION_1;
    size_t srclen = 0, dstlen = 0, contextlen = 0;
    int trivialSNMPv2 = FALSE;
    int arg;
#ifdef USE_V2PARTY_PROTOCOL
    char ctmp[128];
    struct partyEntry *pp;
    struct contextEntry *cxp;
    oid src[MAX_OID_LEN], dst[MAX_OID_LEN], context[MAX_OID_LEN];
    struct hostent *hp;
    in_addr_t destAddr;
#endif

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
	      case 'D':
                debug_register_tokens(&argv[arg][2]);
		snmp_set_do_debugging(1);
		break;
	      case 'p':
		if (++arg == argc) {
		    usage();
		    exit(1);
		}
		dest_port = atoi(argv[arg]);
		break;
	      case 'c':
		clock_flag++;
		srcclock = atoi(argv[++arg]);
		dstclock = atoi(argv[++arg]);
		break;
	      case 'v':
		if (argv[arg][2] != 0) community = argv[arg]+2;
		else community = argv[++arg];
		if (arg == argc) {
		    usage();
		    exit(1);
		}
		if (!strcmp(community,"1"))
		    version = SNMP_VERSION_1;
		else if (!strcmp(community,"2c"))
		    version = SNMP_VERSION_2c;
		else {
		    fprintf(stderr, "Invalid version: %s\n", community);
		    usage();
		    exit(1);
		}
		community = NULL;
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
		if (++arg == argc) {
		    usage();
		    exit(1);
		}
		if ((tp = name2protox(argv [arg])) == NULLPROTOX) {
		  fprintf(stderr, "%s: unknown or uninstrumented protocol\n",
			  argv [arg]);
		  exit(1);
		}
		allprotos = 0;
		tp->pr_wanted = 1;
		break;

	      case 'I':
		iflag++;
		if (*(intrface = argv[arg] + 2) == 0) {
		  if (++arg == argc) {
		      usage();
		      exit(1);
		  }
		  if ((intrface = argv[arg]) == 0)
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
	} else if ((version == SNMP_VERSION_1 || version == SNMP_VERSION_2c)
                   && community == NULL){
	    community = argv[arg]; 
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
    
    if (!hostname ||
	((version == SNMP_VERSION_1 || version == SNMP_VERSION_2c) && !community)
	|| (version == SNMP_VERSION_2p && (!srclen || !dstlen || !contextlen)
	    && !trivialSNMPv2)){
	usage();
	exit(1);
    }
    
    snmp_sess_init(&session);
    session.peername = hostname;
    session.remote_port = dest_port;
    if (version == SNMP_VERSION_1 || version == SNMP_VERSION_2c){
        session.version = version;
        session.community = (u_char *)community;
        session.community_len = strlen((char *)community);
    }

    SOCK_STARTUP;
    Session = snmp_open(&session);
    if (Session == NULL){
        snmp_sess_perror("snmpnetstat", &session);
        SOCK_CLEANUP;
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
    
    if (iflag || rflag || oflag)
	;
    else {

    while ((p = getprotoent())) {
	for (tp = protox; tp->pr_name; tp++)
	    if (strcmp(tp->pr_name, p->p_name) == 0)
		break;
	if (tp->pr_name == 0 || (tp->pr_wanted == 0 && allprotos == 0))
	    continue;
	if (sflag) {
	    if (tp->pr_stats)
		(*tp->pr_stats)();
	} else
	    if (tp->pr_cblocks)
		(*tp->pr_cblocks)(tp->pr_name);
    }
    } /* ! iflag, rflag, oflag */

    endprotoent();
    endservent();
    endnetent();
    endhostent();

    snmp_close(Session);

#ifdef _DEBUG_MALLOC_INC
    current_size = malloc_inuse(&histid2);
    if (current_size != orig_size) malloc_list(2, histid1, histid2);
#endif

    SOCK_CLEANUP;
    exit(0);
}

const char *
plural(int n)
{

	return (n != 1 ? "s" : "");
}

/*
 * Find the protox for the given "well-known" name.
 */
struct protox * 
knownname(const char *name)
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
name2protox(const char *name)
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
			if (strcasecmp(name, *alias) == 0) {
				endprotoent();
				return(knownname(p->p_name));
			}
	}
	endprotoent();
	return(NULLPROTOX);
}
