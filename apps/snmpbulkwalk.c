/*
 * snmpbulkwalk.c - send SNMPv2 Bulk requests to a network entity, walking a
 * subtree.
 *
 */
/*********************************************************************
	Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

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
**********************************************************************/
#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#include <stdio.h>
#include <netdb.h>
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "party.h"
#include "context.h"
#include "view.h"
#include "acl.h"

int main __P((int, char **));

oid objid_mib[] = {1, 3, 6, 1, 2, 1};

void
usage __P((void))
{
    fprintf(stderr, "Usage: snmpbulkwalk -v 1 [-q] hostname community [objectID]      or:\n");
    fprintf(stderr, "Usage: snmpbulkwalk [-v 2] [-q] hostname noAuth [objectID]       or:\n");
    fprintf(stderr, "Usage: snmpbulkwalk [-v 2] [-q] hostname srcParty dstParty context [objectID]\n");
}

int
main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session	session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    int	arg;
    char *hostname = NULL;
    char *community = NULL;
    int gotroot = 0, version = 2;
    oid	name[MAX_NAME_LEN];
    int name_length;
    oid root[MAX_NAME_LEN];
    int	rootlen, count;
    int running;
    int status;
    int port_flag = 0;
    int dest_port = 0;
    oid src[MAX_NAME_LEN], dst[MAX_NAME_LEN], context[MAX_NAME_LEN];
    int srclen = 0, dstlen = 0, contextlen = 0;
    u_long	srcclock = 0, dstclock = 0;
    int clock_flag = 0;
    struct partyEntry *pp;
    struct contextEntry *cxp;
    int reps = 1000;
    int trivialSNMPv2 = FALSE;
    struct hostent *hp;
    u_long destAddr;
    char ctmp[300];

    init_mib();
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
		case 'd':
		    snmp_set_dump_packet(1);
		    break;
		case 'q':
		    snmp_set_quick_print(1);
		    break;
		case 'r':
		    reps = atoi(argv[++arg]);
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
                        fprintf(stderr, "Invalid version\n");
                        usage();
                        exit(1);
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
            sprintf(ctmp,"%s/party.conf",SNMPLIBPATH);
	    if (read_party_database(ctmp) != 0){
		fprintf(stderr,
			"Couldn't read party database from %s\n",ctmp);
		exit(0);
	    }
            sprintf(ctmp,"%s/context.conf",SNMPLIBPATH);
	    if (read_context_database(ctmp) != 0){
		fprintf(stderr,
			"Couldn't read context database from %s\n",ctmp);
		exit(0);
	    }
            sprintf(ctmp,"%s/acl.conf",SNMPLIBPATH);
	    if (read_acl_database(ctmp) != 0){
		fprintf(stderr,
			"Couldn't read access control database from %s\n",ctmp);
		exit(0);
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
	} else {
	    rootlen = MAX_NAME_LEN;
	    if (read_objid(argv[arg], root, &rootlen)){
		gotroot = 1;
	    } else {
		printf("Invalid object identifier: %s\n", argv[arg]);
	    }
	}
    }

    if (gotroot == 0){
      memmove(root, objid_mib, sizeof(objid_mib));
	rootlen = sizeof(objid_mib) / sizeof(oid);
	gotroot = 1;
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
    session.timeout = 2000000L;
    session.authenticator = NULL;
    snmp_synch_setup(&session);
    ss = snmp_open(&session);
    if (ss == NULL){
	printf("Couldn't open snmp\n");
	exit(-1);
    }


    memmove(name, root, rootlen * sizeof(oid));
    name_length = rootlen;

    running = 1;
    while(running){
	running = 1;
	pdu = snmp_pdu_create(BULK_REQ_MSG);
	pdu->non_repeaters = 0;
	pdu->max_repetitions = reps;	/* fill the packet */

	snmp_add_null_var(pdu, name, name_length);

	status = snmp_synch_response(ss, pdu, &response);
	if (status == STAT_SUCCESS){
	    if (response->errstat == SNMP_ERR_NOERROR){
		for(vars = response->variables; vars;
		    vars = vars->next_variable){
		    if (vars->name_length < rootlen
			|| memcmp(root, vars->name, rootlen * sizeof(oid))){
			running = 0;
			continue;	/* not part of this subtree */
		    }
		    print_variable(vars->name, vars->name_length, vars);
		    if (vars->type == SNMP_ENDOFMIBVIEW
			|| vars->type == SNMP_NOSUCHOBJECT /* for robustness */
			|| vars->type == SNMP_NOSUCHINSTANCE){
			running = 0; /* restart so we can get next variable */
		    }
		    if (!vars->next_variable){ /* repeat on last variable */
                      memmove(name, vars->name,
			  vars->name_length * sizeof(oid));
			name_length = vars->name_length;
		    }
		}
	    } else {
		running = 0;
		if (response->errstat == SNMP_ERR_NOSUCHNAME){
		    printf("End of MIB.\n");
		} else {
		    printf("Error in packet.\nReason: %s\n",
			   snmp_errstring(response->errstat));
		    if (response->errstat == SNMP_ERR_NOSUCHNAME){
			printf("The request for this object identifier failed: ");
			for(count = 1, vars = response->variables; vars
			    && count != response->errindex;
			    vars = vars->next_variable, count++)
				/*EMPTY*/;
			if (vars)
			    print_objid(vars->name, vars->name_length);
			printf("\n");
		    }
		}
	    }

	} else if (status == STAT_TIMEOUT){
	    printf("No Response from %s\n", hostname);
	    running = 0;
	} else {    /* status == STAT_ERROR */
	    printf("An error occurred, Quitting\n");
	    running = 0;
	}

	if (response)
	    snmp_free_pdu(response);
    }
    snmp_close(ss);
    exit (0);
}
