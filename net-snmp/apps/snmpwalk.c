/*
 * snmpwalk.c - send snmp GETNEXT requests to a network entity, walking a
 * subtree.
 *
 */
/**********************************************************************
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
******************************************************************/
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>
#include <netdb.h>

#include "snmp.h"
#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "party.h"
#include "context.h"
#include "view.h"
#include "acl.h"

oid objid_mib[] = {1, 3, 6, 1, 2, 1};

int	snmp_dump_packet = 0;

usage(){
    fprintf(stderr, "Usage: snmpwalk -v 1 hostname community [objectID]      or:\n");
    fprintf(stderr, "Usage: snmpwalk [-v 2 ] hostname noAuth [objectID]      or:\n");
    fprintf(stderr, "Usage: snmpwalk [-v 2 ] hostname srcParty dstParty context [objectID]\n");
}

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
    u_long	srcclock, dstclock;
    int clock_flag = 0;
    struct partyEntry *pp;
    struct contextEntry *cxp;
    int trivialSNMPv2 = FALSE;
    struct hostent *hp;
    u_long destAddr;

    init_mib();
    /*
     * Usage: snmpwalk -v 1 hostname community [objectID]      or:
     * Usage: snmpwalk [-v 2 ] hostname noAuth [objectID]      or:
     * Usage: snmpwalk [-v 2 ] hostname srcParty dstParty context [objectID]
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
	bcopy((char *)objid_mib, (char *)root, sizeof(objid_mib));
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
    session.timeout = 2000000L;
    session.authenticator = NULL;
    snmp_synch_setup(&session);
    ss = snmp_open(&session);
    if (ss == NULL){
	printf("Couldn't open snmp\n");
	exit(-1);
    }


    bcopy((char *)root, (char *)name, rootlen * sizeof(oid));
    name_length = rootlen;

    running = 1;
    while(running){
	running = 0;
	pdu = snmp_pdu_create(GETNEXT_REQ_MSG);

	snmp_add_null_var(pdu, name, name_length);

	status = snmp_synch_response(ss, pdu, &response);
	if (status == STAT_SUCCESS){
	    if (response->errstat == SNMP_ERR_NOERROR){
		for(vars = response->variables; vars;
		    vars = vars->next_variable){
		    if (vars->name_length < rootlen
			|| bcmp(root, vars->name, rootlen * sizeof(oid)))
			continue;	/* not part of this subtree */
		    print_variable(vars->name, vars->name_length, vars);
		    if (vars->type != SNMP_ENDOFMIBVIEW
			&& vars->type != SNMP_NOSUCHOBJECT /* for robustness */
			&& vars->type != SNMP_NOSUCHINSTANCE){
			bcopy((char *)vars->name, (char *)name,
			      vars->name_length * sizeof(oid));
			name_length = vars->name_length;
			running = 1; /* restart so we can get next variable */
		    }
		}
	    } else {
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
	} else {    /* status == STAT_ERROR */
	    printf("An error occurred, Quitting\n");
	}

	if (response)
	    snmp_free_pdu(response);
    }
    snmp_close(ss);
}


#if 0
/*
 * to be part of security client library.
 */
find_params(srcParty, dstParty, context, ipaddress, entity, time, security)
    struct partyEntry *srcParty, *dstParty;
    struct contextEntry *context;
    u_long ipaddress;
    char *entity;
    char *time;
    char *security;
{
    struct partyEntry *pp, *goodParties[32];
    struct contextEntry *cxp, *goodContexts[32];
    struct aclEntry *ap;
    int numParties = 0, numContexts = 0;

    party_scanInit();
    for(pp = party_scanNext(); pp; pp = party_scanNext()){
	if (pp->partyTDomain == 1 && !bcmp(pp->partyTAddress, &ipaddress, 4)){
	    if (security == 0 || *security == '\0' || !strcmp(security, "*")){
		goodParties[numParties++] = pp;
	    } else if (!strcmp(security, "auth")
		       && (pp->partyAuthProtocol == 6)){
		goodParties[numParties++] = pp;
	    } else if (!strcmp(security, "priv")
		       && (pp->partyPrivProtocol == 4)){
		goodParties[numParties++] = pp;
	    }
	}
    }
    /*
     * Unfinished ...
     */
}

#endif
