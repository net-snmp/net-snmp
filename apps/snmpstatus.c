/*
 * snmpstatus.c - send snmp GET requests to a network entity.
 *
 */
/***********************************************************************
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
#include <config.h>

#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <ctype.h>
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
#include "mib.h"

extern int  errno;
int	snmp_dump_packet = 0;

oid	objid_sysDescr[] = {1, 3, 6, 1, 2, 1, 1, 1, 0};
int	length_sysDescr = sizeof(objid_sysDescr)/sizeof(oid);
oid	objid_sysUpTime[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
int	length_sysUpTime = sizeof(objid_sysUpTime)/sizeof(oid);
oid	objid_ifOperStatus[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 8};
int	length_ifOperStatus = sizeof(objid_ifOperStatus)/sizeof(oid);
oid	objid_ifInUCastPkts[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 11};
int	length_ifInUCastPkts = sizeof(objid_ifInUCastPkts)/sizeof(oid);
oid	objid_ifInNUCastPkts[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 12};
int	length_ifInNUCastPkts = sizeof(objid_ifInNUCastPkts)/sizeof(oid);
oid	objid_ifOutUCastPkts[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 17};
int	length_ifOutUCastPkts = sizeof(objid_ifOutUCastPkts)/sizeof(oid);
oid	objid_ifOutNUCastPkts[] = {1, 3, 6, 1, 2, 1, 2, 2, 1, 18};
int	length_ifOutNUCastPkts = sizeof(objid_ifOutNUCastPkts)/sizeof(oid);
oid	objid_ipInReceives[] = {1, 3, 6, 1, 2, 1, 4, 3, 0};
int	length_ipInReceives = sizeof(objid_ipInReceives)/sizeof(oid);
oid	objid_ipOutRequests[] = {1, 3, 6, 1, 2, 1, 4, 10, 0};
int	length_ipOutRequests = sizeof(objid_ipOutRequests)/sizeof(oid);

usage(){
    fprintf(stderr, "Usage: snmpstatus -v 1 [-q] hostname community               or:\n");
    fprintf(stderr, "Usage: snmpstatus [-v 2] [-q] hostname noAuth                or:\n");
    fprintf(stderr, "Usage: snmpstatus [-v 2] [-q] hostname srcParty dstParty context\n");
    exit (1);
}

char *uptime_string(timeticks, buf)
    register u_long timeticks;
    char *buf;
{
    int	seconds, minutes, hours, days;

    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (days == 0){
	sprintf(buf, "%d:%02d:%02d", hours, minutes, seconds);
    } else if (days == 1) {
	sprintf(buf, "%d day, %d:%02d:%02d", days, hours, minutes, seconds);
    } else {
	sprintf(buf, "%d days, %d:%02d:%02d", days, hours, minutes, seconds);
    }
    return buf;
}

int snmp_v1_setup (session, host, community)
struct snmp_session *session;
char *host;
char *community;
{
    bzero((char *)session, sizeof(struct snmp_session));
    session->peername = host;
    session->version = SNMP_VERSION_1;
    session->community = (u_char *)community;
    session->community_len = strlen((char *)community);
    session->retries = SNMP_DEFAULT_RETRIES;
    session->timeout = SNMP_DEFAULT_TIMEOUT;
    return 0;
}

int snmp_v2_setup (session, host, srcparty, dstparty, context, srcclock, dstclock)
struct snmp_session *session;
char *host;
char *srcparty;
char *dstparty;
char *context;
u_long srcclock, dstclock;
{
    static oid src[MAX_NAME_LEN], dst[MAX_NAME_LEN], cxt[MAX_NAME_LEN];
    int srclen = 0, dstlen = 0, cxtlen = 0;
    struct partyEntry *pp;
    struct contextEntry *cxp;
    int trivialSNMPv2 = FALSE;
    char ctmp [1024];
    struct hostent *hp;
    u_long destAddr;

    if (strcasecmp(srcparty, "noauth") == 0) trivialSNMPv2 = TRUE;

    if (trivialSNMPv2){
	if ((destAddr = inet_addr(host)) == -1){
	    hp = gethostbyname(host);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", host);
		exit(1);
	    } else {
		bcopy((char *)hp->h_addr, (char *)&destAddr,
		      hp->h_length);
	    }
	}
	srclen = dstlen = cxtlen = MAX_NAME_LEN;
	ms_party_init(destAddr, src, &srclen, dst, &dstlen,
		      cxt, &cxtlen);
    }
    else {
	sprintf(ctmp,"%s/party.conf",SNMPLIBPATH);
	if (read_party_database(ctmp) > 0){
	    fprintf(stderr,
		    "Couldn't read party database from %s\n",ctmp);
	    exit(1);
	}
	sprintf(ctmp,"%s/context.conf",SNMPLIBPATH);
	if (read_context_database(ctmp) > 0){
	    fprintf(stderr,
		    "Couldn't read context database from %s\n",ctmp);
	    exit(1);
	}
	sprintf(ctmp,"%s/acl.conf",SNMPLIBPATH);
	if (read_acl_database(ctmp) > 0){
	    fprintf(stderr,
		    "Couldn't read access control database from %s\n",ctmp);
	    exit(1);
	}

	party_scanInit();
	for(pp = party_scanNext(); pp; pp = party_scanNext()){
	    if (!strcasecmp(pp->partyName, srcparty)){
		srclen = pp->partyIdentityLen;
		bcopy(pp->partyIdentity, src, srclen * sizeof(oid));
		break;
	    }
	}
	if (!pp){
	    srclen = MAX_NAME_LEN;
	    if (!read_objid(srcparty, src, &srclen)){
		fprintf(stderr,"Invalid source party: %s\n", srcparty);
		srclen = 0;
		usage();
	    }
	}

	party_scanInit();
	for(pp = party_scanNext(); pp; pp = party_scanNext()){
	    if (!strcasecmp(pp->partyName, dstparty)){
		dstlen = pp->partyIdentityLen;
		bcopy(pp->partyIdentity, dst, dstlen * sizeof(oid));
		break;
	    }
	}
	if (!pp){
	    dstlen = MAX_NAME_LEN;
	    if (!read_objid(dstparty, dst, &dstlen)){
		fprintf(stderr,"Invalid destination party: %s\n", dstparty);
		dstlen = 0;
		usage();
	    }
	}

	cxtlen = MAX_NAME_LEN;
	context_scanInit();
	for(cxp = context_scanNext(); cxp; cxp = context_scanNext()){
	    if (!strcasecmp(cxp->contextName, context)){
		cxtlen = cxp->contextIdentityLen;
		bcopy(cxp->contextIdentity, cxt,
		      cxtlen * sizeof(oid));
		break;
	    }
	}
	if (!cxp){
	    if (!read_objid(context, cxt, &cxtlen)){
		fprintf(stderr,"Invalid context: %s\n", context);
		cxtlen = 0;
		usage();
	    }
	}
    }

    if (srcclock != 0){
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

    bzero((char *)session, sizeof(struct snmp_session));
    session->peername = host;
    session->version = SNMP_VERSION_2;
    session->srcParty = src;
    session->srcPartyLen = srclen;
    session->dstParty = dst;
    session->dstPartyLen = dstlen;
    session->context = cxt;
    session->contextLen = cxtlen;
    session->retries = SNMP_DEFAULT_RETRIES;
    session->timeout = SNMP_DEFAULT_TIMEOUT;
    return 0;
}

main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    char *hostname = NULL;
    char *community = NULL;
    char *srcparty = NULL, *dstparty = NULL, *context = NULL;
    int timeout_flag = 0, timeout, retransmission_flag = 0, retransmission;
    char name[MAX_NAME_LEN];
    int status;
    int version = 2;
    int port_flag = 0;
    int dest_port = 0;
    u_long      srcclock = 0, dstclock = 0;
    int clock_flag = 0;
    u_long uptime;
    int ipin = 0, ipout = 0, ipackets = 0, opackets = 0;
    int good_var;
    int down_interfaces = 0;
    char buf[40];
    int index, count;
    int c;

    extern int getopt ();
    extern char *optarg;
    extern int optind;

    init_mib();
    while ((c = getopt (argc, argv, "dqp:v:t:r:")) != -1)
	switch (c) {
	    case 'd':
		snmp_dump_packet++;
		break;
	    case 'q':
		quick_print++;
		break;
	    case 'p':
		port_flag++;
		dest_port = atoi(optarg);
		break;
	    case 't':
		timeout_flag++;
		timeout = atoi(optarg) * 1000000L;
		break;
	    case 'r':
		retransmission_flag++;
		retransmission = atoi(optarg);
		break;
	    case 'c':
		clock_flag++;
		srcclock = atoi(optarg);
		dstclock = atoi(argv[optind++]);
		break;
	    case 'v':
		version = atoi(optarg);
		if (version < 1 || version > 2){
		    fprintf(stderr, "Invalid version\n");
		    usage();
		}
		break;
	    default:
		usage();
		break;
	}

    if (optind == argc) usage ();
    hostname = argv[optind++];
    if (version == 1){
	if (optind == argc) usage ();
	community = argv[optind++];
    } else if (version == 2) {
	if (optind == argc) usage ();
	srcparty = argv[optind++];
	if (strcasecmp(srcparty, "noauth")){
	    dstparty = argv[optind++];
	    context = argv[optind++];
	    if (optind > argc) usage();
	}
    }

    if (version == 1){
	snmp_v1_setup (&session, hostname, community);
    } else if (version == 2){
	snmp_v2_setup (&session, hostname, srcparty, dstparty, context,
		       srcclock, dstclock);
    }
    if (retransmission_flag)
        session.retries = retransmission;
    if (timeout_flag)
        session.timeout = timeout;
    if (port_flag)
        session.remote_port = dest_port;

    snmp_synch_setup(&session);
    ss = snmp_open(&session);
    if (ss == NULL){
	fprintf(stderr,"Couldn't open snmp\n");
	exit(1);
    }

    strcpy(name, "No System Description Available");
    pdu = snmp_pdu_create(GET_REQ_MSG);

    snmp_add_null_var(pdu, objid_sysDescr, length_sysDescr);
    snmp_add_null_var(pdu, objid_sysUpTime, length_sysUpTime);
    snmp_add_null_var(pdu, objid_ipInReceives, length_ipInReceives);
    snmp_add_null_var(pdu, objid_ipOutRequests, length_ipOutRequests);

retry:
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
	if (response->errstat == SNMP_ERR_NOERROR){
	    for(vars = response->variables; vars; vars = vars->next_variable){
		if (vars->name_length == length_sysDescr &&
		    !bcmp((char *)objid_sysDescr, (char*)vars->name, sizeof(objid_sysDescr))){
			bcopy((char *)vars->val.string, name, vars->val_len);
			name[vars->val_len] = '\0';
		}
		if (vars->name_length == length_sysUpTime &&
		    !bcmp((char *)objid_sysUpTime, (char*)vars->name, sizeof(objid_sysUpTime))){
			uptime = *vars->val.integer;
		}
		if (vars->name_length == length_ipInReceives &&
		    !bcmp((char *)objid_ipInReceives, (char*)vars->name, sizeof(objid_ipInReceives))){
			ipin = *vars->val.integer;
		}
		if (vars->name_length == length_ipOutRequests &&
		    !bcmp((char *)objid_ipOutRequests, (char*)vars->name, sizeof(objid_ipOutRequests))){
			ipout = *vars->val.integer;
		}
	    }
	} else {
	    printf("Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
	    if (response->errstat == SNMP_ERR_NOSUCHNAME){
		printf("This name doesn't exist: ");
		for(count = 1, vars = response->variables; vars && count != response->errindex;
		    vars = vars->next_variable, count++)
			;
		if (vars)
		    print_objid(vars->name, vars->name_length);
		printf("\n");
	    }
	    if ((pdu = snmp_fix_pdu(response, GET_REQ_MSG)) != NULL)
		goto retry;
	}

    } else if (status == STAT_TIMEOUT){
	fprintf(stderr,"No Response from %s\n", hostname);
	exit(1);
    } else {    /* status == STAT_ERROR */
	fprintf(stderr,"An error occurred, Quitting\n");
	exit(2);
    }

    printf("[%s]=>[%s] Up: %s\n", inet_ntoa(response->address.sin_addr), name,
	uptime_string(uptime, buf));

    if (response)
	snmp_free_pdu(response);

    pdu = snmp_pdu_create(GETNEXT_REQ_MSG);

    snmp_add_null_var(pdu, objid_ifOperStatus, length_ifOperStatus);
    snmp_add_null_var(pdu, objid_ifInUCastPkts, length_ifInUCastPkts);
    snmp_add_null_var(pdu, objid_ifInNUCastPkts, length_ifInNUCastPkts);
    snmp_add_null_var(pdu, objid_ifOutUCastPkts, length_ifOutUCastPkts);
    snmp_add_null_var(pdu, objid_ifOutNUCastPkts, length_ifOutNUCastPkts);

    good_var = 5;
    while(good_var == 5){
	good_var = 0;
	status = snmp_synch_response(ss, pdu, &response);
	if (status == STAT_SUCCESS){
	    if (response->errstat == SNMP_ERR_NOERROR){
		pdu = snmp_pdu_create(GETNEXT_REQ_MSG);

		index = 0;
		for(vars = response->variables; vars; vars = vars->next_variable){
		    if (index == 0 && vars->name_length >= length_ifOperStatus &&
			!bcmp((char *)objid_ifOperStatus, (char *)vars->name,
			sizeof(objid_ifOperStatus))){
			    if (*vars->val.integer != MIB_IFSTATUS_UP)
				down_interfaces++;
			    snmp_add_null_var(pdu, vars->name, vars->name_length);
			    good_var++;
		    } else if (index == 1 && vars->name_length >= length_ifInUCastPkts &&
			!bcmp((char *)objid_ifInUCastPkts, (char *)vars->name,
			sizeof(objid_ifInUCastPkts))){
			    ipackets += *vars->val.integer;
			    snmp_add_null_var(pdu, vars->name, vars->name_length);
			    good_var++;
		    } else if (index == 2 && vars->name_length >= length_ifInNUCastPkts &&
			!bcmp((char *)objid_ifInNUCastPkts, (char *)vars->name,
			sizeof(objid_ifInNUCastPkts))){
			    ipackets += *vars->val.integer;
			    snmp_add_null_var(pdu, vars->name, vars->name_length);
			    good_var++;
		    } else if (index == 3 && vars->name_length >= length_ifOutUCastPkts &&
			!bcmp((char *)objid_ifOutUCastPkts, (char *)vars->name,
			sizeof(objid_ifOutUCastPkts))){
			    opackets += *vars->val.integer;
			    snmp_add_null_var(pdu, vars->name, vars->name_length);
			    good_var++;
		    } else if (index == 4 && vars->name_length >= length_ifOutNUCastPkts &&
			!bcmp((char *)objid_ifOutNUCastPkts, (char *)vars->name,
			sizeof(objid_ifOutNUCastPkts))){
			    opackets += *vars->val.integer;
			    snmp_add_null_var(pdu, vars->name, vars->name_length);
			    good_var++;
		    }
		    index++;
		}
	    } else {
		printf("Error in packet.\nReason: %s\n", snmp_errstring(response->errstat));
		if (response->errstat == SNMP_ERR_NOSUCHNAME){
		    printf("This name doesn't exist: ");
		    for(count = 1, vars = response->variables; vars && count != response->errindex;
			vars = vars->next_variable, count++)
			    ;
		    if (vars)
			print_objid(vars->name, vars->name_length);
		    printf("\n");
		}
	    }

	} else if (status == STAT_TIMEOUT){
	    fprintf(stderr,"No Response from %s\n", hostname);
	} else {    /* status == STAT_ERROR */
	    fprintf(stderr,"An error occurred, Quitting\n");
	}

	if (response)
	    snmp_free_pdu(response);
    }
    printf("Recv/Trans packets: Interfaces: %d/%d | IP: %d/%d\n", ipackets, opackets, ipin, ipout);
    if (down_interfaces > 0){
	printf("%d interface%s down!\n", down_interfaces, down_interfaces > 1 ? "s are": " is" );
    }
    exit (0);
}
