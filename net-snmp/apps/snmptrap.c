/*
 * snmptrap.c - send snmp traps to a network entity.
 *
 */
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
#include <config.h>

#ifdef HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif
#include <ctype.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
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
#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>
#include <net/if.h>
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#include <sys/file.h>
#include <nlist.h>
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif

#include "snmp.h"
#include "asn1.h"
#include "mib.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "party.h"
#include "system.h"

extern int  errno;
int	snmp_dump_packet = 0;
int ascii_to_binary();
int hex_to_binary();

#define NUM_NETWORKS	16   /* max number of interfaces to check */

oid objid_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1};
oid objid_sysdescr[]   = {1, 3, 6, 1, 2, 1, 1, 1, 0};
oid objid_sysuptime[]  = {1, 3, 6, 1, 2, 1, 1, 3, 0};
oid objid_snmptrap[]   = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
struct nlist nl[] = {
    { "_boottime" },
    { "" }
};

void
usage()
{
    fprintf(stderr, "usage:\n");
    fprintf(stderr, "snmptrap -v 1 manager community enterprise-oid agent trap-type specific-type uptime [ var ]...\n");
    fprintf(stderr, "or\n");
    fprintf(stderr, "snmptrap [-v 2] gateway srcParty dstParty [ var ] ...\n");
    exit (1);
}

int snmp_input(operation, session, reqid, pdu, magic)
int operation;
struct snmp_session *session;
int reqid;
struct snmp_pdu *pdu;
void *magic;
{
  return 1;
}

u_long parse_address(address)
    char *address;
{
    u_long addr;
    struct sockaddr_in saddr;
    struct hostent *hp;

    if ((addr = inet_addr(address)) != -1)
	return addr;
    hp = gethostbyname(address);
    if (hp == NULL){
	fprintf(stderr, "unknown host: %s\n", address);
	return 0;
    } else {
	memcpy(&saddr.sin_addr, hp->h_addr, hp->h_length);
	return saddr.sin_addr.s_addr;
    }

}

/*
 * Add a variable with the requested name to the end of the list of
 * variables for this pdu.
 */
void
snmp_add_var(pdu, name, name_length, type, value)
    struct snmp_pdu *pdu;
    oid *name;
    int name_length;
    char type, *value;
{
    struct variable_list *vars;
    char buf[2048];

    if (pdu->variables == NULL){
	pdu->variables = vars =
	    (struct variable_list *)malloc(sizeof(struct variable_list));
    } else {
	for(vars = pdu->variables;
	    vars->next_variable;
	    vars = vars->next_variable)
	    /*EXIT*/;
	vars->next_variable =
	    (struct variable_list *)malloc(sizeof(struct variable_list));
	vars = vars->next_variable;
    }

    vars->next_variable = NULL;
    vars->name = (oid *)malloc(name_length * sizeof(oid));
    memmove(vars->name, name, name_length * sizeof(oid));
    vars->name_length = name_length;

    switch((type = tolower (type))){
	case 'i':
	    vars->type = INTEGER;
	    vars->val.integer = (long *)malloc(sizeof(long));
	    *(vars->val.integer) = atoi(value);
	    vars->val_len = sizeof(long);
	    break;
	case 's':
	case 'x':
	case 'd':
	    vars->type = STRING;
	    if (type == 'd'){
		vars->val_len = ascii_to_binary((u_char *)value, buf);
	    } else if (type == 's'){
		strcpy(buf, value);
		vars->val_len = strlen(buf);
	    } else if (type == 'x'){
		vars->val_len = hex_to_binary((u_char *)value, buf);
	    }
	    vars->val.string = (u_char *)malloc(vars->val_len);
	    memmove(vars->val.string, buf, vars->val_len);
	    break;
	case 'n':
	    vars->type = NULLOBJ;
	    vars->val_len = 0;
	    vars->val.string = NULL;
	    break;
	case 'o':
	    vars->type = OBJID;
	    vars->val_len = MAX_NAME_LEN;
	    read_objid(value, (oid *)buf, &vars->val_len);
	    vars->val_len *= sizeof(oid);
	    vars->val.objid = (oid *)malloc(vars->val_len);
	    memmove(vars->val.objid, buf, vars->val_len);
	    break;
	case 't':
	    vars->type = TIMETICKS;
	    vars->val.integer = (long *)malloc(sizeof(long));
	    *(vars->val.integer) = atoi(value);
	    vars->val_len = sizeof(long);
	    break;
	case 'a':
	    vars->type = IPADDRESS;
	    vars->val.integer = (long *)malloc(sizeof(long));
	    *(vars->val.integer) = inet_addr(value);
	    vars->val_len = sizeof(long);
	    break;
	default:
	    fprintf(stderr, "Internal error in type switching: %c\n", type);
	    exit(1);
    }
}

int
ascii_to_binary(cp, bufp)
    u_char  *cp;
    u_char *bufp;
{
    int	subidentifier;
    u_char *bp = bufp;

    for(; *cp != '\0'; cp++){
	if (isspace(*cp) || *cp == '.')
	    continue;
	if (!isdigit(*cp)){
	    fprintf(stderr, "Input error\n");
	    return -1;
	}
	subidentifier = atoi(cp);
	if (subidentifier > 255){
	    fprintf(stderr, "subidentifier %d is too large ( > 255)\n",
		    subidentifier);
	    return -1;
	}
	*bp++ = (u_char)subidentifier;
	while(isdigit(*cp))
	    cp++;
	cp--;
    }
    return bp - bufp;
}

int
hex_to_binary(cp, bufp)
    u_char  *cp;
    u_char *bufp;
{
    int	subidentifier;
    u_char *bp = bufp;

    for(; *cp != '\0'; cp++){
	if (isspace(*cp))
	    continue;
	if (!isxdigit(*cp)){
	    fprintf(stderr, "Input error\n");
	    return -1;
	}
	sscanf((char *)cp, "%x", &subidentifier);
	if (subidentifier > 255){
	    fprintf(stderr, "subidentifier %d is too large ( > 255)\n",
		    subidentifier);
	    return -1;
	}
	*bp++ = (u_char)subidentifier;
	while(isxdigit(*cp))
	    cp++;
	cp--;
    }
    return bp - bufp;
}

int
main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu;
    oid name[MAX_NAME_LEN];
    int name_length;
    int	arg;
    int dest_port = SNMP_TRAP_PORT;
    char *gateway = NULL;
    char *community = NULL;
    char *trap = NULL, *specific = NULL, *description = NULL, *agent = NULL;
    int version = 2;
    oid src[MAX_NAME_LEN], dst[MAX_NAME_LEN], context[MAX_NAME_LEN];
    int srclen = 0, dstlen = 0, contextlen = 0;
    struct partyEntry *pp;
    char ctmp[300];
    int trivialSNMPv2 = FALSE;

    /*
     * usage: snmptrap gateway-name srcParty dstParty trap-type specific-type device-description [ -a agent-addr ]
     */
    init_mib();
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
		case 'a':
		    agent = argv[++arg];
		    break;
		case 'd':
		    snmp_dump_packet++;
		    break;
		case 'p':
		    dest_port = atoi (argv[++arg]);
		    break;
		case 'v':
		    version = atoi(argv[++arg]);
		    if (version < 1 || version > 2) {
			fprintf (stderr, "invalid version: %s\n", argv [arg]);
			usage ();
		    }
		    break;
		default:
		    fprintf(stderr, "invalid option: -%c\n", argv[arg][1]);
		    usage ();
		    break;
	    }
	    continue;
	}
	if (gateway == NULL){
	    gateway = argv[arg];
	} else if (version == 1 && community == NULL){
	    community = argv[arg];
	} else if (version == 2 && srclen == 0 && !trivialSNMPv2){
	    sprintf(ctmp, "%s/party.conf", SNMPLIBPATH);
	    if (read_party_database(ctmp) != 0){
		fprintf(stderr,
			"Couldn't read party database from %s\n", ctmp);
		exit(0);
	    }
            if (!strcasecmp(argv[arg], "noauth"))
                trivialSNMPv2 = TRUE;
	    else {
		party_scanInit();
		for(pp = party_scanNext(); pp; pp = party_scanNext()){
		    if (!strcasecmp(pp->partyName, argv[arg])){
			srclen = pp->partyIdentityLen;
			memcpy(src, pp->partyIdentity, srclen * sizeof(oid));
			break;
		    }
		}
		if (!pp){
		    srclen = MAX_NAME_LEN;
		    if (!read_objid(argv[arg], src, &srclen)){
			fprintf(stderr, "Invalid source party: %s\n", argv[arg]);
			srclen = 0;
			usage();
		    }
		}
            }
	} else if (version == 2 && dstlen == 0 && !trivialSNMPv2){
	    dstlen = MAX_NAME_LEN;
	    party_scanInit();
	    for(pp = party_scanNext(); pp; pp = party_scanNext()){
		if (!strcasecmp(pp->partyName, argv[arg])){
		    dstlen = pp->partyIdentityLen;
		    memcpy(dst, pp->partyIdentity, dstlen * sizeof(oid));
		    break;
		}
	    }
	    if (!pp){
		if (!read_objid(argv[arg], dst, &dstlen)){
		    fprintf(stderr, "Invalid destination party: %s\n", argv[arg]);
		    dstlen = 0;
		    usage ();
		}
	    }
	} else if (trap == NULL){
	    trap = argv[arg];
	    break;
	}
    }

    if (trap == NULL) {
	usage ();
    }
 
    if (trivialSNMPv2){
        u_long destAddr = parse_address (gateway);;
        srclen = dstlen = contextlen = MAX_NAME_LEN;
        ms_party_init(destAddr, src, &srclen, dst, &dstlen,
                      context, &contextlen);
    }

    memset (&session, 0, sizeof(struct snmp_session));
    session.peername = gateway;
    if (version == 1 ){
	session.version = SNMP_VERSION_1;
	session.community = (u_char *) community;
	session.community_len = strlen(community);
    } else if (version == 1 || version == 2){
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
    session.callback = snmp_input;
    session.callback_magic = NULL;
    session.remote_port = dest_port;
    ss = snmp_open(&session);
    if (ss == NULL){
	fprintf(stderr, "Couldn't open snmp\n");
	exit(1);
    }

    if (version == 1) {
	pdu = snmp_pdu_create(TRP_REQ_MSG);
	if (*trap == 0) {
          pdu->enterprise = (oid *)malloc(sizeof (objid_enterprise));
          memcpy(pdu->enterprise, objid_enterprise, sizeof(objid_enterprise));
          pdu->enterprise_length = sizeof(objid_enterprise)/sizeof (oid);
	}
	else {
	    name_length = MAX_NAME_LEN;
	    if (!read_objid (trap, name, &name_length)) {
		fprintf (stderr, "invalid interprise id: %s\n", trap);
		usage ();
	    }
	    pdu->enterprise = (oid *)malloc(name_length * sizeof(oid));
	    memcpy(pdu->enterprise, name, name_length * sizeof(oid));
	    pdu->enterprise_length = name_length;
	}
	if (++arg >= argc) {
	    fprintf (stderr, "Missing agent parameter\n");
	    usage ();
	}
	agent = argv [arg];
	if (agent != NULL && strlen (agent) != 0)
	    pdu->agent_addr.sin_addr.s_addr = parse_address(agent);
	else
	    pdu->agent_addr.sin_addr.s_addr = get_myaddr();
	if (++arg == argc) {
	    fprintf (stderr, "Missing generic-trap parameter\n");
	    usage ();
	}
	trap = argv [arg];
	pdu->trap_type = atoi(trap);
	if (++arg == argc) {
	    fprintf (stderr, "Missing specific-trap parameter\n");
	    usage ();
	}
	specific = argv [arg];
	pdu->specific_type = atoi(specific);
	if (++arg == argc) {
	    fprintf (stderr, "Missing uptime parameter\n");
	    usage ();
	}
	description = argv [arg];
	if (description == NULL || *description == 0)
	    pdu->time = get_uptime();
	else
	    pdu->time = atol (description);
	arg++;
    }
    else {
	long sysuptime;
	char csysuptime [20];

	pdu = snmp_pdu_create(TRP2_REQ_MSG);
	if (*trap == 0) {
	    sysuptime = get_uptime ();
	    sprintf (csysuptime, "%ld", sysuptime);
	    trap = csysuptime;
	}
	snmp_add_var (pdu, objid_sysuptime, sizeof (objid_sysuptime)/sizeof(oid),
		      't', trap);
	if (++arg == argc) {
	    fprintf (stderr, "Missing trap-oid parameter\n");
	    usage ();
	}
	snmp_add_var (pdu, objid_snmptrap, sizeof (objid_snmptrap)/sizeof(oid),
		      'o', argv [arg]);
	arg++;
    }

    while (arg < argc) {
	arg += 3;
	if (arg > argc) break;
	name_length = MAX_NAME_LEN;
	if (!read_objid (argv [arg-3], name, &name_length)) {
	    fprintf (stderr, "Invalid object identifier: %s\n", argv [arg-3]);
	    continue;
	}

	snmp_add_var (pdu, name, name_length, argv [arg-2][0], argv [arg-1]);
    }

    if (snmp_send(ss, pdu)== 0){
	fprintf(stderr, "error: %d\n", snmp_errno);
    }
    snmp_close(ss);
    exit (0);
}
