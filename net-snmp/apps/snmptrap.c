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
#if HAVE_NETINET_IN_H
# include <netinet/in.h>
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
#include <stdio.h>
#if HAVE_WINSOCK_H
#include <winsock.h>
#else
#include <netdb.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "system.h"
#include "snmp_parse_args.h"

int main __P((int, char **));
int ascii_to_binary __P((u_char *, u_char *));
int hex_to_binary __P((u_char *, u_char *));
int snmp_input __P((int, struct snmp_session *, int, struct snmp_pdu *, void *));
in_addr_t parse_address __P((char *));
void snmp_add_var __P((struct snmp_pdu *, oid *, int, char, char *));

oid objid_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1};
oid objid_sysdescr[]   = {1, 3, 6, 1, 2, 1, 1, 1, 0};
oid objid_sysuptime[]  = {1, 3, 6, 1, 2, 1, 1, 3, 0};
oid objid_snmptrap[]   = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};

void
usage __P((void))
{
    fprintf(stderr,"Usage:\n  snmptrap ");
    snmp_parse_args_usage(stderr);
    fprintf(stderr," [<trap parameters> ...]\n\n");
    snmp_parse_args_descriptions(stderr);
    fprintf(stderr, "  -v 1 trap parameters:\n\t enterprise-oid agent trap-type specific-type uptime [ var ]...\n");
    fprintf(stderr, "  or\n");
    fprintf(stderr, "  -v 2 trap parameters:\n\t uptime trapoid [ var ] ...\n");
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

in_addr_t parse_address(address)
    char *address;
{
    in_addr_t addr;
    struct sockaddr_in saddr;
    struct hostent *hp;

    if ((addr = inet_addr(address)) != -1)
	return addr;
    hp = gethostbyname(address);
    if (hp == NULL){
	fprintf(stderr, "unknown host: %s\n", address);
	exit(1);
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
	    vars->type = ASN_INTEGER;
	    vars->val.integer = (long *)malloc(sizeof(long));
	    *(vars->val.integer) = atoi(value);
	    vars->val_len = sizeof(long);
	    break;
	case 's':
	case 'x':
	case 'd':
	    vars->type = ASN_OCTET_STR;
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
	    vars->type = ASN_NULL;
	    vars->val_len = 0;
	    vars->val.string = NULL;
	    break;
	case 'o':
	    vars->type = ASN_OBJECT_ID;
	    vars->val_len = MAX_NAME_LEN;
	    read_objid(value, (oid *)buf, &vars->val_len);
	    vars->val_len *= sizeof(oid);
	    vars->val.objid = (oid *)malloc(vars->val_len);
	    memmove(vars->val.objid, buf, vars->val_len);
	    break;
	case 't':
	    vars->type = ASN_TIMETICKS;
	    vars->val.integer = (long *)malloc(sizeof(long));
	    *(vars->val.integer) = atoi(value);
	    vars->val_len = sizeof(long);
	    break;
	case 'a':
	    vars->type = ASN_IPADDRESS;
	    vars->val.integer = (long *)malloc(sizeof(long));
	    *(vars->val.integer) = inet_addr(value);
	    vars->val_len = sizeof(long);
	    break;
	default:
	    fprintf(stderr, "Bad object type: %c\n", type);
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
    struct snmp_pdu *pdu, *response;
    oid name[MAX_NAME_LEN];
    int name_length;
    int	arg;
    int status, inform = 0;
    char *trap = NULL, *specific = NULL, *description = NULL, *agent = NULL;
#ifdef _DEBUG_MALLOC_INC
    unsigned long histid1, histid2, orig_size, current_size;
#endif

    /*
     * usage: snmptrap gateway-name srcParty dstParty trap-type specific-type device-description [ -a agent-addr ]
     */
    arg = snmp_parse_args(argc, argv, &session);
 
    session.callback = snmp_input;
    session.callback_magic = NULL;
    if (session.remote_port == SNMP_DEFAULT_REMPORT)
	session.remote_port = SNMP_TRAP_PORT;
    snmp_synch_setup(&session);
    ss = snmp_open(&session);
    if (ss == NULL){
        snmp_perror("snmptrap");
	exit(1);
    }
#ifdef _DEBUG_MALLOC_INC
    orig_size = malloc_inuse(&histid1);
#endif

    if (session.version == SNMP_VERSION_1) {
	pdu = snmp_pdu_create(SNMP_MSG_TRAP);
	if (arg == argc) {
	    fprintf(stderr, "No enterprise oid\n");
	    usage();
	    exit(1);
	}
	if (argv[arg][0] == 0) {
	    pdu->enterprise = (oid *)malloc(sizeof (objid_enterprise));
	    memcpy(pdu->enterprise, objid_enterprise, sizeof(objid_enterprise));
	    pdu->enterprise_length = sizeof(objid_enterprise)/sizeof (oid);
	}
	else {
	    name_length = MAX_NAME_LEN;
	    if (!snmp_parse_oid(argv[arg], name, &name_length)) {
		fprintf (stderr, "Invalid enterprise id: %s\n", argv[arg]);
		usage ();
		exit (1);
	    }
	    pdu->enterprise = (oid *)malloc(name_length * sizeof(oid));
	    memcpy(pdu->enterprise, name, name_length * sizeof(oid));
	    pdu->enterprise_length = name_length;
	}
	if (++arg >= argc) {
	    fprintf (stderr, "Missing agent parameter\n");
	    usage ();
	    exit (1);
	}
	agent = argv [arg];
	if (agent != NULL && strlen (agent) != 0)
	    pdu->agent_addr.sin_addr.s_addr = parse_address(agent);
	else
	    pdu->agent_addr.sin_addr.s_addr = get_myaddr();
	if (++arg == argc) {
	    fprintf (stderr, "Missing generic-trap parameter\n");
	    usage ();
	    exit (1);
	}
	trap = argv [arg];
	pdu->trap_type = atoi(trap);
	if (++arg == argc) {
	    fprintf (stderr, "Missing specific-trap parameter\n");
	    usage ();
	    exit (1);
	}
	specific = argv [arg];
	pdu->specific_type = atoi(specific);
	if (++arg == argc) {
	    fprintf (stderr, "Missing uptime parameter\n");
	    usage ();
	    exit (1);
	}
	description = argv [arg];
	if (description == NULL || *description == 0)
	    pdu->time = get_uptime();
	else
	    pdu->time = atol (description);
    }
    else {
	long sysuptime;
	char csysuptime [20];
	char *prognam;

	prognam = strrchr(argv[0], '/');
	if (prognam) prognam++;
	else prognam = argv[0];

	if (strcmp(prognam, "snmpinform") == 0) inform = 1;
	pdu = snmp_pdu_create(inform ? SNMP_MSG_INFORM : SNMP_MSG_TRAP2);
	if (arg == argc) {
	    fprintf(stderr, "Missing up-time parameter\n");
	    usage();
	    exit(1);
	}
	trap = argv[arg];
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
	    exit (1);
	}
	snmp_add_var (pdu, objid_snmptrap, sizeof (objid_snmptrap)/sizeof(oid),
		      'o', argv [arg]);
    }
    arg++;

    while (arg < argc) {
	arg += 3;
	if (arg > argc) break;
	name_length = MAX_NAME_LEN;
	if (!snmp_parse_oid(argv [arg-3], name, &name_length)) {
	    fprintf (stderr, "Invalid object identifier: %s\n", argv [arg-3]);
	    exit(1);
	}
	snmp_add_var (pdu, name, name_length, argv [arg-2][0], argv [arg-1]);
    }

    if (inform) status = snmp_synch_response(ss, pdu, &response);
    else status = snmp_send(ss, pdu) == 0;
    if (status) {
        snmp_perror(inform ? "snmpinform" : "snmptrap");
    }
    snmp_free_pdu(pdu);

#ifdef _DEBUG_MALLOC_INC
    current_size = malloc_inuse(&histid2);
    if (current_size != orig_size) malloc_list(2, histid1, histid2);
#endif
    snmp_close(ss);
    return (0);
}
