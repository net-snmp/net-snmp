/*
 * snmpget.c - send snmp GET requests to a network entity.
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
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "party.h"
#include "context.h"
#include "view.h"
#include "acl.h"
#include "snmp_parse_args.h"

int main __P((int, char **));
int failures;

void
usage __P((void))
{
    fprintf(stderr, "Usage: snmpget -v 1 [-q] hostname community [objectID]+               or:\n");
    fprintf(stderr, "Usage: snmpget [-v 2] [-q] hostname noAuth [objectID]+                or:\n");
    fprintf(stderr, "Usage: snmpget [-v 2] [-q] hostname srcParty dstParty context [objectID]+\n");
}

int
main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    int	arg;
    char *hostname = NULL;
    char *community = NULL;
    int timeout = SNMP_DEFAULT_TIMEOUT, retransmission = SNMP_DEFAULT_RETRIES;
    int	count, current_name = 0;
    char *names[128];
    oid name[MAX_NAME_LEN];
    int name_length;
    int status;
    int version = 2;
    int dest_port = SNMP_PORT;
    u_long      srcclock = 0, dstclock = 0;
    int clock_flag = 0;
    oid src[MAX_NAME_LEN], dst[MAX_NAME_LEN], context[MAX_NAME_LEN];
    int srclen = 0, dstlen = 0, contextlen = 0;
    struct partyEntry *pp;
    struct contextEntry *cxp;
    int trivialSNMPv2 = FALSE;
    struct hostent *hp;
    in_addr_t destAddr;
    char ctmp[300];



    init_mib();

    arg = snmp_parse_args(argc, argv, &session);
    for(; arg < argc; arg++)
      names[current_name++] = argv[arg];
    
    snmp_synch_setup(&session);
    ss = snmp_open(&session);
    if (ss == NULL){
	printf("Couldn't open snmp\n");
	exit(1);
    }

    pdu = snmp_pdu_create(GET_REQ_MSG);

    for(count = 0; count < current_name; count++){
	name_length = MAX_NAME_LEN;
	if (!read_objid(names[count], name, &name_length)){
	    printf("Invalid object identifier: %s\n", names[count]);
	    failures++;
	}
	else	
	    snmp_add_null_var(pdu, name, name_length);
    }

    if (failures)
	exit(1);

retry:
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
	if (response->errstat == SNMP_ERR_NOERROR){
	    for(vars = response->variables; vars; vars = vars->next_variable)
		print_variable(vars->name, vars->name_length, vars);
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
	printf("No Response from %s\n", hostname);
    } else {    /* status == STAT_ERROR */
	printf("An error occurred, Quitting\n");
    }

    if (response)
	snmp_free_pdu(response);
    snmp_close(ss);
    exit (0);
}
