/*
 * snmpbulkget.c - send SNMPv2 Bulk requests to a network entity.
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
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <getopt.h>
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#endif
#if HAVE_NETDB_H
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

oid objid_mib[] = {1, 3, 6, 1, 2, 1};
int max_repetitions = 100;
int non_repeaters = 0;
struct nameStruct {
  oid name[MAX_OID_LEN];
  size_t name_len;
} *name, *namep;
int names;

void optProc(int argc, char *const *argv, int opt)
{
  switch (opt) {
  case 'B':
    non_repeaters = atoi(optarg);
    max_repetitions = atoi(argv[optind++]);
    break;
  }
}

void
usage (void)
{
  fprintf(stderr,"Usage: snmpbulkget ");
  snmp_parse_args_usage(stderr);
  fprintf(stderr," [<objectID>]\n\n");
  snmp_parse_args_descriptions(stderr);
  fprintf(stderr,"  -B <nonrep> <rep>\tfirst <nonrep> objects are non-repeaters\n");
  fprintf(stderr,"\t\t\tmaximum <rep> repetitions over the remainder\n");
}

int main(int argc, char  *argv[])
{
    struct snmp_session  session, *ss;
    struct snmp_pdu *pdu;
    struct snmp_pdu *response;
    struct variable_list *vars;
    int  arg;
    int  count;
    int  running;
    int  status;
    int  exitval = 0;

    /* get the common command line arguments */
    switch (arg = snmp_parse_args(argc, argv, &session, "B:", optProc)) {
    case -2:
	exit(0);
    case -1:
        usage();
        exit(1);
    default:
        break;
    }
    
    names = argc - arg;
    if (names < non_repeaters) {
      fprintf(stderr, "snmpbulkget: need more objects than <nonrep>\n");
      exit(1);
    }

    namep = name = (struct nameStruct *)calloc(names, sizeof(*name));
    while (arg < argc) {
      namep->name_len = MAX_OID_LEN;
      if (snmp_parse_oid(argv[arg], namep->name, &namep->name_len) == NULL) {
        snmp_perror(argv[arg]);
        exit(1);
      }
      arg++; namep++;
    }

    SOCK_STARTUP;

    /* open an SNMP session */
    ss = snmp_open(&session);
    if (ss == NULL){
      /* diagnose snmp_open errors with the input struct snmp_session pointer */
      snmp_sess_perror("snmpbulkget", &session);
      SOCK_CLEANUP;
      exit(1);
    }

    /* create PDU for GETBULK request and add object name to request */
    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu->non_repeaters = non_repeaters;
    pdu->max_repetitions = max_repetitions;  /* fill the packet */
    for (arg = 0; arg < names; arg++) 
      snmp_add_null_var(pdu, name[arg].name, name[arg].name_len);

    /* do the request */
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
	/* check resulting variables */
	for(vars = response->variables; vars; vars = vars->next_variable)
	  print_variable(vars->name, vars->name_length, vars);
      } else {
	/* error in response, print it */
	running = 0;
	if (response->errstat == SNMP_ERR_NOSUCHNAME){
	  printf("End of MIB.\n");
	} else {
	  fprintf(stderr, "Error in packet.\nReason: %s\n",
		 snmp_errstring(response->errstat));
	  if (response->errindex != 0){
	    fprintf(stderr, "Failed object: ");
	    for(count = 1, vars = response->variables;
		  vars && (count != response->errindex);
		  vars = vars->next_variable, count++)
	      /*EMPTY*/;
	    if (vars)
	      fprint_objid(stderr, vars->name, vars->name_length);
	    fprintf(stderr, "\n");
	  }
	  exitval = 2;
	}
      }
    } else if (status == STAT_TIMEOUT){
      fprintf(stderr, "Timeout: No Response from %s\n", session.peername);
      running = 0;
      exitval = 1;
    } else {    /* status == STAT_ERROR */
      snmp_sess_perror("snmpbulkget", ss);
      running = 0;
      exitval = 1;
    }

    if (response)
      snmp_free_pdu(response);

    snmp_close(ss);
    SOCK_CLEANUP;
    return exitval;
}
