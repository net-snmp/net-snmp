/*
 * snmptable.c - walk a table and print it nicely
 */
/**********************************************************************
	Copyright 1997 Niels Baggesen

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies.

I DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
I BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
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
#if HAVE_GETOPT_H
#include <getopt.h>
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
#include "system.h"
#include "apps/snmp_parse_args.h"

void main __P((int, char **));
struct column {
  int width;
  char *label;
  char *fmt;
} *column = NULL;

static char **data = NULL;
static int fields;
static int entries;
static int allocated;
static int headers_only = 0;
static int no_headers = 0;
static int max_width = 0;
static char *field_separator = NULL;
static char *table_name;
static oid name[MAX_NAME_LEN];
static int name_length;
static oid root[MAX_NAME_LEN];
static int rootlen;
static int debug;
static struct snmp_session session;

void get_field_names __P((void));
void get_table_entries __P((void));
void print_table __P((void));

void usage __P((void))
{
  fprintf(stderr,"Usage:\n  snmptable ");
  snmp_parse_args_usage(stderr);
  fprintf(stderr," [<objectID>]\n\n");
  snmp_parse_args_descriptions(stderr);
  fprintf(stderr,"  -w <W>        print table in parts of W characters width\n");
  fprintf(stderr,"  -f <F>        print an F delimited table\n");
  fprintf(stderr,"  -h            print only the table header\n");
  exit(1);
}

void
main(argc, argv)
  int   argc;
  char  *argv[];
{
  int   arg, argt;
  extern int optind;
  extern char *optarg;
#ifdef _DEBUG_MALLOC_INC
  unsigned long histid1, histid2, orig_size, current_size;
#endif

  setvbuf(stdout, NULL, _IOLBF, 1024);
  snmp_set_quick_print(1);

  /* get the common command line arguments */
  arg = snmp_parse_args(argc, argv, &session)-1;
  
  while ((argt = getopt(argc-arg, argv+arg, "w:f:hH")) != EOF) {
    switch (argt) {
    case 'w':
      max_width = atoi(optarg);
      if (max_width == 0) {
	fprintf(stderr, "Bad -w option\n");
	usage();
      }
      break;
    case 'f':
      field_separator = optarg;
      break;
    case 'h':
      headers_only = 1;
      break;
    case 'H':
      no_headers = 1;
      break;
    default:
      usage();
    }
  }
  optind += arg;

  /* read in MIB database */
  init_mib();

  /* get the initial object and subtree */
  if (optind+1 == argc) {
    /* specified on the command line */
    rootlen = MAX_NAME_LEN;
    if (!read_objid(argv[optind], root, &rootlen)){
      fprintf(stderr, "Invalid object identifier: %s\n", argv[optind]);
      exit(1);
    }
    debug = snmp_get_dump_packet();
  } else {
    fprintf(stderr,"Missing table name\n");
    usage();
  }

#ifdef _DEBUG_MALLOC_INC
  orig_size = malloc_inuse(&histid1);
#endif

  get_field_names();

  if (headers_only == 0) get_table_entries();

  print_table();

#ifdef _DEBUG_MALLOC_INC
  current_size = malloc_inuse(&histid2);
  if (current_size != orig_size) malloc_list(2, histid1, histid2);
#endif

  exit (0);
}

void print_table __P(())
{
  int entry, field, first_field, last_field = 0, width, part = 0;
  char **dp;
  char string_buf[1024];

  printf("SNMP table: %s\n\n", table_name);

  for (field = 0; field < fields; field++) {
    if (field_separator == NULL)
      sprintf(string_buf, "%%%ds", column[field].width+1);
    else if (field == 0) sprintf(string_buf, "%%s");
    else sprintf(string_buf, "%s%%s", field_separator);
    column[field].fmt = strdup (string_buf);
  }

  while (last_field != fields) {
    part++;
    if (part != 1) printf("\nSNMP table %s, part %d\n\n", table_name, part);
    first_field = last_field;
    dp = data;
    width = 0;
    for (field = first_field, width = 0; field < fields; field++) {
      width += column[field].width+1;
      if (max_width != 0 && width > max_width) break;
      printf(column[field].fmt, column[field].label);
    }
    last_field = field;
    printf("\n");
    for (entry = 0; entry < entries; entry++) {
      for (field = first_field; field < last_field; field++) {
	printf(column[field].fmt, dp[field] ? dp[field] : "?");
      }
      dp += fields;
      printf("\n");
    }
  }
}

void get_field_names __P(())
{
  char string_buf[1024];
  char *name_p;

  root[rootlen++] = 1;
  fields = 0;
  while (1) {
    fields++;
    root[rootlen] = fields;
    sprint_objid(string_buf, root, rootlen+1);
    name_p = strrchr(string_buf, '.');
    if (debug) printf("%s %c\n", string_buf, name_p[1]);
    if ('0' <= name_p[1] && name_p[1] <= '9')
      break;
    if (fields == 1) column = malloc(sizeof (*column));
    else column = realloc(column, fields*sizeof(*column));
    column[fields-1].label = strdup(name_p+1);
    column[fields-1].width = strlen(name_p+1);
  }
  if (fields == 1) {
    fprintf(stderr, "Was that a table? %s\n", string_buf);
    exit(1);
  }
  fields--;
  *name_p = 0;
  memmove(name, root, rootlen * sizeof(oid));
  name_length = rootlen+1;
  name_p = strrchr(string_buf, '.');
  if (name_p) *name_p = 0;
  table_name = strdup(string_buf);
}

void get_table_entries __P((void))
{
  int running = 1;
  struct snmp_session *ss;
  struct snmp_pdu *pdu, *response;
  struct variable_list *vars;
  int   count;
  int   status;
  int   i;
  int   col;
  char  string_buf[1024];
  char  *name_p;
  char  **dp;

  SOCK_STARTUP;

  /* open an SNMP session */
  snmp_synch_setup(&session);
  ss = snmp_open(&session);
  if (ss == NULL){
    snmp_perror("snmptable: Couldn't open snmp");
    SOCK_CLEANUP;
    exit(1);
  }

  while (running) {
    /* create PDU for GETNEXT request and add object name to request */
    pdu = snmp_pdu_create(GETNEXT_REQ_MSG);
    for (i = 1; i <= fields; i++) {
      name[rootlen] = i;
      snmp_add_null_var(pdu, name, name_length);
    }

    /* do the request */
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
	/* check resulting variables */
	vars = response->variables;
	if (vars) {
	  name[rootlen] = 1;
	  if (vars->name_length <= rootlen ||
	      memcmp(name, vars->name, (rootlen+1) * sizeof(oid)) != 0) {
	    /* not part of this subtree */
	    if (debug) {
	      printf("End of table: ");
	      print_variable(vars->name, vars->name_length, vars);
	    }
	    running = 0;
	    continue;
	  }
	  name_length = vars->name_length;
	  memcpy(name, vars->name, name_length*sizeof(oid));
	  sprint_objid(string_buf, vars->name, vars->name_length); 
	  name_p = strrchr(string_buf, '.');
	  if (debug) printf("Index: %s\n", name_p+1);
	}
	entries++;
	if (entries >= allocated) {
	  if (allocated == 0) {
	    allocated = 10;
	    data = malloc(allocated*fields*sizeof(char *));
	  }
	  else {
	    allocated += 10;
	    data = realloc(data, allocated*fields*sizeof(char *));
	  }
	}
	dp = data+(entries-1)*fields;
	col = -1;
	for (vars = response->variables; vars; vars = vars->next_variable) {
	  col++;
	  i = name[rootlen] = vars->name[rootlen];
	  if (debug) sprint_variable(string_buf, vars->name, vars->name_length, vars);
	  if (vars->name_length != name_length ||
	      memcmp(name, vars->name, name_length * sizeof(oid)) != 0) {
	    /* not part of this subtree */
	    if (debug) printf("%s => ignored\n", string_buf);
	    continue;
	  }
	  if (debug) printf("%s => taken\n", string_buf);
	  sprint_value(string_buf, vars->name, vars->name_length, vars);
	  dp[i-1] = strdup(string_buf);
	  i = strlen(string_buf);
	  if (i > column[col].width) column[col].width = i;
	}
      } else {
	/* error in response, print it */
	running = 0;
	if (response->errstat == SNMP_ERR_NOSUCHNAME){
	  printf("End of MIB\n");
	} else {
	  fprintf(stderr, "Error in packet.\nReason: %s\n",
		  snmp_errstring(response->errstat));
	  if (response->errstat == SNMP_ERR_NOSUCHNAME){
	    fprintf(stderr, "The request for this object identifier failed: ");
	    for(count = 1, vars = response->variables;
		  vars && count != response->errindex;
		  vars = vars->next_variable, count++)
	      /*EMPTY*/;
	    if (vars)
	      fprint_objid(stderr, vars->name, vars->name_length);
	    fprintf(stderr, "\n");
	  }
	}
      }
    } else if (status == STAT_TIMEOUT){
      fprintf(stderr, "No Response from %s\n", session.peername);
      running = 0;
    } else {    /* status == STAT_ERROR */
      snmp_perror("snmpwalk");
      running = 0;
    }
    if (response)
      snmp_free_pdu(response);
  }
  snmp_close(ss);

  SOCK_CLEANUP;
}
