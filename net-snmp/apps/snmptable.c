/*
 * snmptable.c - walk a table and print it nicely
 *
 * Update: 1999-10-26 <rs-snmp@revelstone.com>
 * Added ability to use MIB to query tables with non-sequential column OIDs
 * Added code to handle sparse tables
 *
 * Update: 1998-07-17 <jhy@gsu.edu>
 * Added text <special options> to usage().
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
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <getopt.h>

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "default_store.h"
#include "system.h"
#include "snmp_parse_args.h"
#include "parse.h"

struct column {
  int width;
  oid subid;
  char *label;
  char *fmt;
} *column = NULL;

static char **data = NULL;
static char **indices = NULL;
static int index_width = sizeof("index")-1;
static int fields;
static int entries;
static int allocated;
static int headers_only = 0;
static int no_headers = 0;
static int max_width = 0;
static int brief = 0;
static int show_index = 0;
static char *field_separator = NULL;
static char *table_name;
static oid name[MAX_OID_LEN];
static size_t name_length;
static oid root[MAX_OID_LEN];
static size_t rootlen;
static int localdebug;
static int exitval = 0;
static int use_getbulk = 1;
static int max_getbulk = 25;
static int nonsequential = 1;

#ifdef COMMENT
Related to the use of the "nonsequential" [-C] flag:

The -C option should NOT be used. It gives you the old, problematic
behaviour of pre-4.1. Forget about it. It is just there as a safe-
guard in case a problem shows up.

You could get away with
 snmptable -CC host community table

but again, -C should be forgotten.

#endif


void usage(void);
void get_field_names (char *);
void get_table_entries( struct snmp_session *ss );
void getbulk_table_entries( struct snmp_session *ss );
void print_table (void);

static void optProc(int argc, char *const *argv, int opt)
{
    switch (opt) {
      case 'C':
		/* Handle new '-C' command-specific meta-options */
	while (*optarg) {
          switch (*optarg++) {
          case 'w':
	    if ( argv[optind] )
               max_width = atoi(argv[optind]);
            if (max_width == 0) {
               fprintf(stderr, "Bad -Cw option: %s\n", argv[optind]);
               usage();
            }
	    optind++;
            break;
          case 'f':
            field_separator = argv[optind];
            if ( !field_separator ) {
               fprintf(stderr, "Bad -Cf option: %s\n", argv[optind]);
               usage();
            }
	    optind++;
            break;
          case 'h':
            headers_only = 1;
            break;
          case 'H':
            no_headers = 1;
            break;
          case 'C':
            nonsequential = 0;
            break;
	  case 'B':
	    use_getbulk = 0;
	    break;
          case 'b':
            brief = 1;
            break;
          case 'i':
            show_index = 1;
            break;
	  default:
	    fprintf(stderr, "Bad option after -C: %c\n", optarg[-1]);
	    usage();
          }
       }
       break;
#ifndef DEPRECATED_CLI_OPTIONS
    case 'w':
      fprintf(stderr, "Warning: -w option is deprecated - use -Cw\n");
      max_width = atoi(optarg);
      if (max_width == 0) {
	fprintf(stderr, "Bad -w option: %s\n", optarg);
	usage();
      }
      break;
    case 'b':
      fprintf(stderr, "Warning: -b option is deprecated - use -Cb\n");
      brief = 1;
      break;
    case 'i':
      fprintf(stderr, "Warning: -i option is deprecated - use -Ci\n");
      show_index = 1;
      break;
#endif
    }
}

void usage(void)
{
  fprintf(stdout,"Usage: snmptable ");
  snmp_parse_args_usage(stdout);
  fprintf(stdout," <objectID>\n\n");
  snmp_parse_args_descriptions(stdout);
  fprintf(stdout,"  -Cw <W>\tprint table in parts of W characters width\n");
  fprintf(stdout,"  -Cf <F>\tprint an F delimited table\n");
  fprintf(stdout,"  -Cb\t\tbrief field names\n");
  fprintf(stdout,"  -CB\t\tdon't use GETBULK requests\n");
  fprintf(stdout,"  -Ci\t\tprint index value\n");
  fprintf(stdout,"  -Ch\t\tprint only the column headers\n");
  fprintf(stdout,"  -CH\t\tprint no column headers\n");
  exit(1);
}

int main(int argc, char *argv[])
{
  struct snmp_session session, *ss;
  char *tblname;

  setvbuf(stdout, NULL, _IOLBF, 1024);
  snmp_set_quick_print(1);

  /* get the common command line arguments */
#ifndef DEPRECATED_CLI_OPTIONS
  switch (snmp_parse_args(argc, argv, &session, "w:C:bi", optProc)) {
#else
  switch (snmp_parse_args(argc, argv, &session, "C:", optProc)) {
#endif
  case  -2:
    exit(0);
  case -1:
    usage();
    exit(1);
  default:
    break;
  }

  /* get the initial object and subtree */
  /* specified on the command line */
  if (optind+1 != argc) {
    fprintf(stderr,"Must have exactly one table name\n");
    usage();
  }

  rootlen = MAX_OID_LEN;
  if (!snmp_parse_oid(argv[optind], root, &rootlen)){
    snmp_perror(argv[optind]);
    exit(1);
  }
  localdebug = snmp_get_dump_packet();
  if( nonsequential ){
    tblname = strrchr( argv[optind], '.' );
    if (!tblname)
      tblname = strrchr( argv[optind], ':' );
    if( tblname )
      ++tblname;
    else
      tblname = argv[optind];
  }
  else
    tblname = NULL;

  get_field_names( tblname );

  /* open an SNMP session */
  SOCK_STARTUP;
  ss = snmp_open(&session);
  if (ss == NULL){
    /* diagnose snmp_open errors with the input struct snmp_session pointer */
    snmp_sess_perror("snmptable", &session);
    SOCK_CLEANUP;
    exit(1);
  }

  if (ss->version == SNMP_VERSION_1)
    use_getbulk = 0;
  if (!headers_only) {
    if (use_getbulk)
      getbulk_table_entries(ss);
    else
      get_table_entries(ss);
  }

  snmp_close(ss);
  SOCK_CLEANUP;
  if (exitval) return exitval;

  if (entries || headers_only) print_table();
  else printf("%s: No entries\n", table_name);

  return 0;
}

void print_table (void)
{
  int entry, field, first_field, last_field = 0, width, part = 0;
  char **dp;
  char string_buf[SPRINT_MAX_LEN];
  char *index_fmt = NULL;

  if (!no_headers && !headers_only) printf("SNMP table: %s\n\n", table_name);

  for (field = 0; field < fields; field++) {
    if (field_separator == NULL)
      sprintf(string_buf, "%%%ds", column[field].width+1);
    else if (field == 0 && !show_index) sprintf(string_buf, "%%s");
    else sprintf(string_buf, "%s%%s", field_separator);
    column[field].fmt = strdup (string_buf);
  }
  if (show_index) {
    if (field_separator == NULL)
      sprintf(string_buf, "%%%ds", index_width);
    else sprintf(string_buf, "%%s");
    index_fmt = strdup(string_buf);
  }

  while (last_field != fields) {
    part++;
    if (part != 1 && !no_headers)
      printf("\nSNMP table %s, part %d\n\n", table_name, part);
    first_field = last_field;
    dp = data;
    if (show_index && !no_headers) {
      width = index_width;
      printf(index_fmt, "index");
    }
    else
      width = 0;
    for (field = first_field; field < fields; field++) {
      width += column[field].width+1;
      if (field != first_field && width > max_width && max_width != 0) break;
      if (!no_headers) printf(column[field].fmt, column[field].label);
    }
    last_field = field;
    if (!no_headers) printf("\n");
    for (entry = 0; entry < entries; entry++) {
      if (show_index) printf(index_fmt, indices[entry]);
      for (field = first_field; field < last_field; field++) {
	printf(column[field].fmt, dp[field] ? dp[field] : "?");
      }
      dp += fields;
      printf("\n");
    }
  }
}

void get_field_names( char* tblname )
{
  char string_buf[SPRINT_MAX_LEN];
  char *name_p;
  struct tree *tbl = NULL;
  int going = 1;

  name_p = string_buf;
  strcpy(string_buf, "");

  if( tblname )
    tbl = find_tree_node( tblname, -1 );
  if( tbl )
    tbl = tbl->child_list;

  if( tbl ) {
    root[rootlen++] = tbl->subid;
    tbl = tbl->child_list;
  }
  else
    root[rootlen++] = 1;

  sprint_objid(string_buf, root, rootlen-1);
  table_name = strdup(string_buf);

  fields = 0;
  while (going) {
    fields++;
    if( tbl ) {
      if (tbl->access == MIB_ACCESS_NOACCESS) {
	fields--;
	tbl = tbl->next_peer;
	continue;
      }
      root[ rootlen ] = tbl->subid;
      tbl = tbl->next_peer;
      if (!tbl) going = 0;
    }
    else
      root[rootlen] = fields;
    sprint_objid(string_buf, root, rootlen+1);
    name_p = strrchr(string_buf, '.');
    if (!name_p) name_p = strrchr(string_buf, ':');
    if (!name_p) name_p = string_buf;
    else name_p++;
    if (localdebug) printf("%s %c\n", string_buf, name_p[0]);
    if ('0' <= name_p[0] && name_p[0] <= '9') {
      fields--;
      break;
    }
    if (fields == 1) column = (struct column *)malloc(sizeof (*column));
    else column = (struct column *)realloc(column, fields*sizeof(*column));
    column[fields-1].label = strdup(name_p);
    column[fields-1].width = strlen(name_p);
    column[fields-1].subid = root[ rootlen ];
  }
  if (fields == 0) {
    fprintf(stderr, "Was that a table? %s\n", string_buf);
    exit(1);
  }
  *name_p = 0;
  memmove(name, root, rootlen * sizeof(oid));
  name_length = rootlen+1;
  name_p = strrchr(string_buf, '.');
  if (!name_p) name_p = strrchr(string_buf, ':');
  if (name_p) *name_p = 0;
  if (brief && fields > 1) {
    char *f1, *f2;
    int common = strlen(column[0].label);
    int field, len;
    for (field = 1; field < fields; field++) {
      f1 = column[field-1].label;
      f2 = column[field].label;
      while (*f1 && *f1++ == *f2++) ;
      len = f2 - column[field].label - 1;
      if (len < common)
	common = len;
    }
    if (common) {
      for (field = 0; field < fields; field++) {
        column[field].label += common;
	column[field].width -= common;
      }
    }
  }
}

void get_table_entries( struct snmp_session *ss )
{
  int running = 1;
  struct snmp_pdu *pdu, *response;
  struct variable_list *vars;
  int   count;
  int   status;
  int   i;
  int   col;
  char  string_buf[SPRINT_MAX_LEN], *cp;
  char  *name_p = NULL;
  char  **dp;
  int end_of_table = 0;
  int have_current_index;

  /*
   * TODO:
   *   1) Deal with multiple index fields
   *   2) Deal with variable length index fields
   *   3) optimize to remove a sparse column from get-requests
   */

  while (running) {
    /* create PDU for GETNEXT request and add object name to request */
    pdu = snmp_pdu_create(SNMP_MSG_GETNEXT);
    for (i = 1; i <= fields; i++) {
      name[rootlen] = column[i-1].subid;
      snmp_add_null_var(pdu, name, name_length);
    }

    /* do the request */
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
	/* check resulting variables */
	vars = response->variables;
	entries++;
	if (entries >= allocated) {
	  if (allocated == 0) {
	    allocated = 10;
	    data = (char **)malloc(allocated*fields*sizeof(char *));
	    memset (data, 0, allocated*fields*sizeof(char *));
	    if (show_index) indices = (char **)malloc(allocated*sizeof(char *));
	  }
	  else {
	    allocated += 10;
	    data = (char **)realloc(data, allocated*fields*sizeof(char *));
	    memset (data+entries*fields, 0,
		    (allocated-entries)*fields*sizeof(char *));
	    if (show_index) indices = (char **)realloc(indices, allocated*sizeof(char *));
	  }
	}
	dp = data+(entries-1)*fields;
	col = -1;
	end_of_table = 1; /* assume end of table */
	have_current_index = 0;
	name_length = rootlen+1;
	for (vars = response->variables; vars; vars = vars->next_variable) {
	  col++;
	  name[rootlen] = column[col].subid;
	  if (localdebug) sprint_variable(string_buf, vars->name, vars->name_length, vars);
	  if( (vars->name_length < name_length) ||
              ((int)vars->name[rootlen] != column[col].subid) ||
	      memcmp(name, vars->name, name_length * sizeof(oid)) != 0 ||
              vars->type == SNMP_ENDOFMIBVIEW) {
	    /* not part of this subtree */
	    if (localdebug) printf("%s => ignored\n", string_buf);
	    continue;
	  }
	  
	  /* save index off */
	  if ( ! have_current_index ) {
	    end_of_table = 0;
	    have_current_index = 1;
	    name_length = vars->name_length;
	    memcpy(name, vars->name, name_length*sizeof(oid));
	    sprint_objid(string_buf, vars->name, vars->name_length); 
	    i = vars->name_length - rootlen + 1;
	    if (localdebug || show_index ) {
	      if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_EXTENDED_INDEX))
		name_p = strchr(string_buf, '[');
	      else {
		switch (snmp_get_suffix_only()) {
		case 2:
		  name_p = strrchr(string_buf, ':');
		  break;
		case 1:
		  name_p = string_buf;
		  break;
		case 0:
		  name_p = string_buf + strlen(table_name)+1;
		  name_p = strchr(name_p, '.')+1;
		  break;
		}
		name_p = strchr(name_p, '.')+1;
	      }
	    }
	    if (localdebug) printf("Index: %s\n", name_p);
	    if (show_index) {
	      indices[entries-1] = strdup(name_p);
	      i = strlen(name_p);
	      if (i > index_width) index_width = i;
	    }
	  }
	  
	  if (localdebug) printf("%s => taken\n", string_buf);
	  sprint_value(string_buf, vars->name, vars->name_length, vars);
	  for (cp = string_buf; *cp; cp++) if (*cp == '\n') *cp = ' ';
	  dp[col] = strdup(string_buf);
	  i = strlen(string_buf);
	  if (i > column[col].width) column[col].width = i;
	}
	if( end_of_table ) {
	      --entries;
	  /* not part of this subtree */
	  if (localdebug) {
	    printf("End of table: %s\n", string_buf);
	  }
	  running = 0;
	  continue;
	}
      } else {
	/* error in response, print it */
	running = 0;
	if (response->errstat == SNMP_ERR_NOSUCHNAME){
	  printf("End of MIB\n");
	} else {
	  fprintf(stderr, "Error in packet.\nReason: %s\n",
		  snmp_errstring(response->errstat));
	  if (response->errindex != 0){
	    fprintf(stderr, "Failed object: ");
	    for(count = 1, vars = response->variables;
		  vars && count != response->errindex;
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
      fprintf(stderr, "Timeout: No Response from %s\n", ss->peername);
      running = 0;
      exitval = 1;
    } else {    /* status == STAT_ERROR */
      snmp_sess_perror("snmptable", ss);
      running = 0;
      exitval = 1;
    }
    if (response)
      snmp_free_pdu(response);
  }
}

void getbulk_table_entries( struct snmp_session *ss )
{
  int running = 1;
  struct snmp_pdu *pdu, *response;
  struct variable_list *vars, *last_var;
  int   count;
  int   status;
  int   i;
  int   row, col;
  char  string_buf[SPRINT_MAX_LEN], *cp;
  char  *name_p = NULL;
  char  **dp;

  while (running) {
    /* create PDU for GETNEXT request and add object name to request */
    pdu = snmp_pdu_create(SNMP_MSG_GETBULK);
    pdu->non_repeaters = 0;
    pdu->max_repetitions = max_getbulk;
    snmp_add_null_var(pdu, name, name_length);

    /* do the request */
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS) {
      if (response->errstat == SNMP_ERR_NOERROR) {
	/* check resulting variables */
	vars = response->variables;
	last_var = NULL;
	while (vars) {
	  sprint_objid(string_buf, vars->name, vars->name_length);
	  if (vars->type == SNMP_ENDOFMIBVIEW || memcmp(vars->name, name, rootlen*sizeof(oid)) != 0) {
	    if (localdebug)
	      printf("%s => end of table\n", string_buf);
	    running = 0;
	    break;
	  }
	  if (localdebug) printf("%s => taken\n", string_buf);
	  if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_EXTENDED_INDEX))
	    name_p = strchr(string_buf, '[');
	  else {
	    switch (snmp_get_suffix_only()) {
	    case 2:
	      name_p = strrchr(string_buf, ':');
	      break;
	    case 1:
	      name_p = string_buf;
	      break;
	    case 0:
	      name_p = string_buf + strlen(table_name)+1;
	      name_p = strchr(name_p, '.')+1;
	      break;
	    }
	    name_p = strchr(name_p, '.')+1;
	  }
	  for (row = 0; row < entries; row++)
	    if (strcmp(name_p, indices[row]) == 0) break;
	  if (row == entries) {
	    entries++;
	    if (entries >= allocated) {
	      if (allocated == 0) {
		allocated = 10;
		data = (char **)malloc(allocated*fields*sizeof(char *));
		memset (data, 0, allocated*fields*sizeof(char *));
		indices = (char **)malloc(allocated*sizeof(char *));
	      }
	      else {
		allocated += 10;
		data = (char **)realloc(data, allocated*fields*sizeof(char *));
		memset (data+entries*fields, 0,
			(allocated-entries)*fields*sizeof(char *));
		indices = (char **)realloc(indices, allocated*sizeof(char *));
	      }
	    }
	    indices[row] = strdup(name_p);
	    i = strlen(name_p);
	    if (i > index_width) index_width = i;
	  }
	  dp = data+row*fields;
	  sprint_value(string_buf, vars->name, vars->name_length, vars);
	  for (cp = string_buf; *cp; cp++)
	    if (*cp == '\n') *cp = ' ';
	  for (col = 0; col < fields; col++)
	    if (column[col].subid == vars->name[rootlen]) break;
	  dp[col] = strdup(string_buf);
	  i = strlen(string_buf);
	  if (i > column[col].width) column[col].width = i;
	  last_var = vars;
	  vars = vars->next_variable;
	}
	if (last_var) {
	  name_length = last_var->name_length;
	  memcpy(name, last_var->name, name_length * sizeof(oid));
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
	  exitval = 2;
	}
      }
    } else if (status == STAT_TIMEOUT){
      fprintf(stderr, "Timeout: No Response from %s\n", ss->peername);
      running = 0;
      exitval = 1;
    } else {    /* status == STAT_ERROR */
      snmp_sess_perror("snmptable", ss);
      running = 0;
      exitval = 1;
    }
    if (response)
      snmp_free_pdu(response);
  }
}
