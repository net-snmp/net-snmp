/*
 * snmpset.c - send snmp SET requests to a network entity.
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
#else
#include <netdb.h>
#endif
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
#include "system.h"
#include "snmp_parse_args.h"

int failures = 0;

void main __P((int, char **));
void snmp_add_var __P((struct snmp_pdu *, oid*, int, char, char *));
int ascii_to_binary __P((u_char *, u_char *));
int hex_to_binary __P((u_char *, u_char *));

void
usage __P((void))
{
  fprintf(stderr,"Usage:\n  snmpset ");
  snmp_parse_args_usage(stderr);
  fprintf(stderr," [<objectID> <type> <value> ...]\n\n");
  snmp_parse_args_descriptions(stderr);
  fprintf(stderr, 
    "  type - one of i, u, t, a, o, s, x, d, n\n");
  fprintf(stderr,
    "    i: INTEGER, u: unsigned INTEGER, t: TIMETICKS, a: IPADDRESS\n");
  fprintf(stderr,
    "    o: OBJID, s: STRING, x: HEX STRING, d: DECIMAL STRING\n");
}

void
main(argc, argv)
    int   argc;
    char  *argv[];
{
    struct snmp_session session, *ss;
    struct snmp_pdu *pdu, *response;
    struct variable_list *vars;
    int arg;
    int count;
    int current_name = 0;
    int current_type = 0;
    int current_value = 0;
    char *names[128];
    char types[128];
    char *values[128];
    oid name[MAX_NAME_LEN];
    int name_length;
    int status;

    /* read in MIB database */
    init_mib();

    /* get the common command line arguments */
    arg = snmp_parse_args(argc, argv, &session);

    /* get object names, types, and values */
    for(; arg < argc; arg++){
      names[current_name++] = argv[arg++];
      if (arg < argc) {
        switch(*argv[arg]){
        case 'i':
        case 'u':
        case 't':
        case 'a':
        case 'o':
        case 's':
        case 'x':
        case 'd':
          types[current_type++] = *argv[arg++];
          break;
        default:
          fprintf(stderr, "Bad object type: %c\n", *argv[arg]);
          usage();
          exit(1);
        }
      } else {
        fprintf(stderr, "Need value type\n");
        usage();
        exit(1);
      }
      if (arg < argc)
        values[current_value++] = argv[arg];
      else {
        fprintf(stderr, "Need value\n");
        usage();
        exit(1);
      }
    }

    SOCK_STARTUP;

    /* open an SNMP session */
    snmp_synch_setup(&session);
    ss = snmp_open(&session);
    if (ss == NULL){
      printf("Couldn't open snmp\n");
      exit(1);
    }

    /* create PDU for SET request and add object names and values to request */
    pdu = snmp_pdu_create(SET_REQ_MSG);
    for(count = 0; count < current_name; count++){
      name_length = MAX_NAME_LEN;
      if (!read_objid(names[count], name, &name_length)){
        printf("Invalid object identifier: %s\n", names[count]);
        failures++;
      } else
        snmp_add_var(pdu, name, name_length, types[count], values[count]);
    }

    if (failures) {
      SOCK_CLEANUP;
      exit(1);
    }

    /* do the request */
retry:
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
        for(vars = response->variables; vars; vars = vars->next_variable)
          print_variable(vars->name, vars->name_length, vars);
        } else {
          printf("Error in packet.\nReason: %s\n",
                 snmp_errstring(response->errstat));
          if (response->errstat == SNMP_ERR_NOSUCHNAME){
            printf("This name doesn't exist: ");
            for(count = 1, vars = response->variables;
                  vars && (count != response->errindex);
                  vars = vars->next_variable, count++)
              ;
            if (vars)
              print_objid(vars->name, vars->name_length);
            printf("\n");
          }
          if ((pdu = snmp_fix_pdu(response, SET_REQ_MSG)) != NULL)
            goto retry;
        }
      } else if (status == STAT_TIMEOUT){
        printf("No Response from %s\n", session.peername);
      } else {    /* status == STAT_ERROR */
        printf("An error occurred, Quitting\n");
    }

    if (response)
      snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;
    exit (0);
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
        ;

      vars->next_variable =
            (struct variable_list *)malloc(sizeof(struct variable_list));
      vars = vars->next_variable;
    }

    vars->next_variable = NULL;
    vars->name = (oid *)malloc(name_length * sizeof(oid));
    memmove(vars->name, name, name_length * sizeof(oid));
    vars->name_length = name_length;

    switch(type){
    case 'i':
      vars->type = INTEGER;
      vars->val.integer = (long *)malloc(sizeof(long));
      *(vars->val.integer) = atol(value);
      vars->val_len = sizeof(long);
      break;

    case 'u':
      vars->type = UNSIGNED;
      vars->val.integer = (long *)malloc(sizeof(long));
      *(vars->val.integer) = (long)strtoul(value, NULL, 10);
      vars->val_len = sizeof(long);
      break;

    case 't':
      vars->type = TIMETICKS;
      vars->val.integer = (long *)malloc(sizeof(long));
      *(vars->val.integer) = (long)strtoul(value, NULL, 10);
      vars->val_len = sizeof(long);
      break;

    case 'a':
      vars->type = IPADDRESS;
      vars->val.integer = (long *)malloc(sizeof(long));
      *(vars->val.integer) = inet_addr(value);
      vars->val_len = sizeof(long);
      break;

    case 'o':
      vars->type = OBJID;
      vars->val_len = MAX_NAME_LEN;
      read_objid(value, (oid *)buf, &vars->val_len);
      vars->val_len *= sizeof(oid);
      vars->val.objid = (oid *)malloc(vars->val_len);
            memmove(vars->val.objid, buf, vars->val_len);
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
      if (vars->val_len < 0) {
        fprintf (stderr, "Bad value: %s\n", value);
        failures++;
        vars->val_len = 0;
      }
      vars->val.string = (u_char *)malloc(vars->val_len);
      memmove(vars->val.string, buf, vars->val_len);
      break;

    case 'n':
      vars->type = NULLOBJ;
      vars->val_len = 0;
      vars->val.string = NULL;
      break;

    default:
      printf("Internal error in type switching\n");
      exit(1);
    }
}

int
ascii_to_binary(cp, bufp)
    u_char  *cp;
    u_char *bufp;
{
    int  subidentifier;
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
    int  subidentifier;
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

