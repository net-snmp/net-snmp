#include <config.h>

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <stdio.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_debug.h"
#include "snmp_impl.h"
#include "mib.h"

static int   dodebug = DODEBUG;
static int   debug_num_tokens=0;
static char *debug_tokens[MAX_DEBUG_TOKENS];
static int   debug_print_everything=0;

void
#ifdef STDC_HEADERS
DEBUGP(const char *first, ...)
#else
DEBUGP(va_alist)
  va_dcl
#endif
{
  va_list args;
#ifndef STDC_HEADERS
  const char *first;
  va_start(args);
  first = va_arg(args, const char *);
#else
  va_start(args, first);
#endif

  if (dodebug && (debug_print_everything || debug_num_tokens == 0)) {
    fprintf(stderr, "%s: ", DEBUG_ALWAYS_TOKEN);
    vfprintf(stderr, first, args);
  }
  va_end(args);
}

void
DEBUGPOID(oid *theoid,
	  int len)
{
  char c_oid[MAX_NAME_LEN];
  sprint_objid(c_oid,theoid,len);
  DEBUGP(c_oid);
}

void debug_register_tokens(char *tokens) {
  char *newp, *cp;
  
  if (tokens == 0 || *tokens == 0)
    return;

  newp = strdup(tokens); /* strtok messes it up */
  cp = strtok(newp, DEBUG_TOKEN_DELIMITER);
  while(cp) {
    if (strlen(cp) < MAX_DEBUG_TOKEN_LEN) {
      if (strcmp(DEBUG_ALWAYS_TOKEN, cp) == 0)
        debug_print_everything = 1;
      else if (debug_num_tokens < MAX_DEBUG_TOKENS)
        debug_tokens[debug_num_tokens++] = strdup(cp);
    }
    cp = strtok(NULL, DEBUG_TOKEN_DELIMITER);
  }
  free(newp);
}


/*
  debug_is_token_registered(char *TOKEN):

  returns SNMPERR_SUCCESS
       or SNMPERR_GENERR

  if TOKEN has been registered and debugging support is turned on.
*/
int
debug_is_token_registered(const char *token) {
  int i;

  /* debugging flag is on or off */
  if (!dodebug)
    return SNMPERR_GENERR;
  
  if (debug_num_tokens == 0 || debug_print_everything) {
    /* no tokens specified, print everything */
    return SNMPERR_SUCCESS;
  } else {
    for(i=0; i < debug_num_tokens; i++) {
      if (strncmp(debug_tokens[i], token, strlen(debug_tokens[i])) == 0) {
        return SNMPERR_SUCCESS;
      }
    }
  }
  return SNMPERR_GENERR;
}

void
#ifdef STDC_HEADERS
debugmsg(const char *token, const char *format, ...)
#else
debugmsg(va_alist)
  va_dcl
#endif
{
  va_list debugargs;
  
#ifndef STDC_HEADERS
  const char *format;
  const char *token;

  va_start(debugargs);
  token = va_arg(debugargs, const char *);
  format = va_arg(debugargs, const char *); /* ??? */
#else
  va_start(debugargs,format);
#endif

  if (debug_is_token_registered(token) == SNMPERR_SUCCESS) {
    vfprintf(stderr, format, debugargs);
  }
  va_end(debugargs);
}

void
debugmsg_oid(char *token, oid *theoid, int len) {
  char c_oid[MAX_NAME_LEN];
  
  sprint_objid(c_oid, theoid, len);
  debugmsg(token, c_oid);
}

void
#ifdef STDC_HEADERS
debugmsgtoken(const char *token, const char *format, ...)
#else
debugmsgtoken(va_alist)
  va_dcl
#endif
{
#ifndef STDC_HEADERS
  const char *token;
  va_list debugargs;

  va_start(debugargs);
  token = va_arg(debugargs, const char *);
#endif

  debugmsg(token, "%s: ", token);
}
  
void
snmp_set_do_debugging(int val)
{
  dodebug = val;
}

int
snmp_get_do_debugging (void)
{
  return dodebug;
}

