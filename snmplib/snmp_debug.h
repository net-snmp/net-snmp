#ifndef SNMP_DEBUG_H
#define SNMP_DEBUG_H

#ifdef __cplusplus
extern "C" {
#endif

/* snmp_debug.h:

   - prototypes for snmp debugging routines.
   - easy to use macros to wrap around the functions.  This also provides
     the ability to reove debugging code easily from the applications at
     compile time.
*/


/* These functions should not be used, if at all possible.  Instead, use
   the macros below. */
#ifdef STDC_HEADERS
void debugmsg(const char *token, const char *format, ...);
void debugmsgtoken(const char *token, const char *format, ...);
#else
void debugmsg(va_alist);
void debugmsgtoken(va_alist);
#endif
void debugmsg_oid(const char *token, oid *theoid, size_t len);

/* Use these macros instead of the functions above to allow them to be
   re-defined at compile time to NOP for speed optimization.

   They need to be called enclosing all the arguments in a single set of ()s.
   Example:
      DEBUGMSGTL(("token", "debugging of something %s related\n", "snmp"));

Usage:
   All of the functions take a "token" argument that helps determine when
   the output in question should be printed.  See the snmpcmd.1 manual page
   on the -D flag to turn on/off output for a given token on the command line.

     DEBUGMSG((token, format, ...)):      equivelent to printf(format, ...)
                                          (if "token" debugging output
                                          is requested by the user)
  
     DEBUGMSGT((token, format, ...)):     equivelent to DEBUGMSG, but prints
                                          "token: " at the beginning of the
                                          line for you.
  
     DEBUGTRACE                           Insert this token anywhere you want
                                          tracing output displayed when the
                                          "trace" debugging token is selected.
  
     DEBUGMSGL((token, format, ...)):     equivelent to DEBUGMSG, but includes
                                          DEBUGTRACE debugging line just before
                                          yours.
  
     DEBUGMSGTL((token, format, ...)):    Same as DEBUGMSGL and DEBUGMSGT
                                          combined.

Important:
   It is considered best if you use DEBUGMSGTL() everywhere possible, as it
   gives the nicest format output and provides tracing support just before
   every debugging statement output.

To print multiple pieces to a single line in one call, use:

     DEBUGMSGTL(("token", "line part 1"));
     DEBUGMSG  (("token", " and part 2\n"));

   to get:

     token: line part 1 and part 2

   as debugging output.
*/

#ifndef SNMP_NO_DEBUGGING  /* make sure we're wanted */
#define DEBUGMSG(x)    debugmsg x;
#define DEBUGMSGT(x)   debugmsgtoken x; debugmsg x;
#ifdef  HAVE_CPP_UNDERBAR_FUNCTION_DEFINED
#define DEBUGTRACE     DEBUGMSGT(("trace","%s(): %s, %d\n",__FUNCTION__,\
                                 __FILE__,__LINE__));
#else
#define DEBUGTRACE     DEBUGMSGT(("trace"," %s, %d\n", __FILE__,__LINE__));
#endif

#define DEBUGMSGL(x)   DEBUGTRACE; debugmsg x;
#define DEBUGMSGTL(x)  DEBUGTRACE; debugmsgtoken x; debugmsg x;
#define DEBUGL(x)      DEBUGTRACE; debugmsg x;
#define DEBUGMSGOID(x)    debugmsg_oid x;

#else /* SNMP_NO_DEBUGGING := enable streamlining of the code */

#define DEBUGMSG(x)
#define DEBUGMSGT(x)
#define DEBUGTRACE
#define DEBUGMSGL(x)
#define DEBUGMSGTL(x)
#define DEBUGL(x)
#define DEBUGMSGOID(x)

#endif

#define MAX_DEBUG_TOKENS 256
#define MAX_DEBUG_TOKEN_LEN 128
#define DEBUG_TOKEN_DELIMITER ","
#define DEBUG_ALWAYS_TOKEN "all"

/*
  setup routines:
  
  debug_register_tokens(char *):     registers a list of tokens to
                                     print debugging output for.

  debug_is_token_registered(char *): returns SNMPERR_SUCCESS or SNMPERR_GENERR
                                     if a token has been registered or
                                     not (and debugging output is "on").
*/
void debug_register_tokens(char *tokens);
int debug_is_token_registered(const char *token);

/* provided for backwards compatability.  Don't use these functions. */
#ifdef STDC_HEADERS
void DEBUGP (const char *, ...);
#else
void DEBUGP (va_alist);
#endif
void DEBUGPOID(oid *, size_t);
void snmp_set_do_debugging (int);
int snmp_get_do_debugging (void);
int debug_is_token_registered(const char *token);

#ifdef __cplusplus
}
#endif

#endif /* SNMP_DEBUG_H */
