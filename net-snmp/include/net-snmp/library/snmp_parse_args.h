#ifndef SNMP_PARSE_ARGS_H
#define SNMP_PARSE_ARGS_H
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @file snmp_parse_args.h
 *
 * Support for initializing variables of type netsnmp_session from command
 * line arguments
 */

/** Don't enable any logging even if there is no -L argument */
#define NETSNMP_PARSE_ARGS_NOLOGGING    0x0001
/** Don't zero out sensitive arguments as they are not on the command line
 *  anyway, typically used when the function is called from an internal
 *  config-line handler
 */
#define NETSNMP_PARSE_ARGS_NOZERO       0x0002

/**
 *  Parse an argument list and initialize \link netsnmp_session
 *  session\endlink
 *  from it.
 *  @param argc Number of elements in argv
 *  @param argv string array of at least argc elements
 *  @param localOpts Additional option characters to accept
 *  @param proc function pointer used to process any unhandled arguments
 *  @param flags flags directing how to handle the string
 *
 *  @return 0 on success, -1 on failure
 *
 *  The proc function is called with argc, argv and the currently processed
 *  option as arguments
 */
NETSNMP_IMPORT int
netsnmp_parse_args(int argc, char **argv, netsnmp_session *session,
                   const char *localOpts, void (*proc)(int, char *const *, int),
                   int flags);

/**
 *  Calls \link netsnmp_parse_args()
 *  netsnmp_parse_args(argc, argv, session, localOpts, proc, 0)\endlink
 */
NETSNMP_IMPORT
int
snmp_parse_args(int argc, char **argv, netsnmp_session *session,
		const char *localOpts, void (*proc)(int, char *const *, int));

NETSNMP_IMPORT
void
snmp_parse_args_descriptions(FILE *);

NETSNMP_IMPORT
void
snmp_parse_args_usage(FILE *);

#ifdef __cplusplus
}
#endif
#endif
