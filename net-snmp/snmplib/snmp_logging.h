#ifndef SNMP_LOGGING
#define SNMP_LOGGING
#include <syslog.h>
#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif

extern disable_syslog();
extern disable_filelog();
extern disable_stderrlog();
extern disable_log();
extern enable_syslog();
extern enable_filelog(const char *logfilename, int dont_zero_log);
extern enable_stderrlog();
extern log_syslog(int priority, const char *format, ...);
extern log_filelog(int priority, const char *format, ...);
extern log_stderrlog(int priority, const char *format, ...);
extern snmp_log(int priority, const char *format, ...);
extern vlog(int priority, const char *format, va_list ap);
extern log_perror(const char *s);
#endif
