#ifndef SNMP_LOGGING
#define SNMP_LOGGING
#include <syslog.h>
#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif

void disable_syslog(void);
void disable_filelog(void);
void disable_stderrlog(void);
void disable_log(void);
void enable_syslog(void);
void enable_filelog(const char *logfilename, int dont_zero_log);
void enable_stderrlog(void);
void log_syslog(int priority, const char *format, ...);
void log_filelog(int priority, const char *format, ...);
void log_stderrlog(int priority, const char *format, ...);
void snmp_log(int priority, const char *format, ...);
void vlog(int priority, const char *format, va_list ap);
void log_perror(const char *s);
#endif
