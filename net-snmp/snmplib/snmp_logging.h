#ifndef SNMP_LOGGING_H
#define SNMP_LOGGING_H

#ifdef __cplusplus
extern "C" {
#endif

#if HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#ifndef LOG_ERR
#define LOG_EMERG       0       /* system is unusable */
#define LOG_ALERT       1       /* action must be taken immediately */
#define LOG_CRIT        2       /* critical conditions */
#define LOG_ERR         3       /* error conditions */
#define LOG_WARNING     4       /* warning conditions */
#define LOG_NOTICE      5       /* normal but significant condition */
#define LOG_INFO        6       /* informational */
#define LOG_DEBUG       7       /* debug-level messages */

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

#ifdef __cplusplus
}
#endif

#endif /* SNMP_LOGGING_H */
