/* logging.c - generic logging for snmp-agent
 * Contributed by Ragnar Kjørstad, ucd@ragnark.vestdata.no 1999-06-26 */

#include "config.h"
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif

#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "snmp_logging.h"
#define LOGLENGTH 1024

int do_syslogging=0;
int do_filelogging=0;
int do_stderrlogging=0;
FILE *logfile;


void
disable_syslog(void) {
#if HAVE_SYSLOG_H
  if (do_syslogging)
    closelog();
#endif
  do_syslogging=0;
}


void
disable_filelog(void) {
  if (do_filelogging)
    fclose(logfile);
  do_filelogging=0;
}


void
disable_stderrlog(void) {
  do_stderrlogging=0;
}


void
disable_log(void) {
  disable_syslog();
  disable_filelog();
  disable_stderrlog();
}


void 
enable_syslog(void) 
{
  disable_syslog();
#if HAVE_SYSLOG_H
  openlog("ucd-snmp", LOG_CONS|LOG_PID, LOG_DAEMON);
  do_syslogging=1;
#endif
}


void
enable_filelog(const char *logfilename, int dont_zero_log) 
{
  disable_filelog();
  logfile=fopen(logfilename, dont_zero_log ? "a" : "w");
  if (logfile)
    do_filelogging=1;
  else
    do_filelogging=0;
}


void
enable_stderrlog(void) {
  do_stderrlogging=1;
}


void
log_syslog (int priority, const char *format)
{
#if HAVE_SYSLOG_H
  if (do_syslogging) {
    syslog(priority, format);
  }
#endif
}


void
log_filelog (int priority, const char *string)
{
  if (do_filelogging) {
    fputs(string, logfile);
    fflush(logfile);
  }
}


void
log_stderrlog (int priority, const char *string)
{
  if (do_stderrlogging) {
    fputs(string, stderr);
    fflush(stderr);
  }
}

void
vlog (int priority, const char *format, va_list ap)
{
  char string[LOGLENGTH];

  vsprintf(string, format, ap);
  log_syslog(priority, string);
  log_filelog(priority, string);
  log_stderrlog(priority, string);
}


void
#ifdef STDC_HEADERS
snmp_log (int priority, const char *format, ...)
#else
snmp_log (int priority, va_alist)
  va_dcl
#endif
{
  va_list ap;
#ifdef STDC_HEADERS
  va_start(ap, format);
#else
  const char *format;
  va_start(ap);
  format = va_arg(ap, const char *);
#endif
  vlog(priority, format, ap);
  va_end(ap);
}

/*
 * log a critical error.
 * Use small messages, please !
 */
void
log_perror(const char *s)
{
  char sbuf[LOGLENGTH];
  char *serr = strerror(errno);

  if (s && *s)
    sprintf(sbuf, "%s: %s\n", s, serr);
  else
    sprintf(sbuf, "%s\n", serr);

  log_syslog(LOG_ERR, sbuf);
  log_filelog(LOG_ERR, sbuf);
  log_stderrlog(LOG_ERR, sbuf);
}

