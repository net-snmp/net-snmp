/* logging.c - generic logging for snmp-agent
 * Contributed by Ragnar Kjørstad, ucd@ragnark.vestdata.no 1999-06-26 */

#include "config.h"
#include <stdio.h>
#ifdef HAVE_MALLOC_H
#include <malloc.h>
#endif
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
log_syslog (int priority, const char *string)
{
#if HAVE_SYSLOG_H
  if (do_syslogging) {
    syslog(priority, string);
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
log_string (int priority, const char *string)
{
  log_syslog(priority, string);
  log_filelog(priority, string);
  log_stderrlog(priority, string);
}


int
vlog (int priority, const char *format, va_list ap)
{
  char buffer[LOGLENGTH];
  int length; 
#if HAVE_VSNPRINTF
  char *dynamic;

  length=vsnprintf(buffer, LOGLENGTH, format, ap);
#else

  length=vsprintf(buffer, format, ap);
#endif

  if (length < 0 ) {
    log_string(LOG_ERR, "Could not format log-string\n");
    return(-1);
  }

  if (length < LOGLENGTH) {
    log_string(priority, buffer);
    return(0);
  } 

#if HAVE_VSNPRINTF
  dynamic=malloc(length+1);
  if (dynamic==NULL) {
    log_string(LOG_ERR, "Could not allocate memory for log-message\n");
    log_string(priority, buffer);
    return(-2);
  }

  vsnprintf(dynamic, length+1, format, ap);
  log_string(priority, dynamic);
  free(dynamic);
  return(0);

#else
  log_string(priority, buffer);
  log_string(LOG_ERR, "Log-message too long!\n");
  return(-3);
#endif
}


int
#ifdef STDC_HEADERS
snmp_log (int priority, const char *format, ...)
#else
snmp_log (int priority, va_alist)
  va_dcl
#endif
{
  va_list ap;
  int ret;
#ifdef STDC_HEADERS
  va_start(ap, format);
#else
  const char *format;
  va_start(ap);
  format = va_arg(ap, const char *);
#endif
  ret=vlog(priority, format, ap);
  va_end(ap);
  return(ret);
}

/*
 * log a critical error.
 */
void
log_perror(const char *s)
{
  char *error  = strerror(errno);
  if (s) {
    if (error)
      snmp_log(LOG_ERR, "%s: %s\n", s, error);
    else 
      snmp_log(LOG_ERR, "%s: Error %d out-of-range\n", s, errno);
  } else {
    if (error)
      snmp_log(LOG_ERR, "%s\n", error);
    else
      snmp_log(LOG_ERR, "Error %d out-of-range\n", errno);
  }
}

