/* logging.c - generic logging for snmp-agent
 * Contributed by Ragnar Kjørstad, ucd@ragnark.vestdata.no 1999-06-26 */

#include "config.h"
#include <stdio.h>
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#if HAVE_SYSLOG_H
#include <syslog.h>
#ifndef LOG_CONS	/* Interesting Ultrix feature */
#include <sys/syslog.h>
#endif
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
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_STDARG_H
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include "asn1.h"
#include "default_store.h"
#include "snmp_logging.h"
#include "callback.h"
#include "system.h"
#define LOGLENGTH 1024

static int do_syslogging=0;
static int do_filelogging=0;
static int do_stderrlogging=1;
static int do_log_callback=0;
static int newline = 1;
static FILE *logfile;

#ifndef HAVE_VSNPRINTF
		/* Need to use the UCD-provided one */
int vsnprintf (char *str, size_t count, const char *fmt, va_list arg);
#endif

void
init_snmp_logging(void) {
  ds_register_premib(ASN_BOOLEAN, "snmp", "logTimestamp", DS_LIBRARY_ID,
                     DS_LIB_LOG_TIMESTAMP);
}

int
snmp_get_do_logging(void) {
  return (do_syslogging || do_filelogging || do_stderrlogging ||
          do_log_callback);
}


static char *
sprintf_stamp (time_t *now, char *sbuf)
{
    time_t Now;
    struct tm *tm;

    if (now == NULL) {
	now = &Now;
	time (now);
    }
    tm = localtime (now);
    sprintf(sbuf, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d ",
	    tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec);
    return sbuf;
}

void
snmp_disable_syslog(void) {
#if HAVE_SYSLOG_H
  if (do_syslogging)
    closelog();
#endif
  do_syslogging=0;
}


void
snmp_disable_filelog(void) {
  if (do_filelogging)
  {
    fputs("\n",logfile);
    fclose(logfile);
  }
  do_filelogging=0;
}


void
snmp_disable_stderrlog(void) {
  do_stderrlogging=0;
}


void
snmp_disable_log(void) {
  snmp_disable_syslog();
  snmp_disable_filelog();
  snmp_disable_stderrlog();
  snmp_disable_calllog();
}


void
snmp_enable_syslog(void)
{
  snmp_disable_syslog();
#if HAVE_SYSLOG_H
  openlog("ucd-snmp", LOG_CONS|LOG_PID, LOG_DAEMON);
  do_syslogging=1;
#endif
}


void
snmp_enable_filelog(const char *logfilename, int dont_zero_log)
{
  snmp_disable_filelog();
  logfile=fopen(logfilename, dont_zero_log ? "a" : "w");
  if (logfile) {
    do_filelogging=1;
    setvbuf(logfile, NULL, _IOLBF, BUFSIZ);
  }
  else
    do_filelogging=0;
}


void
snmp_enable_stderrlog(void) {
  do_stderrlogging=1;
}


void
snmp_enable_calllog(void) {
  do_log_callback = 1;
}


void
snmp_disable_calllog(void) {
  do_log_callback = 0;
}


void
snmp_log_string (int priority, const char *string)
{
    char sbuf[40];
    struct snmp_log_message slm;

#if HAVE_SYSLOG_H
  if (do_syslogging) {
    syslog(priority, "%s", string);
  }
#endif

  if (do_log_callback) {
      slm.priority = priority;
      slm.msg = string;
      snmp_call_callbacks(SNMP_CALLBACK_LIBRARY, SNMP_CALLBACK_LOGGING, &slm);
  }

  if (do_filelogging || do_stderrlogging) {

    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_LOG_TIMESTAMP) && newline) {
      sprintf_stamp(NULL, sbuf);
    } else {
      strcpy(sbuf, "");
    }
    newline = string[strlen(string)-1] == '\n';

    if (do_filelogging)
      fprintf(logfile, "%s%s", sbuf, string);

    if (do_stderrlogging)
      fprintf(stderr, "%s%s", sbuf, string);
  }
}

int
snmp_vlog (int priority, const char *format, va_list ap)
{
  char buffer[LOGLENGTH];
  int length;
  char *dynamic;

  length=vsnprintf(buffer, LOGLENGTH, format, ap);

  if (length == 0) 
    return(0);		/* Empty string */

  if (length == -1) {
    snmp_log_string(LOG_ERR, "Could not format log-string\n");
    return(-1);
  }

  if (length < LOGLENGTH) {
    snmp_log_string(priority, buffer);
    return(0);
  }

  dynamic = (char *)malloc(length+1);
  if (dynamic==NULL) {
    snmp_log_string(LOG_ERR, "Could not allocate memory for log-message\n");
    snmp_log_string(priority, buffer);
    return(-2);
  }

  vsnprintf(dynamic, length+1, format, ap);
  snmp_log_string(priority, dynamic);
  free(dynamic);
  return 0;
}


int
#if HAVE_STDARG_H
snmp_log (int priority, const char *format, ...)
#else
snmp_log (va_alist)
  va_dcl
#endif
{
  va_list ap;
  int ret;
#if HAVE_STDARG_H
  va_start(ap, format);
#else
  int priority;
  const char *format;
  va_start(ap);

  priority = va_arg(ap, int);
  format = va_arg(ap, const char *);
#endif
  ret=snmp_vlog(priority, format, ap);
  va_end(ap);
  return(ret);
}

/*
 * log a critical error.
 */
void
snmp_log_perror(const char *s)
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

