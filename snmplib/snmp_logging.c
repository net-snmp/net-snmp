/* logging.c - generic logging for snmp-agent
 * Contributed by Ragnar Kjørstad, ucd@ragnark.vestdata.no 1999-06-26 */

#include "config.h"
#include <syslog.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif

int do_syslogging=0;
int do_filelogging=0;
int do_stderrlogging=0;
FILE *logfile;


void
disable_syslog() {
  if (do_syslogging) 
    closelog();
  do_syslogging=0;
}


void
disable_filelog() {
  if (do_filelogging)
    fclose(logfile);
  do_filelogging=0;
}


void
disable_stderrlog() {
  do_stderrlogging=0;
}


void
disable_log() {
  disable_syslog();
  disable_filelog();
  disable_stderrlog();
}



void 
enable_syslog() 
{
  disable_syslog();
  openlog("ucd-snmp", LOG_CONS|LOG_PID, LOG_DAEMON);
  do_syslogging=1;
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
enable_stderrlog() {
  do_stderrlogging=1;
}

void
vlog_syslog (int priority, const char *format, va_list ap) 
{
  if (do_syslogging) {
    syslog(priority, format, ap);
  }
}

void
#ifdef STDC_HEADERS
log_syslog (int priority, const char *format, ...)
#else
log_syslog (int priority, va_alist)
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

  vlog_syslog(priority, format, ap);
  va_end(ar);
}


void
vlog_toFILE(FILE *file, int priority, const char *format, va_list ap)
{
  fprintf(file, "log: %d: ", priority);
  vfprintf(file, format[0]=='\n'?format+1:format, ap);
  /*  Making sure error-message ends with a newline:
      if (format[strlen(format)-1]!='\n')
        fprintf(file, "\n"); */
}


void
vlog_filelog (int priority, const char *format, va_list ap)
{
  if (do_filelogging) {
    vlog_toFILE(logfile, priority, format, ap);
  }
}


void
#ifdef STDC_HEADERS
log_filelog (int priority, const char *format, ...)
#else
log_filelog (int priority, va_alist)
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
  vlog_filelog(priority, format, ap);

  va_end(ar);
} 


void
vlog_stderrlog (int priority, const char *format, va_list ap)
{
  if (do_stderrlogging) {
    vlog_toFILE(stderr, priority, format, ap);
  }
}



void
#ifdef STDC_HEADERS
log_stderrlog (int priority, const char *format, ...)
#else
log_stderrlog (int priority, va_alist)
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
  vlog_stderrlog(priority, format, ap);
   
  va_end(ar);
}


void
vlog (int priority, const char *format, va_list ap)
{
  vlog_syslog(priority, format, ap);
  vlog_filelog(priority, format, ap);
  vlog_stderrlog(priority, format, ap);
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


void
log_perror_syslog(char *s)
{
  log_syslog(LOG_ERR, "System error - check logfile (if any) for details");
}

void
log_perror_filelog(char *s)
{
  log_filelog(LOG_ERR, "System error - detail error reporting not implemented");
}

void
log_perror_stderrlog(char *s)
{
  log_stderrlog(LOG_ERR, "System error: ");
  perror(s);
}


void
log_perror(char *s)
{
  log_perror_syslog(s);
  log_perror_filelog(s);
  log_perror_stderrlog(s);
}

