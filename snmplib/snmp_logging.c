/* logging.c - generic logging for snmp-agent
 * Contributed by Ragnar Kjørstad, ucd@ragnark.vestdata.no 1999-06-26 */

#include "config.h"
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_logging.h"
#include "tools.h"

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
vlog_syslog (int priority, const char *format, va_list ap) 
{
#if HAVE_SYSLOG_H
  if (do_syslogging) {
    char xbuf[SPRINT_MAX_LEN];
/* HP-UX 9 and Solaris 2.5.1 do not have this *
    vsnprintf(xbuf, sizeof(xbuf), format, ap);
*/
    vsprintf(xbuf, format, ap);
    syslog(priority, xbuf);
  }
#endif
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
  va_end(ap);
}


void
vlog_toFILE(FILE *file, int priority, const char *format, va_list ap)
{
  /* fprintf(file, "log: %d: ", priority); */
  /* vfprintf(file, format[0]=='\n'?format+1:format, ap); */
  vfprintf(file, format, ap);
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

  va_end(ap);
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
   
  va_end(ap);
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

/*
 * log a critical error.
 * Use small messages, please !
 */
void
log_perror(const char *s)
{
    char zbuf[SNMP_MAXBUF_SMALL];
    int sav_errno = errno;

    if (s && *s)
        sprintf(zbuf, "%s: %s\n", s, strerror(sav_errno));
    else
        sprintf(zbuf, "%s\n", strerror(sav_errno));

    if (do_filelogging) {
        fprintf(logfile, zbuf);
        fflush(logfile);
    }
#if HAVE_SYSLOG_H
    if (do_syslogging) {
        syslog(LOG_ERR, zbuf);
    }
#endif
    if (do_stderrlogging) {
        fprintf(stderr, zbuf);
        fflush(stderr);
    }
}

