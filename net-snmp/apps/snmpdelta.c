/*
 * snmpdelta.c - Monitor deltas of integer valued SNMP variables
 *
 */
/**********************************************************************
 *
 *           Copyright 1996 by Carnegie Mellon University
 * 
 *                       All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and its
 * documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * 
 **********************************************************************/

#include "config.h"

#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifdef HAVE_STRINGS_H
# include <strings.h>
#else /* HAVE_STRINGS_H */
# include <string.h>
#endif /* HAVE_STRINGS_H */

#ifdef HAVE_MALLOC_H
# include <malloc.h>
#endif /* HAVE_MALLOC_H */

#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif /* HAVE_STDLIB_H */

#ifdef HAVE_UNISTD_H
# include <unistd.h>
#endif /* HAVE_UNISTD_H */

#ifdef HAVE_SYS_SELECT_H
# include <sys/select.h>
#endif /* HAVE_SYS_SELECT_H */
#include <stdio.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <ctype.h>

#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "snmp_parse_args.h"
#include "system.h"

#define MAX_ARGS 256
    
char *SumFile = "Sum";
char *Argv[MAX_ARGS];
int Argc;

/* Information about the handled variables */
struct varInfo {
  char *name;
  oid *oid;
  int oidlen;
  char descriptor[64];
  u_int value;
  float max;
  time_t time;
  int peak_count;
  float peak;
  float peak_average;
  int spoiled;
};

int main __P((int, char **));
int wait_for_peak_start __P((int period, int peak));
void log __P((char *file, char *message));
void sprint_descriptor __P((char *buffer, struct varInfo *vip));
void processFileArgs __P((char *fileName));
void wait_for_period __P((int period));

void usage __P((void))
{
  fprintf(stderr, "Usage:\nsnmpdelta ");
  snmp_parse_args_usage(stderr);
  fprintf(stderr, "[-f commandFile]\n[-l] [-L SumFileName] [-s] [-k] [-t] [-S] [-v vars/pkt]\n [-p period] [-P peaks] oid [oid ...]\n");
  snmp_parse_args_descriptions(stderr);
}

int wait_for_peak_start(period, peak)
int period;
int peak;
{
  struct timeval time, *tv = &time;
  struct tm tm;
  time_t SecondsAtNextHour;
  int target = 0;
  int seconds;

  seconds = period * peak;

  /* Find the current time */
  gettimeofday(tv, (struct timezone *)0);

  /* Create a tm struct from it */
  memcpy(&tm, localtime((time_t *)&tv->tv_sec), sizeof(tm));

  /* Calculate the next hour */
  tm.tm_sec = 0;
  tm.tm_min = 0;
  tm.tm_hour++;
  SecondsAtNextHour = mktime(&tm);
    
  /* Now figure out the amount of time to sleep */
  target = (SecondsAtNextHour - tv->tv_sec) % seconds;

  return target;
}

void log(file, message)
char *file;
char *message;
{
  FILE *fp;

  fp = fopen(file, "a");
  if (fp == NULL){
    fprintf(stderr, "Couldn't open %s\n", file);
    return;
  }
  fprintf(fp, "%s\n", message);
  fclose(fp);
}

void sprint_descriptor(buffer, vip)
char *buffer;
struct varInfo *vip;
{
  char buf[256], *cp;

  sprint_objid(buf, vip->oid, vip->oidlen);
  for(cp = buf; *cp; cp++)
    ;
  while(cp >= buf){
    if (isalpha(*cp))
      break;
    cp--;
  }
  while(cp >= buf){
    if (*cp == '.')
      break;
    cp--;
  }
  cp++;
  if (cp < buf)
    cp = buf;
  strcpy(buffer, cp);
}

void processFileArgs(fileName)
char *fileName;
{
  FILE *fp;
  char buf[257], *cp;
  int blank, linenumber = 0;

  fp = fopen(fileName, "r");
  if (fp == NULL)
    return;
  while (fgets(buf, 256, fp)){
    linenumber++;
    if (strlen(buf) > 256){
      fprintf(stderr, "Line too long on line %d of %s\n",
	      linenumber, fileName);
      exit(1);
    }
    if (buf[0] == '#')
      continue;
    blank = TRUE;
    for(cp = buf; *cp; cp++)
      if (!isspace(*cp)){
	blank = FALSE;
	break;
      }
    if (blank)
      continue;
    Argv[Argc] = (char *)malloc(strlen(buf)); /* ignore newline */
    buf[strlen(buf) - 1] = 0;
    strcpy(Argv[Argc++], buf);
  }
  fclose(fp);
  return;
}

void wait_for_period(period)
int period;
{
  struct timeval time, *tv = &time;
  struct tm tm;
  int count;
  static int target = 0;
  time_t nexthour;

  gettimeofday(tv, (struct timezone *)0);
    
  if (target){
    target += period;
  } else {
    memcpy(&tm, localtime((time_t *)&tv->tv_sec), sizeof(tm));
    tm.tm_sec = 0;
    tm.tm_min = 0;
    tm.tm_hour++;
    nexthour = mktime(&tm);

    target = (nexthour - tv->tv_sec) % period;
    if (target == 0)
      target = period;
    target += tv->tv_sec;
  }
    
  tv->tv_sec = target - tv->tv_sec;
  if (tv->tv_usec != 0){
    tv->tv_sec--;
    tv->tv_usec = 1000000 - tv->tv_usec;
  }
  if (tv->tv_sec < 0){
    /* ran out of time, schedule immediately */
    tv->tv_sec = 0;
    tv->tv_usec = 0;
  }
  count = 1;
  while(count != 0){
    count = select(0, 0, 0, 0, tv);
    switch (count){
    case 0:
      break;
    case -1:
      /* FALLTHRU */
    default:
      perror("select");
      break;
    }
  }
}

oid sysUpTimeOid[9] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
int sysUpTimeLen = 9;

int main(argc, argv)
int argc;
char **argv;
{
  struct snmp_session session, *ss;
  struct snmp_pdu *pdu, *response;
  struct variable_list *vars;
  int	arg;
  char *gateway;

  int	count, current_name = 0;
  struct varInfo varinfo[128], *vip;
  u_int value;
  float printvalue;
  int period = 1;
  int deltat = 0, timestamp = 0, fileout = 0, dosum = 0, printmax = 0;
  int keepSeconds = 0, peaks = 0;
  time_t last_time = 0;
  time_t this_time;
  time_t delta_time;
  int sum;
  char filename[128];
  struct timeval tv;
  struct tm tm;
  char timestring[64], valueStr[64], maxStr[64], peakStr[64];
  char outstr[256];
  int status;
  int begin, end, last_end;
  int varbindsPerPacket = 60;
  int print = 1;
    
  arg = snmp_parse_args(argc, argv, &session);
  gateway = session.peername;

  /*
   * usage: snmpdelta gateway-name community-name [-f commandFile] [-l]
   * [-v vars/pkt] [-s] [-t] [-S] [-p period] [-P peaks] [-k]
   * [-L SumFileName] variable list ..
   */

  Argc = 0;
  for(; arg < argc; arg++){
    if (argv[arg][0] == '-'){
      switch(argv[arg][1]){
      case 'd':
	snmp_set_dump_packet(1);
	break;
      case 'p':
	period = atoi(argv[++arg]);
	break;
      case 'P':
	peaks = atoi(argv[++arg]);
	break;
      case 'v':
	varbindsPerPacket = atoi(argv[++arg]);
	break;
      case 't':
	deltat = 1;
	break;
      case 's':
	timestamp = 1;
	break;
      case 'S':
	dosum = 1;
	break;
      case 'm':
	printmax = 1;
	break;
      case 'f':
	processFileArgs(argv[++arg]);
	break;
      case 'l':
	fileout = 1;
	break;
      case 'L':
	SumFile = argv[++arg];
	break;
      case 'k':
	keepSeconds = 1;
	break;
      default:
	fprintf(stderr, "Invalid option: -%c\n", argv[arg][1]);
	usage();
	exit(1);
	break;
      }
    } else {
      Argv[Argc++] = strdup(argv[arg]);
    }
  }

  for (arg = 0; arg < Argc; arg++)
    varinfo[current_name++].name = Argv[arg];

  if (current_name == 0){
    usage();
    exit(1);
  }
    
  if (dosum){
    varinfo[current_name++].name = 0;
  }

  SOCK_STARTUP;
  snmp_synch_setup(&session);
  ss = snmp_open(&session);
  if (ss == NULL){
    snmp_perror("snmpdelta");
    SOCK_CLEANUP;
    exit(1);
  }
    
  for(count = 0; count < current_name; count++){
    vip = varinfo + count;
    if (vip->name){
      vip->oidlen = MAX_NAME_LEN;
      vip->oid = (oid *)malloc(sizeof(oid) * vip->oidlen);
      if (snmp_parse_oid(vip->name, vip->oid, &vip->oidlen) == NULL) {
	fprintf(stderr, "Invalid object identifier: %s\n", vip->name);
	SOCK_CLEANUP;
	exit(1);
      }
      sprint_descriptor(vip->descriptor, vip);
    } else {
      vip->oidlen = 0;
      strcpy(vip->descriptor, SumFile);
    }
    vip->value = 0;
    vip->time = 0;
    vip->max = 0;
    if (peaks){
      vip->peak_count = -1;
      vip->peak = 0;
      vip->peak_average = 0;
    }
  }
    
  wait_for_period(period);

  end = current_name;
  sum = 0;
  while(1){
    pdu = snmp_pdu_create(GET_REQ_MSG);
	
    if (deltat)
      snmp_add_null_var(pdu, sysUpTimeOid, sysUpTimeLen);

    if (end == current_name)
      count = 0;
    else
      count = end;
    begin = count;
    for(; count < current_name
	  && count < begin + varbindsPerPacket - deltat; count++){
      if (varinfo[count].oidlen)
	snmp_add_null_var(pdu, varinfo[count].oid, varinfo[count].oidlen);
    }
    last_end = end;
    end = count;
	
  retry:
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
	if (timestamp){
	  gettimeofday(&tv, (struct timezone *)0);
	  memcpy(&tm, localtime((time_t *) &tv.tv_sec), sizeof(tm));
	  if (((period % 60)
	       && (!peaks || ((period * peaks) % 60)))
	      || keepSeconds)
	    sprintf(timestring, " [%02d:%02d:%02d %d/%d]",
		    tm.tm_hour, tm.tm_min, tm.tm_sec,
		    tm.tm_mon+1, tm.tm_mday);
	  else
	    sprintf(timestring, " [%02d:%02d %d/%d]",
		    tm.tm_hour, tm.tm_min,
		    tm.tm_mon+1, tm.tm_mday);
	}

	vars = response->variables;
	if (deltat){
	  if (!vars){
	    fprintf(stderr, "Missing variable in reply\n");
	    continue;
	  } else {
	    this_time = *(vars->val.integer);
	  }
	  vars = vars->next_variable;
	} else {
	  this_time = 1;
	}

	for(count = begin; count < end; count++){
	  vip = varinfo + count;

	  if (vip->oidlen){
	    if (!vars){
	      fprintf(stderr, "Missing variable in reply\n");
	      break;
	    }
	    value = *(vars->val.integer) - vip->value;
	    vip->value = *(vars->val.integer);
	    vars = vars->next_variable;
	  } else {
	    value = sum;
	    sum = 0;
	  }
	  delta_time = this_time - vip->time;
	  if (delta_time <= 0)
	    delta_time = 100;
	  last_time = vip->time;
	  vip->time = this_time;
	  if (last_time == 0)
	    continue;

	  if (vip->oidlen)
	    sum += value;

	  sprintf(outstr, "%s %s", timestring, vip->descriptor);

	  if (deltat){
	    printvalue = ((float)value * 100) / delta_time;
	    sprintf(valueStr, " /sec: %.2f", printvalue);
	  } else {
	    printvalue = value;
	    sprintf(valueStr, " /%d sec: %.0f",
		    period, printvalue);
	  }

	  if (!peaks){
	    strcat(outstr, valueStr);
	  } else {
	    print = 0;
	    if (vip->peak_count == -1){
	      if (wait_for_peak_start(period, peaks) == 0)
		vip->peak_count = 0;
	    } else {
	      vip->peak_average += printvalue;
	      if (vip->peak < printvalue)
		vip->peak = printvalue;
	      if (++vip->peak_count == peaks){
		if (deltat)
		  sprintf(peakStr,
			  " /sec: %.2f	(%d sec Peak: %.2f)",
			  vip->peak_average/vip->peak_count,
			  period, vip->peak);
		else
		  sprintf(peakStr,
			  " /%d sec: %.0f	(%d sec Peak: %.0f)",
			  period,
			  vip->peak_average/vip->peak_count,
			  period, vip->peak);
		vip->peak_average = 0;
		vip->peak = 0;
		vip->peak_count = 0;
		print = 1;
		strcat(outstr, peakStr);
	      }
	    }
	  }
    
	  if (printmax){
	    if (printvalue > vip->max){
	      vip->max = printvalue;
	    }
	    if (deltat)
	      sprintf(maxStr, "	(Max: %.2f)", vip->max);
	    else
	      sprintf(maxStr, "	(Max: %.0f)", vip->max);
	    strcat(outstr, maxStr);
	  }

	  if (print){
	    if (fileout){
	      sprintf(filename, "%s-%s", gateway, vip->descriptor);
	      log(filename, outstr + 1);
	    } else {
	      fprintf(stderr, "%s\n", outstr + 1);
	      fflush(stdout);
	    }
	  }
	}
      } else {
	if (response->errstat == SNMP_ERR_TOOBIG){
	  if (response->errindex <= varbindsPerPacket
	      && response->errindex > 0){
	    varbindsPerPacket = response->errindex - 1;
	  } else {
	    if (varbindsPerPacket > 30)
	      varbindsPerPacket -= 5;
	    else
	      varbindsPerPacket--;
	  }
	  if (varbindsPerPacket <= 0)
	    exit(5);
	  end = last_end;
	  continue;
	} else if (response->errstat == SNMP_ERR_NOSUCHNAME){
	  fprintf(stderr, "This object doesn't exist on %s: ", gateway);
	  for(count = 1, vars = response->variables;
	      vars && count != response->errindex;
	      vars = vars->next_variable, count++)
	    ;
	  if (vars)
	    fprint_objid(stderr, vars->name, vars->name_length);
	  fprintf(stderr, "\n");
	  SOCK_CLEANUP;
	  exit(1);
	} else {
	  fprintf(stderr, "Error in packet: %s\n",
		  snmp_errstring(response->errstat));
	  SOCK_CLEANUP;
	  exit(1);
	}
	if ((pdu = snmp_fix_pdu(response, GET_REQ_MSG)) != NULL)
	  goto retry;
      }
	    
    } else if (status == STAT_TIMEOUT){
      fprintf(stderr, "No Response from %s\n", gateway);
      response = 0;
      break;
    } else {    /* status == STAT_ERROR */
      snmp_perror("snmpdelta");
      response = 0;
      break;
    }
	
    if (response)
      snmp_free_pdu(response);
    if (end == current_name){
      wait_for_period(period);
    }
  }
  snmp_close(ss);
  SOCK_CLEANUP;
  exit(0);
}
