/*
 * snmptrapd_log.c - format SNMP trap information for logging
 *
 */
/*****************************************************************
	Copyright 1989, 1991, 1992 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its
documentation for any purpose and without fee is hereby granted,
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#else
#include <sys/socket.h>
#endif
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <ctype.h>
#if HAVE_SYS_TIME_H
# include <sys/time.h>
# if TIME_WITH_SYS_TIME
#  include <time.h>
# endif
#else
# include <time.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if HAVE_NET_IF_H
#include <net/if.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "mib.h"
#include "snmp.h"
#include "tools.h"

#include "snmptrapd_log.h"


#ifndef BSD4_3
#define BSD4_2
#endif

/* These flags mark undefined values in the options structure */
#define UNDEF_CMD '*'
#define UNDEF_PRECISION -1

/* This structure holds the options for a single format command */
typedef struct {
  char cmd;                   /* the format command itself */
  int  width;                 /* the field's minimum width */
  int  precision;             /* the field's precision */
  int  left_justify;          /* if true, left justify this field */
  int  alt_format;            /* if true, display in alternate format */
  int  leading_zeroes;        /* if true, display with leading zeroes */
} options_type;

/* 
 * These symbols define the characters that the parser recognizes.
 * The rather odd choice of symbols comes from an attempt to avoid
 * colliding with the ones that printf uses, so that someone could add
 * printf functionality to this code and turn it into a library
 * routine in the future.  
 */
typedef enum {
  CHR_FMT_DELIM  = '%',       /* starts a format command */
  CHR_LEFT_JUST  = '-',       /* left justify */
  CHR_LEAD_ZERO  = '0',       /* use leading zeroes */
  CHR_ALT_FORM   = '#',       /* use alternate format */
  CHR_FIELD_SEP  = '.',       /* separates width and precision fields */
  CHR_CUR_TIME   = 't',       /* current time, Unix format */
  CHR_CUR_YEAR   = 'y',       /* current year */
  CHR_CUR_MONTH  = 'm',       /* current month */
  CHR_CUR_MDAY   = 'l',       /* current day of month */
  CHR_CUR_HOUR   = 'h',       /* current hour */
  CHR_CUR_MIN    = 'j',       /* current minute */
  CHR_CUR_SEC    = 'k',       /* current second */
  CHR_UP_TIME    = 'T',       /* uptime, Unix format */
  CHR_UP_YEAR    = 'Y',       /* uptime year */
  CHR_UP_MONTH   = 'M',       /* uptime month */
  CHR_UP_MDAY    = 'L',       /* uptime day of month */
  CHR_UP_HOUR    = 'H',       /* uptime hour */
  CHR_UP_MIN     = 'J',       /* uptime minute */
  CHR_UP_SEC     = 'K',       /* uptime second */
  CHR_AGENT_IP   = 'a',       /* agent's IP address */
  CHR_AGENT_NAME = 'A',       /* agent's host name if available */
  CHR_PDU_IP     = 'b',       /* PDU's IP address */
  CHR_PDU_NAME   = 'B',       /* PDU's host name if available */
  CHR_PDU_ENT    = 'N',       /* PDU's enterprise string */
  CHR_PDU_WRAP	 = 'P',       /* PDU's wrapper info (community, security) */
  CHR_TRAP_NUM   = 'w',       /* trap number */
  CHR_TRAP_DESC  = 'W',       /* trap's description (textual) */
  CHR_TRAP_STYPE = 'q',       /* trap's subtype */
  CHR_TRAP_VARS  = 'v'        /* tab-separated list of trap's variables */
} parse_chr_type;

/* These symbols define the states for the parser's state machine */
typedef enum {
  PARSE_NORMAL,              /* looking for next character */
  PARSE_BACKSLASH,           /* saw a backslash */
  PARSE_IN_FORMAT,           /* saw a % sign, in a format command */
  PARSE_GET_WIDTH,           /* getting field width */
  PARSE_GET_PRECISION        /* getting field precision */
} parse_state_type;

/* macros */

#define is_cur_time_cmd(chr) ((((chr) == CHR_CUR_TIME)     \
			       || ((chr) == CHR_CUR_YEAR)  \
			       || ((chr) == CHR_CUR_MONTH) \
			       || ((chr) == CHR_CUR_MDAY)  \
			       || ((chr) == CHR_CUR_HOUR)  \
			       || ((chr) == CHR_CUR_MIN)   \
			       || ((chr) == CHR_CUR_SEC)) ? TRUE : FALSE)
     /*
      * Function:
      *    Returns true if the character is a format command that outputs
      * some field that deals with the current time.
      *
      * Input Parameters:
      *    chr - character to check
      */

#define is_up_time_cmd(chr) ((((chr) == CHR_UP_TIME)     \
			      || ((chr) == CHR_UP_YEAR)  \
			      || ((chr) == CHR_UP_MONTH) \
			      || ((chr) == CHR_UP_MDAY)  \
			      || ((chr) == CHR_UP_HOUR)  \
			      || ((chr) == CHR_UP_MIN)   \
			      || ((chr) == CHR_UP_SEC)) ? TRUE : FALSE)
     /*
      * Function:
      *    Returns true if the character is a format command that outputs
      * some field that deals with up-time.
      *
      * Input Parameters:
      *    chr - character to check
      */

#define is_agent_cmd(chr) ((((chr) == CHR_AGENT_IP) \
			    || ((chr) == CHR_AGENT_NAME)) ? TRUE : FALSE)
     /*
      * Function:
      *    Returns true if the character outputs information about the
      * agent.
      *
      * Input Parameters:
      *    chr - the character to check
      */

#define is_pdu_ip_cmd(chr) ((((chr) == CHR_PDU_IP)   \
			  || ((chr) == CHR_PDU_NAME)) ? TRUE : FALSE)
     /*
      * Function:
      *    Returns true if the character outputs information about the PDU's
      * host name or IP address.
      *
      * Input Parameters:
      *    chr - the character to check
      */

#define is_trap_cmd(chr) ((((chr) == CHR_TRAP_NUM)      \
			   || ((chr) == CHR_TRAP_DESC)  \
			   || ((chr) == CHR_TRAP_STYPE) \
			   || ((chr) == CHR_TRAP_VARS)) ? TRUE : FALSE)

     /*
      * Function:
      *    Returns true if the character outputs information about the trap.
      *
      * Input Parameters:
      *    chr - the character to check
      */

#define is_fmt_cmd(chr) ((is_cur_time_cmd (chr)     \
			  || is_up_time_cmd (chr)   \
			  || is_agent_cmd (chr)     \
			  || is_pdu_ip_cmd (chr)    \
                          || ((chr) == CHR_PDU_ENT) \
                          || ((chr) == CHR_PDU_WRAP) \
			  || is_trap_cmd (chr)) ? TRUE : FALSE)
     /*
      * Function:
      *    Returns true if the character is a format command.
      * 
      * Input Parameters:
      *    chr - character to check
      */

#define is_numeric_cmd(chr) ((is_cur_time_cmd(chr)   \
			      || is_up_time_cmd(chr) \
			      || (chr) == CHR_TRAP_NUM) ? TRUE : FALSE)
     /*
      * Function:
      *    Returns true if this is a numeric format command.
      *
      * Input Parameters:
      *    chr - character to check
      */

#define reference(var) ((var) == (var))

     /*
      * Function:
      *    Some compiler options will tell the compiler to be picky and
      * warn you if you pass a parameter to a function but don't use it.
      * This macro lets you reference a parameter so that the compiler won't
      * generate the warning. It has no other effect.
      *
      * Input Parameters:
      *    var - the parameter to reference
      */

/* prototypes */
extern const char * trap_description (int trap);

static void init_options (options_type * options)

     /*
      * Function:
      *    Initialize a structure that contains the option settings for
      * a format command.
      *
      * Input Parameters:
      *    options - points to the structure to initialize
      */
{
  /* initialize the structure's fields */
  options->cmd = '*';
  options->width = 0;
  options->precision = UNDEF_PRECISION;
  options->left_justify = FALSE;
  options->alt_format = FALSE;
  options->leading_zeroes = FALSE;
  return;
}

static void str_append (char * dest,
			unsigned long * tail,
			unsigned long limit,
			const char * source)

     /*
      * Function:
      *    This function is similar to strncpy, in that it copies
      * characters, up to the specified limit, from the source string.
      * It copies them onto the destination starting at the index
      * "tail". This copy operation does NOT include the terminating
      * null character.  The routine updates the contents of "tail"
      * after the copy operation.
      *
      * Input Parameters:
      *    dest   - copy onto this string
      *    tail   - last character in the destination buffer
      *    limit  - copy up to this many characters 
      *    source - copy characters from this string
      */
{
  unsigned long copy_count = 0;           /* number of characters copied */

  /* copy characters until we hit a null or a limit */
  for (copy_count = 0;
       source[copy_count] != '\0' && *tail < limit;
       copy_count++)
    {
      dest[*tail] = source[copy_count];
      (*tail)++;
    }
}

static void output_temp_bfr (char * bfr,
			     unsigned long * tail,
			     unsigned long len,
			     char * temp_bfr,
			     options_type * options)

     /*
      * Function:
      *    Append the contents of the temporary buffer to the specified
      * buffer using the correct justification, leading zeroes, width,
      * precision, and other characteristics specified in the options
      * structure. This routine modifies the contents of "tail" to point
      * to the new tail of the buffer. It does NOT append the terminating
      * null character.
      *
      *    bfr      - append data to this buffer
      *    tail     - points one character beyond current last char in bfr
      *    len      - length of buffer - truncate after this point
      *    temp_bfr - String to append onto output buffer. THIS ROUTINE
      *               MAY CHANGE THE CONTENTS OF THIS BUFFER.
      *    options  - what options to use when appending string
      */
{
  int temp_len;           /* length of temporary buffer */
  int temp_to_write;      /* # of chars to write from temp bfr */
  int char_to_write;      /* # of other chars to write */
  int zeroes_to_write;    /* fill to precision with zeroes for numbers */

  /* 
   * Figure out how many characters are in the temporary buffer now,
   * and how many of them we'll write.
   */
  temp_len = (int) strlen (temp_bfr);
  temp_to_write = temp_len;
  if (temp_to_write > options->precision && options->precision != UNDEF_PRECISION)
    temp_to_write = options->precision;

  /* handle leading characters */
  if ((! options->left_justify) && (temp_to_write < options->width)) {
    zeroes_to_write = options->precision - temp_to_write;
    if (!is_numeric_cmd(options->cmd)) zeroes_to_write = 0;
    for (char_to_write = options->width - temp_to_write;
	 char_to_write > 0;
	 char_to_write--) {
      if (options->leading_zeroes || zeroes_to_write-- > 0)
	str_append (bfr, tail, len, "0");
      else
	str_append (bfr, tail, len, " ");
    }
  }

  /* truncate the temporary buffer and append its contents */
  temp_bfr[temp_to_write] = '\0';
  str_append (bfr, tail, len, temp_bfr);

  /* handle trailing characters */
  if ((options->left_justify) && (temp_to_write < options->width)) {
    for (char_to_write = options->width - temp_to_write;
	 char_to_write > 0;
	 char_to_write--)
      str_append (bfr, tail, len, "0");
  }
    
  return;
}

static void handle_time_fmt (char * bfr,
			     unsigned long * tail,
			     unsigned long len,
			     options_type * options,
			     struct snmp_pdu * pdu)

     /*
      * Function:
      *    Handle a format command that deals with the current or up-time.
      * Append the correct time information to the buffer subject to the
      * buffer's length limit.
      *
      * Input Parameters:
      *    bfr     - append the results to this buffer
      *    tail    - index of one character beyond last buffer element
      *    len     - length of the buffer
      *    options - options governing how to write the field
      *    pdu     - information about this trap
      */
{
  time_t        time_val;           /* the time value to output */
  struct tm *   parsed_time;        /* parsed version of current time */
  char          safe_bfr[30];       /* temporary string-building buffer */
  char          fmt_cmd = options->cmd; /* the format command to use */
  int           offset = 0;         /* offset into string to display */
  int           year_len;           /* length of year string */

  /* get the time field to output */
  if (is_up_time_cmd (fmt_cmd))
    time_val = pdu->time;
  else
    time (&time_val);

  /* handle output in Unix time format */
  if (fmt_cmd == CHR_CUR_TIME)
    sprintf (safe_bfr, "%ld", (long) time_val);
  else if (fmt_cmd == CHR_UP_TIME && !options->alt_format)
    sprintf (safe_bfr, "%ld", (long) time_val);
  else if (fmt_cmd == CHR_UP_TIME) {
    int centisecs, seconds, minutes, hours, days;

    centisecs = time_val % 100;
    time_val /= 100;
    days = time_val / (60 * 60 * 24);
    time_val %= (60 * 60 * 24);

    hours = time_val / (60 * 60);
    time_val %= (60 * 60);

    minutes = time_val / 60;
    seconds = time_val % 60;

    switch (days) {
    case 0:
      sprintf(safe_bfr, "%d:%02d:%02d.%02d", hours, minutes, seconds, centisecs);
      break;
    case 1:
      sprintf(safe_bfr, "1 day, %d:%02d:%02d.%02d", hours, minutes, seconds, centisecs);
      break;
    default:
      sprintf(safe_bfr, "%d days, %d:%02d:%02d.%02d",
	      days, hours, minutes, seconds, centisecs);
    }
  }

  /* handle other time fields */
  else {
    if (options->alt_format)
      parsed_time = gmtime (&time_val);
    else
      parsed_time = localtime (&time_val);
    switch (fmt_cmd) 
      {
      /* 
       * Output year. The year field is unusual: if there's a restriction 
       * on precision, we want to truncate from the left of the number,
       * not the right, so someone printing the year 1972 with 2 digit 
       * precision gets "72" not "19".
       */
      case CHR_CUR_YEAR:
      case CHR_UP_YEAR:
	sprintf (safe_bfr, "%d", parsed_time->tm_year + 1900);
	if (options->precision != UNDEF_PRECISION) {
	  year_len = (unsigned long) strlen (safe_bfr);
	  if (year_len > options->precision)
	    offset = year_len - options->precision;
	}
	break;

      /* output month */
      case CHR_CUR_MONTH:
      case CHR_UP_MONTH:
	sprintf (safe_bfr, "%d", parsed_time->tm_mon + 1);
	break;

      /* output day of month */
      case CHR_CUR_MDAY:
      case CHR_UP_MDAY:
	sprintf (safe_bfr, "%d", parsed_time->tm_mday);
	break;

      /* output hour */
      case CHR_CUR_HOUR:
      case CHR_UP_HOUR:
	sprintf (safe_bfr, "%d", parsed_time->tm_hour);
	break;

      /* output minute */
      case CHR_CUR_MIN:
      case CHR_UP_MIN:
	sprintf (safe_bfr, "%d", parsed_time->tm_min);
	break;

      /* output second */
      case CHR_CUR_SEC:
      case CHR_UP_SEC:
	sprintf (safe_bfr, "%d", parsed_time->tm_sec);
	break;

      /* unknown format command - just output the character */
      default:
	sprintf (safe_bfr, "%c", fmt_cmd);
      }
  }

  /* output with correct justification, leading zeroes, etc. */
  output_temp_bfr (bfr, tail, len, &(safe_bfr[offset]), options);
  return;
}

static void handle_ip_fmt (char * bfr,
			   unsigned long * tail,
			   unsigned long len,
			   options_type * options,
			   struct snmp_pdu * pdu)

     /*
      * Function:
      *     Handle a format command that deals with an IP address 
      * or host name.  Append the information to the buffer subject to
      * the buffer's length limit.
      *
      * Input Parameters:
      *    bfr     - append the results to this buffer
      *    tail    - index of one character beyond last buffer element
      *    len     - length of the buffer
      *    options - options governing how to write the field
      *    pdu     - information about this trap 
      */
{
  struct sockaddr_in * ip_addr;       /* IP address to output */
  struct hostent *     host;          /* corresponding host name */
  char                 safe_bfr[200]; /* temporary string-building buffer */
  char                 fmt_cmd = options->cmd; /* what we're formatting */

  /* figure out which IP address to write */
  if (is_agent_cmd (fmt_cmd))
    ip_addr = (struct sockaddr_in *) &(pdu->agent_addr);
  else
    ip_addr = (struct sockaddr_in *) &(pdu->address);

  /* decide exactly what to output */
  switch (fmt_cmd)
    {
    /* write an IP address */
    case CHR_AGENT_IP:
    case CHR_PDU_IP:
      sprintf (safe_bfr, "%s", inet_ntoa (ip_addr->sin_addr));
      break;

    /* write a host name */
    case CHR_AGENT_NAME:
    case CHR_PDU_NAME:
      host = gethostbyaddr ((char *) &(ip_addr->sin_addr),
			    sizeof (ip_addr->sin_addr),
			    AF_INET);
      if (host != (struct hostent *) NULL)
	sprintf (safe_bfr, "%s", host->h_name);
      else
	sprintf (safe_bfr, "%s", inet_ntoa (ip_addr->sin_addr));
      break;

    /* don't know how to handle this command - write the character itself */
    default:
      sprintf (safe_bfr, "%c", fmt_cmd);
    }

  /* output with correct justification, leading zeroes, etc. */
  output_temp_bfr (bfr, tail, len, safe_bfr, options);
  return;
}

static void handle_ent_fmt (char * bfr,
			    unsigned long * tail,
			    unsigned long len,
			    options_type * options,
			    struct snmp_pdu * pdu)

     /*
      * Function:
      *     Handle a format command that deals with the enterprise 
      * string.  Append the information to the buffer subject to the
      * buffer's length limit.
      *
      * Input Parameters:
      *    bfr     - append the results to this buffer
      *    tail    - index of one character beyond last buffer element
      *    len     - length of the buffer
      *    options - options governing how to write the field
      *    pdu     - information about this trap 
      */
{
  char safe_bfr[SPRINT_MAX_LEN]; /* temporary string-building buffer */
  char fmt_cmd = options->cmd;   /* what we're formatting */

  /* decide exactly what to output */
  switch (fmt_cmd)
    {
    /* write the enterprise string */
    case CHR_PDU_ENT:
      sprint_objid (safe_bfr, pdu->enterprise, pdu->enterprise_length);
      break;

    /* don't know how to handle this command - write the character itself */
    default:
      sprintf (safe_bfr, "%c", fmt_cmd);
    }

  /* output with correct justification, leading zeroes, etc. */
  output_temp_bfr (bfr, tail, len, safe_bfr, options);
  return;
}

static void handle_trap_fmt (char * bfr,
			     unsigned long * tail,
			     unsigned long len,
			     options_type * options,
			     struct snmp_pdu * pdu)

     /*
      * Function:
      *     Handle a format command that deals with the trap itself. 
      * Append the information to the buffer subject to the buffer's 
      * length limit.
      *
      * Input Parameters:
      *    bfr     - append the results to this buffer
      *    tail    - index of one character beyond last buffer element
      *    len     - length of the buffer
      *    options - options governing how to write the field
      *    pdu     - information about this trap 
      */
{
  oid                    trap_oid[MAX_OID_LEN]; /* holds obj id for trap */
  unsigned long          trap_oid_len;          /* length of object ID */
  struct variable_list * vars;                  /* variables assoc with trap */
  char                   sprint_bfr[SPRINT_MAX_LEN]; /* string-building bfr */
  char                   safe_bfr[SNMP_MAXBUF]; /* string-building bfr */
  char *                 out_ptr = safe_bfr;    /* points to str to output */
  unsigned long          safe_tail;             /* end of safe buffer */
  char                   fmt_cmd = options->cmd; /* what we're outputting */

  /* decide exactly what to output */
  switch (fmt_cmd)
    {
    /* write the trap's number */
    case CHR_TRAP_NUM:
      sprintf (safe_bfr, "%ld", pdu->trap_type);
      break;

    /* write the trap's description */
    case CHR_TRAP_DESC:
      sprintf (safe_bfr, "%s", trap_description (pdu->trap_type));
      break;

    /* write the trap's subtype */
    case CHR_TRAP_STYPE:
      if (pdu->trap_type != SNMP_TRAP_ENTERPRISESPECIFIC) {
	sprintf (safe_bfr, "%ld", pdu->specific_type);
      }
      else {
	
	/* get object ID for the trap */
	trap_oid_len = pdu->enterprise_length;
	memcpy (trap_oid, pdu->enterprise, sizeof (oid) * trap_oid_len);
	if (trap_oid[trap_oid_len - 1] != 0) {
	  trap_oid[trap_oid_len] = 0;
	  trap_oid_len++;
	}
	trap_oid[trap_oid_len] = pdu->specific_type;
	trap_oid_len++;

	/* find the element after the last dot */
	sprint_objid (sprint_bfr, trap_oid, trap_oid_len);
	out_ptr = strrchr (sprint_bfr, '.');
	if (out_ptr != (char *) NULL)
	  out_ptr++;
	else
	  out_ptr = sprint_bfr;
      }
      break;

    /* write the trap's variables */
    case CHR_TRAP_VARS:
      safe_tail = 0;
      for (vars = pdu->variables;
	   vars != (struct variable_list *) NULL && safe_tail < SNMP_MAXBUF;
	   vars = vars->next_variable) {
	if (options->alt_format)
	  str_append (safe_bfr, &safe_tail, SNMP_MAXBUF, ", ");
	else
	  str_append (safe_bfr, &safe_tail, SNMP_MAXBUF, "\t");
	sprint_variable (sprint_bfr, vars->name, vars->name_length, vars);
	str_append (safe_bfr, &safe_tail, SNMP_MAXBUF, sprint_bfr);
      }
      if (safe_tail < SNMP_MAXBUF) {
	safe_bfr[safe_tail] = '\0';
	safe_tail++;
      }
      else
          safe_bfr[safe_tail - 1] = '\0';
      break;

    /* don't know how to handle this command - write the character itself */
    default:
      sprintf (safe_bfr, "%c", fmt_cmd);
    }

  /* output with correct justification, leading zeroes, etc. */
  output_temp_bfr (bfr, tail, len, out_ptr, options);
  if (*tail < len) {
      bfr[*tail] = '\0';
  } else {
      bfr[len-1] = '\0';
  }

  return;
}

static void handle_wrap_fmt(char *bfr, unsigned long *tail, unsigned long len,
  			   struct snmp_pdu *pdu)
{
#define LCL_SAFE_LEN 200
  char                   sprint_bfr[SPRINT_MAX_LEN]; /* string-building bfr */
  char                   safe_bfr[LCL_SAFE_LEN]; /* string-building bfr */
  unsigned long          safe_tail = 0;             /* end of safe buffer */
  char *                 cp;
  int                    i;
  
  switch (pdu->command) {
  case SNMP_MSG_TRAP:
      str_append (safe_bfr, &safe_tail, LCL_SAFE_LEN, "TRAP");
      break;
  case SNMP_MSG_TRAP2:
      str_append (safe_bfr, &safe_tail, LCL_SAFE_LEN, "TRAP2");
      break;
  case SNMP_MSG_INFORM:
      str_append (safe_bfr, &safe_tail, LCL_SAFE_LEN, "INFORM");
      break;
  }
  str_append(safe_bfr, &safe_tail, LCL_SAFE_LEN, ", SNMP v");
  switch (pdu->version) {
  case SNMP_VERSION_1:
      str_append (safe_bfr, &safe_tail, LCL_SAFE_LEN, "1");
      break;
  case SNMP_VERSION_2c:
      str_append (safe_bfr, &safe_tail, LCL_SAFE_LEN, "2c");
      break;
  case SNMP_VERSION_3:
      str_append (safe_bfr, &safe_tail, LCL_SAFE_LEN, "3");
      break;
  }
  switch (pdu->version) {
  case SNMP_VERSION_1:
  case SNMP_VERSION_2c:
      str_append(safe_bfr, &safe_tail, LCL_SAFE_LEN, ", Community ");
      cp = sprint_bfr;
      for (i = 0; i < (int)pdu->community_len; i++)
          if (isprint(pdu->community[i])) *cp++ = pdu->community[i];
	  else *cp++ = '.';
      *cp = 0;
      str_append(safe_bfr, &safe_tail, LCL_SAFE_LEN, sprint_bfr);
      break;
  case SNMP_VERSION_3:
      str_append(safe_bfr, &safe_tail, LCL_SAFE_LEN, ", User ");
      cp = sprint_bfr;
      for (i = 0; i < (int)pdu->securityNameLen; i++)
          if (isprint(pdu->securityName[i])) *cp++ = pdu->securityName[i];
	  else *cp++ = '.';
      *cp = 0;
      str_append(safe_bfr, &safe_tail, LCL_SAFE_LEN, sprint_bfr);
      str_append(safe_bfr, &safe_tail, LCL_SAFE_LEN, ", Context ");
      cp = sprint_bfr;
      for (i = 0; i < (int)pdu->contextNameLen; i++)
          if (isprint(pdu->contextName[i])) *cp++ = pdu->contextName[i];
	  else *cp++ = '.';
      *cp = 0;
      str_append(safe_bfr, &safe_tail, LCL_SAFE_LEN, sprint_bfr);
      break;
  }
  str_append (bfr, tail, len, safe_bfr);
}

static void dispatch_format_cmd (char * bfr,
				 unsigned long * tail,
				 unsigned long len,
				 options_type * options,
				 struct snmp_pdu * pdu)

     /*
      * Function:
      *     Dispatch a format command to the appropriate command handler.
      *
      * Input Parameters:
      *    bfr     - append the results to this buffer
      *    tail    - index of one character beyond last buffer element
      *    len     - length of the buffer
      *    options - options governing how to write the field
      *    pdu     - information about this trap 
      */
{
  char fmt_cmd = options->cmd;          /* for speed */

  /* choose the appropriate command handler */
  if (is_cur_time_cmd (fmt_cmd) || is_up_time_cmd (fmt_cmd))
    handle_time_fmt (bfr, tail, len, options, pdu);
  else if (is_agent_cmd (fmt_cmd) || is_pdu_ip_cmd (fmt_cmd))
    handle_ip_fmt (bfr, tail, len, options, pdu);
  else if (is_trap_cmd (fmt_cmd))
    handle_trap_fmt (bfr, tail, len, options, pdu);
  else if (fmt_cmd == CHR_PDU_ENT)
    handle_ent_fmt (bfr, tail, len, options, pdu);
  else if (fmt_cmd == CHR_PDU_WRAP)
    handle_wrap_fmt (bfr, tail, len, pdu);

  /* unknown command */
  else {
    if (*tail < len) {
      bfr[*tail] = fmt_cmd;
      (*tail)++;
    }
  }

  return;
}


static void handle_backslash (char * bfr,
			      unsigned long * tail,
			      unsigned long len,
			      char fmt_cmd)

     /*
      * Function:
      *     Handle a character following a backslash. Append the resulting 
      * character to the buffer subject to the buffer's length limit.
      *     This routine currently isn't sophisticated enough to handle
      * \nnn or \xhh formats.
      *
      * Input Parameters:
      *    bfr     - append the results to this buffer
      *    tail    - index of one character beyond last buffer element
      *    len     - length of the buffer
      *    fmt_cmd - the character after the backslash
      */
{
  char temp_bfr[3];                     /* for bulding temporary strings */

  /* select the proper output character(s) */
  switch (fmt_cmd)
    {
    case 'a':
      str_append (bfr, tail, len, "\a");
      break;
    case 'b':
      str_append (bfr, tail, len, "\b");
      break;
    case 'f':
      str_append (bfr, tail, len, "\f");
      break;
    case 'n':
      str_append (bfr, tail, len, "\n");
      break;
    case 'r':
      str_append (bfr, tail, len, "\r");
      break;
    case 't':
      str_append (bfr, tail, len, "\t");
      break;
    case 'v':
      str_append (bfr, tail, len, "\v");
      break;
    case '\\':
      str_append (bfr, tail, len, "\\");
      break;
    case '?':
      str_append (bfr, tail, len, "\?");
      break;
    case '\'':
      str_append (bfr, tail, len, "\'");
      break;
    case '"':
      str_append (bfr, tail, len, "\"");
      break;
    default:
      sprintf (temp_bfr, "\\%c", fmt_cmd);
      str_append (bfr, tail, len, temp_bfr);
    }

  return;
}

unsigned long format_plain_trap (char * bfr,
				 unsigned long len,
				 struct snmp_pdu * pdu)

     /*
      * Function:
      *    Format the trap information in the default way and put the results
      * into the buffer, truncating at the buffer's length limit. This
      * routine returns the number of characters that it puts into the buffer.
      *
      * Input Parameters:
      *    bfr - where to put the formatted trap info
      *    len - how many bytes of buffer space are available
      *    pdu - the pdu information
      */
{
  time_t                 now;                   /* the current time */
  struct tm *            now_parsed;            /* time in struct format */
  char                   sprint_bfr[SPRINT_MAX_LEN]; /* holds sprint strings */
  char                   safe_bfr[200];         /* holds other strings */
  unsigned long          tail = 0;              /* points to end of buffer */
  struct sockaddr_in *   agent_ip;              /* agent's IP info */
  struct sockaddr_in *   pdu_ip;                /* PDU's IP info */
  struct hostent *       host;                  /* host name */
  oid                    trap_oid[MAX_OID_LEN]; /* holds obj ID for trap */
  unsigned long          trap_oid_len;          /* length of object ID */
  char *                 ent_spec_code;         /* for ent. specific traps */
  struct variable_list * vars;                  /* variables assoc with trap */

  /* If the output buffer's pathologically short, RETURN EARLY. */
  if (len == 0)
    return 0;

  /* 
   * Print the current time. Since we don't know how long the buffer is,
   * and snprintf isn't yet standard, build the timestamp in a separate
   * buffer of guaranteed length and then copy it to the output buffer.
   */
  time (&now);
  now_parsed = localtime (&now);
  sprintf (safe_bfr, 
	   "%.4d-%.2d-%.2d %.2d:%.2d:%.2d ",
	   now_parsed->tm_year + 1900,
	   now_parsed->tm_mon + 1,
	   now_parsed->tm_mday,
	   now_parsed->tm_hour,
	   now_parsed->tm_min,
	   now_parsed->tm_sec);
  str_append (bfr, &tail, len, safe_bfr);

  /* get info about the sender */
  agent_ip = (struct sockaddr_in *) &(pdu->agent_addr);
  host = gethostbyaddr ((char *) &(agent_ip->sin_addr),
			sizeof (agent_ip->sin_addr),
			AF_INET);
  if (host != (struct hostent *) NULL)
    str_append (bfr, &tail, len, host->h_name);
  else
    str_append (bfr, &tail, len, inet_ntoa (agent_ip->sin_addr));
  str_append (bfr, &tail, len, " [");
  str_append (bfr, &tail, len, inet_ntoa (agent_ip->sin_addr));
  str_append (bfr, &tail, len, "] ");

  /* append PDU IP info if necessary */
  pdu_ip = (struct sockaddr_in *) &(pdu->address);
  if (agent_ip->sin_addr.s_addr != pdu_ip->sin_addr.s_addr) {
    str_append (bfr, &tail, len, "(via ");
    host = gethostbyaddr ((char *) &(pdu_ip->sin_addr),
			  sizeof (pdu_ip->sin_addr),
			  AF_INET);
    if (host != (struct hostent *) NULL)
      str_append (bfr, &tail, len, host->h_name);
    else
      str_append (bfr, &tail, len, inet_ntoa (pdu_ip->sin_addr));
    str_append (bfr, &tail, len, " [");
    str_append (bfr, &tail, len, inet_ntoa (pdu_ip->sin_addr));
    str_append (bfr, &tail, len, "]) ");
  }

  /* add security wrapper information */
  handle_wrap_fmt(bfr, &tail, len, pdu);
  str_append(bfr, &tail, len, "\n");

  /* add enterprise information */
  str_append (bfr, &tail, len, "\t");
  sprint_objid (sprint_bfr, pdu->enterprise, pdu->enterprise_length);
  str_append (bfr, &tail, len, sprint_bfr);

  /* handle enterprise specific traps */
  str_append (bfr, &tail, len, " ");
  str_append (bfr, &tail, len, trap_description (pdu->trap_type));
  str_append (bfr, &tail, len, " Trap (");
  if (pdu->trap_type == SNMP_TRAP_ENTERPRISESPECIFIC) {

    /* get object ID for the trap */
    trap_oid_len = pdu->enterprise_length;
    memcpy (trap_oid, pdu->enterprise, sizeof (oid) * trap_oid_len);
    if (trap_oid[trap_oid_len - 1] != 0) {
      trap_oid[trap_oid_len] = 0;
      trap_oid_len++;
    }
    trap_oid[trap_oid_len] = pdu->specific_type;
    trap_oid_len++;

    /* find the element after the last dot */
    sprint_objid (sprint_bfr, trap_oid, trap_oid_len);
    ent_spec_code = strrchr (sprint_bfr, '.');
    if (ent_spec_code != (char *) NULL)
      ent_spec_code++;
    else
      ent_spec_code = sprint_bfr;

    /* print trap info */
    str_append (bfr, &tail, len, ent_spec_code);
  }

  /* handle traps that aren't enterprise specific */
  else {
    sprintf (safe_bfr, "%ld", pdu->specific_type);
    str_append (bfr, &tail, len, safe_bfr);
  }

  /* finish the line */
  str_append (bfr, &tail, len, ") Uptime: ");
  str_append (bfr, &tail, len, uptime_string (pdu->time, safe_bfr));
  str_append (bfr, &tail, len, "\n");

  /* output the PDU variables */
  for (vars = pdu->variables; 
       vars != (struct variable_list *) NULL;
       vars = vars->next_variable) {
    str_append (bfr, &tail, len, "\t");
    sprint_variable (sprint_bfr, vars->name, vars->name_length, vars);
    str_append (bfr, &tail, len, sprint_bfr);
  }
  str_append (bfr, &tail, len, "\n");

  /* add the null terminator */
  if (tail < len) {
    bfr[tail] = '\0';
    tail++;
  }
  else 
    bfr[tail - 1] = '\0';

  return tail;
}

unsigned long format_trap (char * bfr,
			   unsigned long len,
			   const char * format_str,
			   struct snmp_pdu * pdu)

     /*
      * Function:
      *    Format the trap information for display in a log. Place the results
      * in the specified buffer (truncating to the length of the buffer).
      *    Returns the number of characters it put in the buffer.
      *
      * Input Parameters:
      *    bfr        - where to put the formatted trap info
      *    len        - how many bytes of buffer space are available
      *    format_str - specifies how to format the trap info
      *    pdu        - the pdu information
      */
{
  unsigned long    tail = 0;             /* points to the end of the buffer */
  unsigned long    fmt_idx = 0;          /* index into the format string */
  options_type     options;              /* formatting options */
  parse_state_type state = PARSE_NORMAL; /* state of the parser */
  char             next_chr;             /* for speed */
  int              reset_options = TRUE; /* reset opts on next NORMAL state */

  /* if the buffer's pathologically short, RETURN EARLY */
  if (len == 0)
    return 0;

  /* go until we reach the end of the format string */
  for (fmt_idx = 0;
       (format_str[fmt_idx] != '\0') && (tail < len);
       fmt_idx++) {
    next_chr = format_str[fmt_idx];
    switch (state)
      {
      /* looking for next character */
      case PARSE_NORMAL:
	if (reset_options) {
	  init_options (&options);
	  reset_options = FALSE;
	}
	if (next_chr == '\\') {
	  state = PARSE_BACKSLASH;
	}
	else if (next_chr == CHR_FMT_DELIM) {
	  state = PARSE_IN_FORMAT;
	}
	else {
	  if (tail < len) {
	    bfr[tail] = next_chr;
	    tail++;
	  }
	}
	break;

      /* found a backslash */
      case PARSE_BACKSLASH:
	handle_backslash (bfr, &tail, len, next_chr);
	state = PARSE_NORMAL;
	break;
	
      /* in a format command */
      case PARSE_IN_FORMAT:
	reset_options = TRUE;
	if (next_chr == CHR_LEFT_JUST)
	  options.left_justify = TRUE;
	else if (next_chr == CHR_LEAD_ZERO)
	  options.leading_zeroes = TRUE;
	else if (next_chr == CHR_ALT_FORM)
	  options.alt_format = TRUE;
	else if (next_chr == CHR_FIELD_SEP)
	  state = PARSE_GET_PRECISION;
	else if ((next_chr >= '1') && (next_chr <= '9')) {
	  options.width = ((unsigned long) next_chr) - ((unsigned long) '0');
	  state = PARSE_GET_WIDTH;
	}
	else if (is_fmt_cmd (next_chr)) {
	  options.cmd = next_chr;
	  dispatch_format_cmd (bfr, &tail, len, &options, pdu);
	  state = PARSE_NORMAL;
	}
	else {
	  if (tail < len) {
	    bfr[tail] = next_chr;
	    tail++;
	  }
	  state = PARSE_NORMAL;
	}
	break;

      /* parsing a width field */
      case PARSE_GET_WIDTH:
	reset_options = TRUE;
	if (isdigit (next_chr)) {
	  options.width *= 10;
	  options.width += (unsigned long) next_chr - (unsigned long) '0';
	}
	else if (next_chr == CHR_FIELD_SEP)
	  state = PARSE_GET_PRECISION;
	else if (is_fmt_cmd (next_chr)) {
	  options.cmd = next_chr;
	  dispatch_format_cmd (bfr, &tail, len, &options, pdu);
	  state = PARSE_NORMAL;
	}
	else {
	  if (tail < len) {
	    bfr[tail] = next_chr;
	    tail++;
	  }
	  state = PARSE_NORMAL;
	}
	break;

      /* parsing a precision field */
      case PARSE_GET_PRECISION:
	reset_options = TRUE;
	if (isdigit (next_chr)) {
	  if (options.precision == UNDEF_PRECISION)
	    options.precision = (unsigned long) next_chr - (unsigned long) '0';
	  else {
	    options.precision *= 10;
	    options.precision += (unsigned long) next_chr - (unsigned long) '0';
	  }
	}
	else if (is_fmt_cmd (next_chr)) {
	  options.cmd = next_chr;
	  if (options.width < options.precision)
	    options.width = options.precision;
	  dispatch_format_cmd (bfr, &tail, len, &options, pdu);
	  state = PARSE_NORMAL;
	}
	else {
	  if (tail < len) {
	    bfr[tail] = next_chr;
	    tail++;
	  }
	  state = PARSE_NORMAL;
	}
	break;

      /* unknown state */
      default:
	reset_options = TRUE;
	if (tail < len) {
	  bfr[tail] = next_chr;
	  tail++;
	}
	state = PARSE_NORMAL;
      }
  }

  /* append the null terminator */
  if (tail < len) {
    bfr[tail] = '\0';
    tail++;
  }
  else 
    bfr[tail - 1] = '\0';

  return tail;
}
