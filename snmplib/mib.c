/**********************************************************************
	Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

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

#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "mib.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "parse.h"
#include "int64.h"
#include "system.h"

static void sprint_by_type __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static int parse_subtree __P((struct tree *, char *, oid *, int *));
static char *uptimeString __P((u_long, char *));
static void sprint_hexstring __P((char *, u_char *, int));
static void sprint_asciistring __P((char *, u_char *, int));
static void sprint_octet_string __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_opaque __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_object_identifier __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_timeticks __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_hinted_integer __P((char *, long, char *, char *));
static void sprint_integer __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_uinteger __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_gauge __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_counter __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_networkaddress __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_ipaddress __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_null __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_bitstring __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_nsapaddress __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_counter64 __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_unknowntype __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_badtype __P((char *, struct variable_list *, struct enum_list *, char *, char *));
  
#ifdef OPAQUE_SPECIAL_TYPES
static void sprint_float __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static void sprint_double __P((char *, struct variable_list *, struct enum_list *, char *, char *));
#endif

int quick_print = 0;
static int full_objid = 0;
static int suffix_only = 0;

void snmp_set_quick_print(val)
    int val;
{
    quick_print = val;
}

int snmp_get_quick_print __P((void))
{
    return quick_print;
}

void snmp_set_full_objid(val)
    int val;
{
    full_objid = val;
}

int snmp_get_full_objid __P((void))
{
    return full_objid;
}

void snmp_set_suffix_only(val)
    int val;
{
    suffix_only = val;
}

int snmp_get_suffix_only __P((void))
{
    return suffix_only;
}

static char *
uptimeString(timeticks, buf)
    register u_long timeticks;
    char *buf;
{
    int	centisecs, seconds, minutes, hours, days;

    centisecs = timeticks % 100;
    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (quick_print)
	sprintf(buf, "%d:%d:%02d:%02d.%02d",
		days, hours, minutes, seconds, centisecs);
    else {
	if (days == 0){
	    sprintf(buf, "%d:%02d:%02d.%02d",
		hours, minutes, seconds, centisecs);
	} else if (days == 1) {
	    sprintf(buf, "%d day, %d:%02d:%02d.%02d",
		days, hours, minutes, seconds, centisecs);
	} else {
	    sprintf(buf, "%d days, %d:%02d:%02d.%02d",
		days, hours, minutes, seconds, centisecs);
	}
    }
    return buf;
}

static void sprint_hexstring(buf, cp, len)
    char *buf;
    u_char  *cp;
    int	    len;
{

    for(; len >= 16; len -= 16){
	sprintf(buf, "%02X %02X %02X %02X %02X %02X %02X %02X ", cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
	buf += strlen(buf);
	cp += 8;
	sprintf(buf, "%02X %02X %02X %02X %02X %02X %02X %02X\n", cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
	buf += strlen(buf);
	cp += 8;
    }
    for(; len > 0; len--){
	sprintf(buf, "%02X ", *cp++);
	buf += strlen(buf);
    }
    *buf = '\0';
}

static void sprint_asciistring(buf, cp, len)
    char *buf;
    u_char  *cp;
    int	    len;
{
    int	x;

    for(x = 0; x < len; x++){
	if (isprint(*cp)){
	    *buf++ = *cp++;
	} else {
	    *buf++ = '.';
	    cp++;
	}
#if 0
	if ((x % 48) == 47)
	    *buf++ = '\n';
#endif
    }
    *buf = '\0';
}


/*
  0
  < 4
  hex

  0 ""
  < 4 hex Hex: oo oo oo
  < 4     "fgh" Hex: oo oo oo
  > 4 hex Hex: oo oo oo oo oo oo oo oo
  > 4     "this is a test"

  */
static void
sprint_octet_string(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    int hex, x;
    u_char *cp;
    char *saved_hint = hint;
    char *saved_buf = buf;

    if (var->type != ASN_OCTET_STR){
	sprintf(buf, "Wrong Type (should be OCTET STRING): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }

    if (hint) {
	int repeat, width = 1;
	long value;
	char code = 'd', separ = 0, term = 0, ch;
	u_char *ecp;

	*buf = 0;
	cp = var->val.string;
	ecp = cp + var->val_len;
	while (cp < ecp) {
	    repeat = 1;
	    if (*hint) {
		if (*hint == '*') {
		    repeat = *cp++;
		    hint++;
		}
		width = 0;
		while ('0' <= *hint && *hint <= '9')
		    width = width * 10 + *hint++ - '0';
		code = *hint++;
		if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
                    && (width != 0 || (ch != 'x' && ch != 'd' && ch != 'o')))
		    separ = *hint++;
		else separ = 0;
		if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
                    && (width != 0 || (ch != 'x' && ch != 'd' && ch != 'o')))
		    term = *hint++;
		else term = 0;
		if (width == 0) width = 1;
	    }
	    while (repeat && cp < ecp) {
                value = 0;
		if (code != 'a')
		    for (x = 0; x < width; x++) value = value * 256 + *cp++;
		switch (code) {
		case 'x':
                    sprintf (buf, "%lx", value); break;
		case 'd':
                    sprintf (buf, "%ld", value); break;
		case 'o':
                    sprintf (buf, "%lo", value); break;
		case 'a':
                    for (x = 0; x < width && cp < ecp; x++)
			*buf++ = *cp++;
		    *buf = 0;
		    break;
		default:
		    sprintf(saved_buf, "(Bad hint ignored: %s) ", saved_hint);
		    sprint_octet_string(saved_buf+strlen(saved_buf),
					var, enums, NULL, NULL);
		    return;
		}
		buf += strlen (buf);
		if (cp < ecp && separ) *buf++ = separ;
		repeat--;
	    }
	    if (term && cp < ecp) *buf++ = term;
	}
	if (units) sprintf (buf, " %s", units);
        return;
    }

    hex = 0;
    for(cp = var->val.string, x = 0; x < var->val_len; x++, cp++){
	if (!(isprint(*cp) || isspace(*cp)))
	    hex = 1;
    }
    if (var->val_len == 0){
	strcpy(buf, "\"\"");
	return;
    }
    if (!hex){
	*buf++ = '"';
	sprint_asciistring(buf, var->val.string, var->val_len);
	buf += strlen(buf);
	*buf++ = '"';
	*buf = '\0';
    }
    if (hex || ((var->val_len <= 4) && !quick_print)){
	if (quick_print){
	    *buf++ = '"';
	    *buf = '\0';
	} else {
	    sprintf(buf, " Hex: ");
	    buf += strlen(buf);
	}
	sprint_hexstring(buf, var->val.string, var->val_len);
	if (quick_print){
	    buf += strlen(buf);
	    *buf++ = '"';
	    *buf = '\0';
	}
    }
    if (units) sprintf (buf, " %s", units);
}

#ifdef OPAQUE_SPECIAL_TYPES

static void
sprint_float(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
  if (var->type != ASN_OPAQUE_FLOAT) {
	sprintf(buf, "Wrong Type (should be Float): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!quick_print){
	sprintf(buf, "Opaque: Float:");
	buf += strlen(buf);
    }
    sprintf(buf, " %f", *var->val.floatVal);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

static void
sprint_double(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
  if (var->type != ASN_OPAQUE_DOUBLE) {
	sprintf(buf, "Wrong Type (should be Double): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!quick_print){
	sprintf(buf, "Opaque: Double:");
	buf += strlen(buf);
    }
    sprintf(buf, " %f", *var->val.doubleVal);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

#endif /* OPAQUE_SPECIAL_TYPES */

static void
sprint_opaque(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{

    if (var->type != ASN_OPAQUE
#ifdef OPAQUE_SPECIAL_TYPES
        && var->type != ASN_OPAQUE_COUNTER64
        && var->type != ASN_OPAQUE_U64
        && var->type != ASN_OPAQUE_I64
        && var->type != ASN_OPAQUE_FLOAT
        && var->type != ASN_OPAQUE_DOUBLE
#endif /* OPAQUE_SPECIAL_TYPES */
      ){
	sprintf(buf, "Wrong Type (should be Opaque): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
#ifdef OPAQUE_SPECIAL_TYPES
    switch(var->type) {
      case ASN_OPAQUE_COUNTER64:
      case ASN_OPAQUE_U64:
      case ASN_OPAQUE_I64:
        sprint_counter64(buf, var, enums, hint, units);
        break;
        
      case ASN_OPAQUE_FLOAT:
        sprint_float(buf, var, enums, hint, units);
        break;

      case ASN_OPAQUE_DOUBLE:
        sprint_double(buf, var, enums, hint, units);
        break;

      case ASN_OPAQUE:
#endif
    if (!quick_print){
	sprintf(buf, "OPAQUE: ");
	buf += strlen(buf);
    }
    sprint_hexstring(buf, var->val.string, var->val_len);
    buf += strlen (buf);
#ifdef OPAQUE_SPECIAL_TYPES
    }
#endif
    if (units) sprintf (buf, " %s", units);
}

static void
sprint_object_identifier(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    if (var->type != ASN_OBJECT_ID){
	sprintf(buf, "Wrong Type (should be OBJECT IDENTIFIER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!quick_print){
	sprintf(buf, "OID: ");
	buf += strlen(buf);
    }
    sprint_objid(buf, (oid *)(var->val.objid), var->val_len / sizeof(oid));
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

static void
sprint_timeticks(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    char timebuf[32];

    if (var->type != ASN_TIMETICKS){
	sprintf(buf, "Wrong Type (should be Timeticks): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!quick_print){
	sprintf(buf, "Timeticks: (%lu) ", *(u_long *)(var->val.integer));
	buf += strlen(buf);
    }
    sprintf(buf, "%s", uptimeString(*(u_long *)(var->val.integer), timebuf));
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

static void
sprint_hinted_integer (buf, val, hint, units)
    char *buf;
    long val;
    char *hint;
    char *units;
{
    char code;
    int shift, len;
    char tmp[256];
    char fmt[10];

    code = hint[0];
    if (hint [1] == '-') {
        shift = atoi (hint+2);
    }
    else shift = 0;
    fmt[0] = '%';
    fmt[1] = 'l';
    fmt[2] = code;
    fmt[3] = 0;
    sprintf (tmp, fmt, val);
    if (shift != 0) {
	len = strlen (tmp);
	if (shift <= len) {
	    tmp[len+1] = 0;
	    while (shift--) {
		tmp[len] = tmp[len-1];
		len--;
	    }
	    tmp[len] = '.';
	}
	else {
	    tmp[shift+1] = 0;
	    while (shift) {
		if (len-- > 0) tmp [shift] = tmp [len];
		else tmp[shift] = '0';
		shift--;
	    }
	    tmp[0] = '.';
	}
    }
    strcpy (buf, tmp);
}

static void
sprint_integer(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    char    *enum_string = NULL;

    if (var->type != ASN_INTEGER){
	sprintf(buf, "Wrong Type (should be INTEGER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    for (; enums; enums = enums->next)
	if (enums->value == *var->val.integer){
	    enum_string = enums->label;
	    break;
	}
    if (enum_string == NULL) {
	if (hint) sprint_hinted_integer(buf, *var->val.integer, hint, units);
	else sprintf(buf, "%ld", *var->val.integer);
    }
    else if (quick_print)
	sprintf(buf, "%s", enum_string);
    else
	sprintf(buf, "%s(%ld)", enum_string, *var->val.integer);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

static void
sprint_uinteger(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    char    *enum_string = NULL;

    if (var->type != ASN_UINTEGER){
	sprintf(buf, "Wrong Type (should be UInteger32): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    for (; enums; enums = enums->next)
	if (enums->value == *var->val.integer){
	    enum_string = enums->label;
	    break;
	}
    if (enum_string == NULL)
	sprintf(buf, "%ld", *var->val.integer);
    else if (quick_print)
	sprintf(buf, "%s", enum_string);
    else
	sprintf(buf, "%s(%ld)", enum_string, *var->val.integer);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

static void
sprint_gauge(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    if (var->type != ASN_GAUGE){
	sprintf(buf, "Wrong Type (should be Gauge): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (quick_print)
	sprintf(buf, "%lu", *var->val.integer);
    else
	sprintf(buf, "Gauge: %lu", *var->val.integer);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

static void
sprint_counter(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    if (var->type != ASN_COUNTER){
	sprintf(buf, "Wrong Type (should be Counter): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    sprintf(buf, "%lu", *var->val.integer);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

static void
sprint_networkaddress(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    int x, len;
    u_char *cp;

    if (!quick_print){
	sprintf(buf, "Network Address: ");
	buf += strlen(buf);
    }
    cp = var->val.string;    
    len = var->val_len;
    for(x = 0; x < len; x++){
	sprintf(buf, "%02X", *cp++);
	buf += strlen(buf);
	if (x < (len - 1))
	    *buf++ = ':';
    }
}

static void
sprint_ipaddress(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    u_char *ip;

    if (var->type != ASN_IPADDRESS){
	sprintf(buf, "Wrong Type (should be Ipaddress): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    ip = var->val.string;
    if (quick_print)
	sprintf(buf, "%d.%d.%d.%d",ip[0], ip[1], ip[2], ip[3]);
    else
	sprintf(buf, "IpAddress: %d.%d.%d.%d",ip[0], ip[1], ip[2], ip[3]);
}

static void
sprint_null(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    if (var->type != ASN_NULL){
	sprintf(buf, "Wrong Type (should be NULL): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    sprintf(buf, "NULL");
}

static void
sprint_bitstring(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    int len, bit;
    u_char *cp;
    char *enum_string;

    if (var->type != ASN_BIT_STR && var->type != ASN_OCTET_STR){
	sprintf(buf, "Wrong Type (should be BIT STRING): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (quick_print){
	*buf++ = '"';
	*buf = '\0';
    } else {
	sprintf(buf, "BIT_STRING: ");
	buf += strlen(buf);
    }
    sprint_hexstring(buf, var->val.bitstring, var->val_len);
    buf += strlen(buf);

    if (quick_print){
	buf += strlen(buf);
	*buf++ = '"';
	*buf = '\0';
    } else {
	cp = var->val.bitstring + 1;
	for(len = 0; len < var->val_len - 1; len++){
	    for(bit = 0; bit < 8; bit++){
		if (*cp & (0x80 >> bit)){
		    enum_string = NULL;
		    for (; enums; enums = enums->next)
			if (enums->value == (len * 8) + bit){
			    enum_string = enums->label;
			    break;
			}
		    if (enum_string == NULL)
			sprintf(buf, "%d ", (len * 8) + bit);
		    else
			sprintf(buf, "%s(%d) ", enum_string, (len * 8) + bit);
		    buf += strlen(buf);
		}
	    }
	}
	cp ++;	    
    }
}

static void
sprint_nsapaddress(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    if (var->type != ASN_NSAP){
	sprintf(buf, "Wrong Type (should be NsapAddress): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!quick_print){
	sprintf(buf, "NsapAddress: ");
	buf += strlen(buf);
    }
    sprint_hexstring(buf, var->val.string, var->val_len);
}

static void
sprint_counter64(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
  if (var->type != ASN_COUNTER64
#ifdef OPAQUE_SPECIAL_TYPES
      && var->type != ASN_OPAQUE_COUNTER64
      && var->type != ASN_OPAQUE_I64
      && var->type != ASN_OPAQUE_U64
#endif
    ){
	sprintf(buf, "Wrong Type (should be Counter64): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
/* XXX */
    if (!quick_print){
#ifdef OPAQUE_SPECIAL_TYPES
      if (var->type != ASN_COUNTER64) {
	sprintf(buf, "Opaque: ");
	buf += strlen(buf);
      }
#endif
#ifdef OPAQUE_SPECIAL_TYPES
        switch(var->type) {
          case ASN_OPAQUE_U64:
            sprintf(buf, "UInt64: ");
            break;
          case ASN_OPAQUE_I64:
            sprintf(buf, "Int64: ");
            break;
          case ASN_COUNTER64:
          case ASN_OPAQUE_COUNTER64:
#endif
            sprintf(buf, "Counter64: ");
#ifdef OPAQUE_SPECIAL_TYPES
        }
#endif
	buf += strlen(buf);
    }
#ifdef OPAQUE_SPECIAL_TYPES
    if (var->type == ASN_OPAQUE_I64)
      sprintf(buf, printI64(var->val.counter64));
    else
#endif
      sprintf(buf, printU64(var->val.counter64));
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

static void
sprint_unknowntype(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
/*    sprintf(buf, "Variable has bad type"); */
    sprint_by_type(buf, var, NULL, NULL, NULL);
}

static void
sprint_badtype(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    sprintf(buf, "Variable has bad type");
}

static void
sprint_by_type(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{
    switch (var->type){
	case ASN_INTEGER:
	    sprint_integer(buf, var, enums, hint, units);
	    break;
	case ASN_OCTET_STR:
	    sprint_octet_string(buf, var, enums, hint, units);
	    break;
	case ASN_OPAQUE:
	    sprint_opaque(buf, var, enums, hint, units);
	    break;
	case ASN_OBJECT_ID:
	    sprint_object_identifier(buf, var, enums, hint, units);
	    break;
	case ASN_TIMETICKS:
	    sprint_timeticks(buf, var, enums, hint, units);
	    break;
	case ASN_GAUGE:
	    sprint_gauge(buf, var, enums, hint, units);
	    break;
	case ASN_COUNTER:
	    sprint_counter(buf, var, enums, hint, units);
	    break;
	case ASN_IPADDRESS:
	    sprint_ipaddress(buf, var, enums, hint, units);
	    break;
	case ASN_NULL:
	    sprint_null(buf, var, enums, hint, units);
	    break;
	case ASN_UINTEGER:
	    sprint_uinteger(buf, var, enums, hint, units);
	    break;
	case ASN_COUNTER64:
#ifdef OPAQUE_SPECIAL_TYPES
	case ASN_OPAQUE_U64:
	case ASN_OPAQUE_I64:
	case ASN_OPAQUE_COUNTER64:
#endif /* OPAQUE_SPECIAL_TYPES */
	    sprint_counter64(buf, var, enums, hint, units);
	    break;
#ifdef OPAQUE_SPECIAL_TYPES
	case ASN_OPAQUE_FLOAT:
	    sprint_float(buf, var, enums, hint, units);
	    break;
	case ASN_OPAQUE_DOUBLE:
	    sprint_double(buf, var, enums, hint, units);
	    break;
#endif /* OPAQUE_SPECIAL_TYPES */
	default:
            DEBUGP("bad type: %d\n", var->type);
	    sprint_badtype(buf, var, enums, hint, units);
	    break;
    }
}


oid RFC1213_MIB[] = { 1, 3, 6, 1, 2, 1 };
unsigned char RFC1213_MIB_text[] = ".iso.org.dod.internet.mgmt.mib-2";
unsigned char EXPERIMENTAL_MIB_text[] = ".iso.org.dod.internet.experimental";
unsigned char PRIVATE_MIB_text[] = ".iso.org.dod.internet.private";
unsigned char PARTY_MIB_text[] = ".iso.org.dod.internet.snmpParties";
unsigned char SECRETS_MIB_text[] = ".iso.org.dod.internet.snmpSecrets";
extern struct tree *tree_head;
struct tree *Mib;             /* Backwards compatibility */

static char Standard_Prefix[] = ".1.3.6.1.2.1.";
static char *Prefix;


struct tree *get_tree_head __P((void))
{
   return(tree_head);
}

void
init_mib __P((void))
{
    char *prefix;
    char  *env_var, *entry;

    if (Mib) return;

	/* Initialise the MIB directory/ies */

    env_var = getenv("MIBDIRS");
    if ( env_var == NULL ) {
        env_var = strdup(DEFAULT_MIBDIRS);
    } else if ( *env_var == '+' ) {
      entry = (char *)malloc(strlen(DEFAULT_MIBDIRS)+strlen(env_var)+2);
      sprintf(entry, "%s%c%s", DEFAULT_MIBDIRS, ENV_SEPARATOR_CHAR, env_var+1);
      env_var = entry;
    }
    else env_var = strdup(env_var);
    entry = strtok( env_var, ENV_SEPARATOR );
    while ( entry ) {
        add_mibdir(entry);
        entry = strtok( NULL, ENV_SEPARATOR);
    }
    free(env_var);

    init_mib_internals();

	/* Read in any modules or mibs requested */

    env_var = getenv("MIBS");
    if ( env_var == NULL ) {
        env_var = DEFAULT_MIBS;
    }
    if (strcmp (env_var, "ALL") == 0) {
	read_all_mibs();
    }
    else {
	if ( *env_var == '+' ) {
	    entry = (char *)malloc(strlen(DEFAULT_MIBS)+strlen(env_var)+2);
	    sprintf(entry, "%s%c%s", DEFAULT_MIBS, ENV_SEPARATOR_CHAR, env_var+1);
	    env_var = entry;
	}
	else env_var = strdup(env_var);
	entry = strtok( env_var, ENV_SEPARATOR );
	while ( entry ) {
	    read_module(entry);
	    entry = strtok( NULL, ENV_SEPARATOR);
	}
	adopt_orphans();
	free(env_var);
    }

    env_var = getenv("MIBFILES");
    if ( env_var == NULL ) {
      env_var = getenv("MIBFILE");  /* backwards compatibility */
#ifdef DEFAULT_MIBFILES
      if ( env_var == NULL ) {
        env_var = strdup(DEFAULT_MIBFILES);
      }
#endif
    }
#ifdef DEFAULT_MIBFILES
    else if ( *env_var == '+') {
      entry = (char *)malloc(strlen(DEFAULT_MIBFILES)+strlen(env_var)+2);
      sprintf(entry, "%s%c%s", DEFAULT_MIBFILES, ENV_SEPARATOR_CHAR, env_var+1);
      env_var = entry;
    }
#endif
    else env_var = strdup(env_var);
    
    if ( env_var != NULL ) {
      entry = strtok( env_var, ENV_SEPARATOR );
      while ( entry ) {
        read_mib(entry);
        entry = strtok( NULL, ENV_SEPARATOR);
      }
    }
    free(env_var);

    prefix = getenv("PREFIX");

    if (!prefix)
        prefix = Standard_Prefix;
    if (prefix[0] == '.') prefix++;    /* get past leading dot. */
    Prefix = malloc(strlen(prefix)+2);
    strcpy(Prefix, prefix);
    if (Prefix[strlen(Prefix) - 1] != '.')
        strcat(Prefix, ".");  /* add a trailing dot in case user didn't */ 

    if (getenv("SUFFIX"))
	suffix_only = 1;

    Mib = tree_head;          /* Backwards compatibility */
}

void
print_mib (fp)
    FILE *fp;
{
    print_subtree (fp, tree_head, 0);
}

void
print_ascii_dump (fp)
    FILE *fp;
{
  fprintf(fp, "dump DEFINITIONS ::= BEGIN\n");
  print_ascii_dump_tree (fp, tree_head, 0);
  fprintf(fp, "END\n");
}

void
set_function(subtree)
    struct tree *subtree;
{
	switch(subtree->type){
	    case TYPE_OBJID:
		subtree->printer = sprint_object_identifier;
		break;
	    case TYPE_OCTETSTR:
		subtree->printer = sprint_octet_string;
		break;
	    case TYPE_INTEGER:
		subtree->printer = sprint_integer;
		break;
	    case TYPE_NETADDR:
		subtree->printer = sprint_networkaddress;
		break;
	    case TYPE_IPADDR:
		subtree->printer = sprint_ipaddress;
		break;
	    case TYPE_COUNTER:
		subtree->printer = sprint_counter;
		break;
	    case TYPE_GAUGE:
		subtree->printer = sprint_gauge;
		break;
	    case TYPE_TIMETICKS:
		subtree->printer = sprint_timeticks;
		break;
	    case TYPE_OPAQUE:
		subtree->printer = sprint_opaque;
		break;
	    case TYPE_NULL:
		subtree->printer = sprint_null;
		break;
	    case TYPE_BITSTRING:
		subtree->printer = sprint_bitstring;
		break;
	    case TYPE_NSAPADDRESS:
		subtree->printer = sprint_nsapaddress;
		break;
	    case TYPE_COUNTER64:
		subtree->printer = sprint_counter64;
		break;
	    case TYPE_UINTEGER:
		subtree->printer = sprint_uinteger;
		break;
	    case TYPE_OTHER:
	    default:
		subtree->printer = sprint_unknowntype;
		break;
	}
}

int read_objid(input, output, out_len)
    char *input;
    oid *output;
    int	*out_len;   /* number of subid's in "output" */
{
    struct tree *root = tree_head;
    oid *op = output;
    char buf[512];


    if (*input == '.')
	input++;
    else {
        strcpy(buf, Prefix);
	strcat(buf, input);
	input = buf;
    }

    if (root == NULL){
	fprintf(stderr, "Mib not initialized.  Exiting.\n");
	exit(1);
    }
    if ((*out_len =
	 parse_subtree(root, input, output, out_len)) == 0)
	return (0);
    *out_len += output - op;

    return (1);
}


static int
parse_subtree(subtree, input, output, out_len)
    struct tree *subtree;
    char *input;
    oid	*output;
    int	*out_len;   /* number of subid's */
{
    char buf[128], *to = buf;
    u_long subid = 0;
    struct tree *tp;

    /*
     * No empty strings.  Can happen if there is a trailing '.' or two '.'s
     * in a row, i.e. "..".
     */
    if ((*input == '\0') ||
	(*input == '.'))
	return (0);

    if (isdigit(*input)) {
	/*
	 * Read the number, then try to find it in the subtree.
	 */
	while (isdigit(*input)) {
	    subid *= 10;
	    subid += *input++ - '0';
	}
	for (tp = subtree; tp; tp = tp->next_peer) {
	    if (tp->subid == subid)
		goto found;
	}
	tp = NULL;
    }
    else {
	/*
	 * Read the name into a buffer.
	 */
	while ((*input != '\0') &&
	       (*input != '.')) {
	    *to++ = *input++;
	}
	*to = '\0';

	/*
	 * Find the name in the subtree;
	 */
	for (tp = subtree; tp; tp = tp->next_peer) {
	    if (strcasecmp(tp->label, buf) == 0) {
		subid = tp->subid;
		goto found;
	    }
	}

	/*
	 * If we didn't find the entry, punt...
	 */
	if (tp == NULL) {
	    fprintf(stderr, "sub-identifier not found: %s\n", buf);
	    return (0);
	}
    }

found:
    if(subid > (u_long)MAX_SUBID){
	fprintf(stderr, "sub-identifier too large: %s\n", buf);
	return (0);
    }

    if ((*out_len)-- <= 0){
	fprintf(stderr, "object identifier too long\n");
	return (0);
    }
    *output++ = subid;

    if (*input != '.')
	return (1);
    if ((*out_len =
	 parse_subtree(tp ? tp->child_list : NULL, ++input, output, out_len)) == 0)
	return (0);
    return (++*out_len);
}

char *
sprint_objid(buf, objid, objidlen)
    char *buf;
    oid	    *objid;
    int	    objidlen;	/* number of subidentifiers */
{
    char    tempbuf[2048], *cp;
    struct tree    *subtree = tree_head;

    *tempbuf = '.';	/* this is a fully qualified name */
    subtree = get_symbol(objid, objidlen, subtree, tempbuf + 1);
    if (suffix_only){
	for(cp = tempbuf; *cp; cp++)
	    ;
	while(cp >= tempbuf){
	    if (isalpha(*cp))
		break;
	    cp--;
	}
	while(cp >= tempbuf){
	    if (*cp == '.')
		break;
	    cp--;
	}
	cp++;
	if (suffix_only == 2 && cp > tempbuf) {
	    char *mod = module_name(subtree->modid);
	    int len = strlen(mod);
	    if (len >= cp-tempbuf) {
		memmove(tempbuf+len+1, cp, strlen(cp)+1);
		cp = tempbuf+len+1;
	    }
	    cp -= len+1;
	    memcpy(cp, mod, len);
	    cp[len] = ':';
	}
    }
    else if (!full_objid) {
	cp = tempbuf;
	if (strlen(tempbuf) > strlen(Prefix)
	    && !memcmp(tempbuf+1, Prefix, strlen(Prefix)-1))
            cp += strlen(Prefix) + 1;
	else if (strlen(tempbuf) > strlen(RFC1213_MIB_text)
	    && !memcmp(tempbuf, RFC1213_MIB_text, strlen(RFC1213_MIB_text)))
	    cp += sizeof(RFC1213_MIB_text);
	else if (strlen(tempbuf) > strlen(EXPERIMENTAL_MIB_text)
	    && !memcmp(tempbuf, EXPERIMENTAL_MIB_text, strlen(EXPERIMENTAL_MIB_text)))
            cp += sizeof(EXPERIMENTAL_MIB_text);
	else if (strlen(tempbuf) > strlen(PRIVATE_MIB_text)
	    && !memcmp(tempbuf, PRIVATE_MIB_text, strlen(PRIVATE_MIB_text)))
            cp += sizeof(PRIVATE_MIB_text);
	else if (strlen(tempbuf) > strlen(PARTY_MIB_text)
	    && !memcmp(tempbuf, PARTY_MIB_text, strlen(PARTY_MIB_text)))
            cp += sizeof(PARTY_MIB_text);
	else if (strlen(tempbuf) > strlen(SECRETS_MIB_text)
	    && !memcmp(tempbuf, SECRETS_MIB_text, strlen(SECRETS_MIB_text)))
            cp += sizeof(SECRETS_MIB_text);
    }
    else cp = tempbuf;
    strcpy(buf, cp);
    return buf;
}

void
print_objid(objid, objidlen)
    oid	    *objid;
    int	    objidlen;	/* number of subidentifiers */
{
    char    buf[256];

    sprint_objid(buf, objid, objidlen);
    printf("%s\n", buf);
}

void
fprint_objid(f, objid, objidlen)
    FILE    *f;
    oid	    *objid;
    int	    objidlen;	/* number of subidentifiers */
{
    char    buf[256];

    sprint_objid(buf, objid, objidlen);
    fprintf(f, "%s\n", buf);
}

void
sprint_variable(buf, objid, objidlen, variable)
    char *buf;
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    tempbuf[2048];
    struct tree    *subtree = tree_head;

    sprint_objid(buf, objid, objidlen);
    buf += strlen(buf);
    if (quick_print)
	strcat(buf, " ");
    else
	strcat(buf, " = ");
    buf += strlen(buf);

    if (variable->type == SNMP_NOSUCHOBJECT)
	sprintf(buf, "No Such Object available on this agent");
    else if (variable->type == SNMP_NOSUCHINSTANCE)
	sprintf(buf, "No Such Instance currently exists");
    else if (variable->type == SNMP_ENDOFMIBVIEW)
	sprintf(buf, "No more variables left in this MIB View");
    else {
	*tempbuf = '.';	/* this is a fully qualified name */
	subtree = get_symbol(objid, objidlen, subtree, tempbuf + 1);
	buf += strlen(buf);
	if (subtree->printer)
	    (*subtree->printer)(buf, variable, subtree->enums, subtree->hint, subtree->units);
	else {
	    sprint_by_type(buf, variable, subtree->enums, subtree->hint, subtree->units);
	}
    }
}

void
print_variable(objid, objidlen, variable)
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    buf[2048];

    sprint_variable(buf, objid, objidlen, variable);
    printf("%s\n", buf);
}

void
fprint_variable(f, objid, objidlen, variable)
    FILE    *f;
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    buf[2048];

    sprint_variable(buf, objid, objidlen, variable);
    fprintf(f, "%s\n", buf);
}

void
sprint_value(buf, objid, objidlen, variable)
    char *buf;
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    tempbuf[2048];
    struct tree    *subtree = tree_head;

    if (variable->type == SNMP_NOSUCHOBJECT)
	sprintf(buf, "No Such Object available on this agent\n");
    else if (variable->type == SNMP_NOSUCHINSTANCE)
	sprintf(buf, "No Such Instance currently exists\n");
    else if (variable->type == SNMP_ENDOFMIBVIEW)
	sprintf(buf, "No more variables left in this MIB View\n");
    else {
	subtree = get_symbol(objid, objidlen, subtree, tempbuf);
	if (subtree->printer)
	    (*subtree->printer)(buf, variable, subtree->enums, subtree->hint, subtree->units);
	else {
	    sprint_by_type(buf, variable, subtree->enums, subtree->hint, subtree->units);
	}
    }
}

void
print_value(objid, objidlen, variable)
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    tempbuf[2048];

    sprint_value(tempbuf, objid, objidlen, variable);
    printf("%s\n", tempbuf);
}

void
fprint_value(f, objid, objidlen, variable)
    FILE    *f;
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    tempbuf[2048];

    sprint_value(tempbuf, objid, objidlen, variable);
    fprintf(f, "%s\n", tempbuf);
}

struct tree *
get_symbol(objid, objidlen, subtree, buf)
    oid	    *objid;
    int	    objidlen;
    struct tree    *subtree;
    char    *buf;
{
    struct tree    *return_tree = NULL;

    for(; subtree; subtree = subtree->next_peer){
	if (*objid == subtree->subid){
	    if (!strncmp( subtree->label, ANON, ANON_LEN))
                sprintf(buf, "%lu", subtree->subid);
	    else
                strcpy(buf, subtree->label);
	    goto found;
	}
    }

    /* subtree not found */
    while(objidlen--){	/* output rest of name, uninterpreted */
	sprintf(buf, "%lu.", *objid++);
	while(*buf)
	    buf++;
    }
    *(buf - 1) = '\0'; /* remove trailing dot */
    return NULL;

found:
    if (objidlen > 1){
	while(*buf)
	    buf++;
	*buf++ = '.';
	*buf = '\0';
	return_tree = get_symbol(objid + 1, objidlen - 1, subtree->child_list,
				 buf);
    } 
    if (return_tree != NULL)
	return return_tree;
    else
	return subtree;
}

/*
 * Clone of get_symbol that doesn't take a buffer argument
 */
struct tree *
get_tree(objid, objidlen, subtree)
    oid     *objid;
    int     objidlen;
    struct tree    *subtree;
{
    struct tree    *return_tree = NULL;

    for(; subtree; subtree = subtree->next_peer){
        if (*objid == subtree->subid)
            goto found;
    }

    return NULL;

found:
    if (objidlen > 1)
        return_tree = get_tree(objid + 1, objidlen - 1, subtree->child_list);
    if (return_tree != NULL)
        return return_tree;
    else
        return subtree;
}

void
print_description(objid, objidlen)
    oid     *objid;
    int     objidlen;   /* number of subidentifiers */
{
    fprint_description(stdout, objid, objidlen);
}

void
fprint_description(f, objid, objidlen)
    FILE    *f;
    oid     *objid;
    int     objidlen;   /* number of subidentifiers */
{
    struct tree *tp = get_tree(objid, objidlen, tree_head);
    char *cp;
    char str[32];
    if (tp) {
	switch (tp->type) {
	case TYPE_OBJID:	cp = "OBJECT IDENTIFIER"; break;
	case TYPE_OCTETSTR:	cp = "OCTET STRING"; break;
	case TYPE_INTEGER:	cp = "INTEGER"; break;
	case TYPE_NETADDR:	cp = "NetworkAddress"; break;
	case TYPE_IPADDR:	cp = "IpAddress"; break;
	case TYPE_COUNTER:	cp = "Counter"; break;
	case TYPE_GAUGE:	cp = "Gauge"; break;
	case TYPE_TIMETICKS:	cp = "TimeTicks"; break;
	case TYPE_OPAQUE:	cp = "Opaque"; break;
	case TYPE_NULL:		cp = "NULL"; break;
	case TYPE_COUNTER64:	cp = "Counter64"; break;
	case TYPE_BITSTRING:	cp = "BIT STRING"; break;
	case TYPE_NSAPADDRESS:	cp = "NsapAddress"; break;
	case TYPE_UINTEGER:	cp = "UInteger32"; break;
	case 0:			cp = NULL; break;
	default:		sprintf(str,"type_%d", tp->type); cp = str;
	}
	if (cp) fprintf(f, "SYNTAX\t%s\n", cp);
	if (tp->hint) fprintf(f, "DISPLAY-HINT\t\"%s\"\n", tp->hint);
	if (tp->units) fprintf(f, "UNITS\t\"%s\"\n", tp->units);
	switch (tp->access) {
	case MIB_ACCESS_READONLY:	cp = "read-only"; break;
	case MIB_ACCESS_READWRITE:	cp = "read-write"; break;
	case MIB_ACCESS_WRITEONLY:	cp = "write-only"; break;
	case MIB_ACCESS_NOACCESS:	cp = "not-accessible"; break;
	case MIB_ACCESS_NOTIFY:	cp = "accessible-for-notify"; break;
	case MIB_ACCESS_CREATE:	cp = "read-create"; break;
	case 0:			cp = NULL; break;
	default:		sprintf(str,"access_%d", tp->access); cp = str;
	}
	if (cp) fprintf(f, "MAX-ACCESS\t%s\n", cp);
	switch (tp->status) {
	case MIB_STATUS_MANDATORY:	cp = "mandatory"; break;
	case MIB_STATUS_OPTIONAL:	cp = "optional"; break;
	case MIB_STATUS_OBSOLETE:	cp = "obsolete"; break;
	case MIB_STATUS_DEPRECATED:	cp = "deprecated"; break;
	case MIB_STATUS_CURRENT:	cp = "current"; break;
	case 0:			cp = NULL; break;
	default:		sprintf(str,"status_%d", tp->status); cp = str;
	}
	if (cp) fprintf(f, "STATUS\t%s\n", cp);
	if (tp->description) fprintf(f, "DESCRIPTION\t\"%s\"\n", tp->description);
    }
    else
        fprintf(f, "No description\n");
}

int
get_module_node(name, module, objid, objidlen)
    char *name;
    char *module;
    oid *objid;
    int *objidlen;
{
    int modid, subid;
    struct tree *tp, *tp2;
    oid newname[64], *op;
    char *cp, *cp2;

    if ( !strcmp(module, "ANY") )
        modid = -1;
    else {
	read_module(module);
        modid = which_module( module );
	if (modid == -1) return 0;
    }

		/* Isolate the first component of the name ... */
    cp = strchr( name, '.' );
    if ( cp != NULL ) {
	*cp = '\0';
	cp++;
    }
		/* ... and locate it in the tree. */
    tp = find_tree_node(name, modid);
    if (tp){
		/* Build up the object ID, working backwards,
		   starting from the end of the buffer. */
	tp2 = tp;
	for(op = newname + 63; op >= newname; op--){
	    *op = tp2->subid;
	    tp2 = tp2->parent;
	    if (tp2 == NULL)
		break;
	}
	if (newname + 64 - op > *objidlen)
	    return 0;
	*objidlen = newname + 64 - op;
	memmove(objid, op, (newname + 64 - op) * sizeof(oid));

		/* If the name requested was more than one element,
		   tag on the rest of the components */
	while ( cp != NULL ) {
	    cp2 = strchr( cp, '.' );	/* Isolate the next entry */
	    if ( cp2 != NULL ) {
		*cp2 = '\0';
		cp2++;
	    }

					/* Is it numeric ? */
	    if ( isdigit( *cp ) ) 
		subid=(atoi(cp));
	    else
		subid = -1;

					/* Search for the appropriate child */
	    if ( tp != NULL )
	        tp2 = tp->child_list;
	    while ( tp2 != NULL ) {
		if (( tp2->subid == subid ) ||
		    ( !strcasecmp( tp2->label, cp ))) {
			objid[ *objidlen ] = tp2->subid;
			(*objidlen)++;
			tp = tp2;
			break;
		}
		tp2 = tp2->next_peer;
	    }
	    if ( tp2 == NULL ) {
		if ( subid == -1 )
		    return 0;
				/* pure numeric from now on */
		objid[ *objidlen ] = subid;
		(*objidlen)++;
		tp = NULL;
	    }
	    cp = cp2;
	}
		
	return 1;
    } else {
	return 0;
    }
}


int
get_node(name, objid, objidlen)
    char *name;
    oid *objid;
    int *objidlen;
{
    char *cp;

    if (( cp=strchr(name, ':')) == NULL )
	return( get_module_node( name, "ANY", objid, objidlen ));
    else {
	char *module;
	int res;
		/*
		 *  requested name is of the form
		 *	"module:subidentifier"
		 */
	module = malloc(cp-name+1);
	memcpy(module,name,cp-name);
	module[cp-name] = 0;
	cp++;		/* cp now point to the subidentifier */

			/* 'cp' and 'name' *do* go that way round! */
	res = get_module_node( cp, module, objid, objidlen );
	free(module);
	return res;
    }
}

#ifdef testing

main(argc, argv)
     int argc;
     char *argv[];
{
    oid objid[64];
    int objidlen = sizeof (objid);
    int count;
    struct variable variable;

    init_mib();
    if (argc < 2)
	print_subtree(stdout, tree_head, 0);
    variable.type = ASN_INTEGER;
    variable.val.integer = 3;
    variable.val_len = 4;
    for (argc--; argc; argc--, argv++) {
	objidlen = sizeof (objid);
	printf("read_objid(%s) = %d\n",
	       argv[1], read_objid(argv[1], objid, &objidlen));
	for(count = 0; count < objidlen; count++)
	    printf("%d.", objid[count]);
	printf("\n");
	print_variable(objid, objidlen, &variable);
    }
}

#endif /* testing */
