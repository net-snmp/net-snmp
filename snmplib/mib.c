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
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if STDC_HEADERS
#include <string.h>
#include <stdlib.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "mib.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "parse.h"

static void sprint_by_type __P((char *, struct variable_list *, struct enum_list *, char *, char *));
static parse_subtree __P((struct tree *, char *, oid *, int *));
static void set_functions __P((struct tree *));
static int lc_cmp __P((char *, char *));
char *sprint_objid __P((char *, oid *, int));
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
  
struct tree *get_symbol __P((oid *, int, struct tree *, char *));
struct tree *get_tree __P((oid *, int, struct tree *));
char *get_description __P((oid *, int));
struct tree *find_node __P((char *, struct tree *));

static int quick_print = 0;

void snmp_set_quick_print(val)
    int val;
{
    quick_print = val;
}

int snmp_get_quick_print __P((void))
{
    return quick_print;
}

static char *
uptimeString(timeticks, buf)
    register u_long timeticks;
    char *buf;
{
    int	seconds, minutes, hours, days;

    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (quick_print)
	sprintf(buf, "%d:%d:%02d:%02d", days, hours, minutes, seconds);
    else {
	if (days == 0){
	    sprintf(buf, "%d:%02d:%02d", hours, minutes, seconds);
	} else if (days == 1) {
	    sprintf(buf, "%d day, %d:%02d:%02d", days,hours,minutes,seconds);
	} else {
	    sprintf(buf, "%d days, %d:%02d:%02d", days,hours,minutes,seconds);
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

#ifdef UNUSED
int
read_rawobjid(input, output, out_len)
    char *input;
    oid *output;
    int	*out_len;
{
    char    buf[12], *cp;
    oid	    *op = output;
    u_long  subid;

    while(*input != '\0'){
	if (!isdigit(*input))
	    break;
	cp = buf;
	while(isdigit(*input))
	    *cp++ = *input++;
	*cp = '\0';
	subid = atoi(buf);
	if(subid > MAX_SUBID){
	    fprintf(stderr, "sub-identifier too large: %s\n", buf);
	    return 0;
	}
	if((*out_len)-- <= 0){
	    fprintf(stderr, "object identifier too long\n");
	    return 0;
	}
	*op++ = subid;
	if(*input++ != '.')
	    break;
    }
    *out_len = op - output;
    if (*out_len == 0)
	return 0;
    return 1;
}

#endif /* UNUSED */

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

    if (var->type != ASN_OCTET_STR){
	sprintf(buf, "Wrong Type (should be OCTET STRING): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }

    if (hint) {
	int repeat, width = 1;
	long value;
	char code = 'd', separ = 0, term = 0;
	u_char *ecp;
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
		if (*hint && *hint != '*' && (*hint < '0' || *hint > '9'))
		    separ = *hint++;
		else separ = 0;
		if (*hint && *hint != '*' && (*hint < '0' || *hint > '9'))
		    term = *hint++;
		else term = 0;
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

static void
sprint_opaque(buf, var, enums, hint, units)
    char *buf;
    struct variable_list *var;
    struct enum_list	    *enums;
    char *hint;
    char *units;
{

    if (var->type != OPAQUE){
	sprintf(buf, "Wrong Type (should be Opaque): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!quick_print){
	sprintf(buf, "OPAQUE: ");
	buf += strlen(buf);
    }
    sprint_hexstring(buf, var->val.string, var->val_len);
    buf += strlen (buf);
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

    if (var->type != TIMETICKS){
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
    strcat (buf, tmp);
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

    if (var->type != UINTEGER){
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
    if (var->type != GAUGE){
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
    if (var->type != COUNTER){
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

    if (var->type != IPADDRESS){
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

    if (var->type != ASN_BIT_STR){
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
    if (var->type != NSAP){
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
    if (var->type != COUNTER64){
	sprintf(buf, "Wrong Type (should be Counter64): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
/* XXX */
    if (!quick_print){
	sprintf(buf, "Counter64: ");
	buf += strlen(buf);
    }
    sprint_hexstring(buf, (char *)&var->val.counter64->high,
		     sizeof(var->val.counter64->high));
    buf += strlen(buf);
    sprint_hexstring(buf, (char *)&var->val.counter64->low,
		     sizeof(var->val.counter64->low));
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
	case OPAQUE:
	    sprint_opaque(buf, var, enums, hint, units);
	    break;
	case ASN_OBJECT_ID:
	    sprint_object_identifier(buf, var, enums, hint, units);
	    break;
	case TIMETICKS:
	    sprint_timeticks(buf, var, enums, hint, units);
	    break;
	case GAUGE:
	    sprint_gauge(buf, var, enums, hint, units);
	    break;
	case COUNTER:
	    sprint_counter(buf, var, enums, hint, units);
	    break;
	case IPADDRESS:
	    sprint_ipaddress(buf, var, enums, hint, units);
	    break;
	case ASN_NULL:
	    sprint_null(buf, var, enums, hint, units);
	    break;
	case UINTEGER:
	    sprint_uinteger(buf, var, enums, hint, units);
	    break;
	default:
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
struct tree *Mib;

char Standard_Prefix[] = ".1.3.6.1.2.1.";
char Prefix[128];
int Suffix;

void
init_mib __P((void))
{
    char *file, *prefix, mibpath[300];

    Mib = 0;
    file = getenv("MIBFILE");
    if (file)
	Mib = read_mib(file);
    if (!Mib) {
      sprintf(mibpath,"%s/mib.txt",SNMPLIBPATH);
      Mib = read_mib(mibpath);
    }
    if (!Mib)
	Mib = read_mib("mib.txt");
    if (!Mib)
	Mib = read_mib("/usr/local/lib/mib.txt");
    if (!Mib)
	Mib = read_mib("/etc/mib.txt");
    if (!Mib){
	fprintf(stderr, "Couldn't find mib file\n");
	exit(2);
    }
    prefix = getenv("PREFIX");
    if (!prefix)
        prefix = Standard_Prefix;
    if (prefix[strlen(prefix) - 1] != '.')
        strcat(prefix, ".");  /* add a trailing dot in case user didn't */ 
    prefix++;    /* get past leading dot. */
    strcpy(Prefix, prefix);

    if (getenv("SUFFIX"))
	Suffix = TRUE;
    else
	Suffix = FALSE;
    set_functions(Mib);
}

void
print_mib (fp)
    FILE *fp;
{
    print_subtree (fp, Mib, 0);
}

static void
set_functions(subtree)
    struct tree *subtree;
{
    for(; subtree; subtree = subtree->next_peer){
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
	set_functions(subtree->child_list);
    }
}

#ifdef testing
int snmp_dump_packet = 0;
int quick_print = 0;

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
	print_subtree(stdout, Mib, 0);
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

#endif testing

int read_objid(input, output, out_len)
    char *input;
    oid *output;
    int	*out_len;   /* number of subid's in "output" */
{
    struct tree *root = Mib;
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

#ifdef notdef
int read_objid(input, output, out_len)
    char *input;
    oid *output;
    int	*out_len;   /* number of subid's in "output" */
{
    struct tree *root = Mib;
    oid *op = output;
    int i;

    if (*input == '.')
	input++;
    else {
	root = find_rfc1213_mib(root);
	for (i = 0; i < sizeof (RFC1213_MIB)/sizeof(oid); i++) {
	    if ((*out_len)-- > 0)
		*output++ = RFC1213_MIB[i];
	    else {
		fprintf(stderr, "object identifier too long\n");
		return (0);
	    }
	}
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
#endif

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
	    if (lc_cmp(tp->label, buf) == 0) {
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
    struct tree    *subtree = Mib;

    *tempbuf = '.';	/* this is a fully qualified name */
    get_symbol(objid, objidlen, subtree, tempbuf + 1);
    if (Suffix){
	for(cp =tempbuf; *cp; cp++)
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
	if (cp < tempbuf)
	    cp = tempbuf;

    } else {
	cp = tempbuf;
	if (((int) (strlen(tempbuf)) > ((int) strlen((char *)RFC1213_MIB_text)))
	    && !memcmp(tempbuf, (char *)RFC1213_MIB_text,
		     strlen((char *)RFC1213_MIB_text))){
	    cp += sizeof(RFC1213_MIB_text);
	}
	if (((int) (strlen(tempbuf))) >
                   ((int)strlen((char *)EXPERIMENTAL_MIB_text))
	    && !memcmp(tempbuf, (char *) EXPERIMENTAL_MIB_text,
		     strlen((char *)EXPERIMENTAL_MIB_text))){
            cp += sizeof(EXPERIMENTAL_MIB_text);
	}
	if (((int)(strlen(tempbuf))) > ((int)strlen((char *)PRIVATE_MIB_text))
	    && !memcmp(tempbuf, (char *) PRIVATE_MIB_text,
		     strlen((char *)PRIVATE_MIB_text))){
            cp += sizeof(PRIVATE_MIB_text);
	}
	if (((int)(strlen(tempbuf)) > ((int)strlen((char *)PARTY_MIB_text)))
	    && !memcmp(tempbuf, (char *) PARTY_MIB_text,
		     strlen((char *)PARTY_MIB_text))){
            cp += sizeof(PARTY_MIB_text);
	}
	if (((int)(strlen(tempbuf)) > ((int)strlen((char *)SECRETS_MIB_text)))
	    && !memcmp(tempbuf, (char *) SECRETS_MIB_text,
		     strlen((char *)SECRETS_MIB_text))){
            cp += sizeof(SECRETS_MIB_text);
	}
    }
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
sprint_variable(buf, objid, objidlen, variable)
    char *buf;
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    tempbuf[2048];
    struct tree    *subtree = Mib;

    sprint_objid(buf, objid, objidlen);
    buf += strlen(buf);
    if (quick_print)
	strcat(buf, " ");
    else
	strcat(buf, " = ");
    buf += strlen(buf);

    if (variable->type == SNMP_NOSUCHOBJECT)
	sprintf(buf, "No Such Object available on this agent\n");
    else if (variable->type == SNMP_NOSUCHINSTANCE)
	sprintf(buf, "No Such Instance currently exists\n");
    else if (variable->type == SNMP_ENDOFMIBVIEW)
	sprintf(buf, "No more variables left in this MIB View\n");
    else {
	*tempbuf = '.';	/* this is a fully qualified name */
	subtree = get_symbol(objid, objidlen, subtree, tempbuf + 1);
	buf += strlen(buf);
	if (subtree->printer)
	    (*subtree->printer)(buf, variable, subtree->enums, subtree->hint, subtree->units);
	else {
	    sprint_by_type(buf, variable, subtree->enums, subtree->hint, subtree->units);
	}
	strcat(buf, "\n");
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
    printf("%s", buf);
}

void
sprint_value(buf, objid, objidlen, variable)
    char *buf;
    oid     *objid;
    int	    objidlen;
    struct  variable_list *variable;
{
    char    tempbuf[2048];
    struct tree    *subtree = Mib;

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


static int
lc_cmp(s1, s2)
    char *s1, *s2;
{
    char c1, c2;

    while(*s1 && *s2){
	if (isupper(*s1))
	    c1 = tolower(*s1);
	else
	    c1 = *s1;
	if (isupper(*s2))
	    c2 = tolower(*s2);
	else
	    c2 = *s2;
	if (c1 != c2)
	    return ((c1 - c2) > 0 ? 1 : -1);
	s1++;
	s2++;
    }

    if (*s1)
	return -1;
    if (*s2)
	return 1;
    return 0;
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

char *get_description(objid, objidlen)
    oid     *objid;
    int     objidlen;   /* number of subidentifiers */
{
    struct tree    *subtree = Mib;

    subtree = get_tree(objid, objidlen, subtree);
    if (subtree)
        return (subtree->description);
    else
        return NULL;
}

void
print_description(objid, objidlen)
    oid     *objid;
    int     objidlen;   /* number of subidentifiers */
{
    char *desc = get_description(objid, objidlen);

    if (desc && desc[0] != '\0')
        printf("Description: \"%s\"\n", desc);
    else
        printf("No description\n");
}

struct tree *
find_node(name, subtree)
    char *name;
    struct tree *subtree;
{
    struct tree *tp, *ret;

    for(tp = subtree; tp; tp = tp->next_peer){
	if (!strcasecmp(name, tp->label))
	    return tp;
	ret = find_node(name, tp->child_list);
	if (ret)
	    return ret;
    }
    return 0;
}


int
get_node(name, objid, objidlen)
    char *name;
    oid *objid;
    int *objidlen;
{
    struct tree *tp;
    oid newname[64], *op;

    tp = find_node(name, Mib);
    if (tp){
	for(op = newname + 63; op >= newname; op--){
	    *op = tp->subid;
	    tp = tp->parent;
	    if (tp == NULL)
		break;
	}
	if (newname + 64 - op > *objidlen)
	    return 0;
	*objidlen = newname + 64 - op;
	memmove(objid, op, (newname + 64 - op) * sizeof(oid));
	return 1;
    } else {
	return 0;
    }

    
}
