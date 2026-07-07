#include <net-snmp/net-snmp-config.h>

#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "mibgroup/util_funcs.h"
#include "pass_common.h"

static int
netsnmp_internal_asc2bin(char *p)
{
    char           *r, *q = p;
    char            c;
    int             n = 0;

    for (;;) {
        c = (char) strtol(q, &r, 16);
        if (r == q)
            break;
        *p++ = c;
        q = r;
        n++;
    }
    return n;
}

static int
netsnmp_internal_bin2asc(const unsigned char *in_buf, size_t in_len, char *out_buf, size_t out_len)
{
    const char     *end = out_buf + out_len;
    int             i, flag = 0, res;
    char           *p = out_buf;

    if (out_len == 0)
        return 0;

    for (i = 0; i < in_len; i++) {
        if (!isprint(in_buf[i])) {
            flag = 1;
            break;
        }
    }
    if (flag == 0) {
        snprintf(out_buf, out_len, "%.*s", (int)in_len, (const char *)in_buf);
        return SNMP_MIN(out_len - 1, in_len);
    }
    for (i = 0; i < in_len; i++) {
        res = snprintf(p, end - p, "%02x ", in_buf[i]);
        if (res < 0)
            break;
        if (res >= end - p)
            break;
        p += res;
    }
    /* Remove the trailing space. */
    if (p > out_buf && p[-1] == ' ')
        *--p = '\0';
    return p - out_buf;
}

int
netsnmp_internal_pass_str_to_errno(const char *buf)
{
    if (!strncasecmp(buf, "too-big", 7)) {
        /* Shouldn't happen */
        return SNMP_ERR_TOOBIG;
    } else if (!strncasecmp(buf, "no-such-name", 12)) {
        return SNMP_ERR_NOSUCHNAME;
    } else if (!strncasecmp(buf, "bad-value", 9)) {
        return SNMP_ERR_BADVALUE;
    } else if (!strncasecmp(buf, "read-only", 9)) {
        return SNMP_ERR_READONLY;
    } else if (!strncasecmp(buf, "gen-error", 9)) {
        return SNMP_ERR_GENERR;
    } else if (!strncasecmp(buf, "no-access", 9)) {
        return SNMP_ERR_NOACCESS;
    } else if (!strncasecmp(buf, "wrong-type", 10)) {
        return SNMP_ERR_WRONGTYPE;
    } else if (!strncasecmp(buf, "wrong-length", 12)) {
        return SNMP_ERR_WRONGLENGTH;
    } else if (!strncasecmp(buf, "wrong-encoding", 14)) {
        return SNMP_ERR_WRONGENCODING;
    } else if (!strncasecmp(buf, "wrong-value", 11)) {
        return SNMP_ERR_WRONGVALUE;
    } else if (!strncasecmp(buf, "no-creation", 11)) {
        return SNMP_ERR_NOCREATION;
    } else if (!strncasecmp(buf, "inconsistent-value", 18)) {
        return SNMP_ERR_INCONSISTENTVALUE;
    } else if (!strncasecmp(buf, "resource-unavailable", 20)) {
        return SNMP_ERR_RESOURCEUNAVAILABLE;
    } else if (!strncasecmp(buf, "commit-failed", 13)) {
        return SNMP_ERR_COMMITFAILED;
    } else if (!strncasecmp(buf, "undo-failed", 11)) {
        return SNMP_ERR_UNDOFAILED;
    } else if (!strncasecmp(buf, "authorization-error", 19)) {
        return SNMP_ERR_AUTHORIZATIONERROR;
    } else if (!strncasecmp(buf, "not-writable", 12)) {
        return SNMP_ERR_NOTWRITABLE;
    } else if (!strncasecmp(buf, "inconsistent-name", 17)) {
        return SNMP_ERR_INCONSISTENTNAME;
    }

    return SNMP_ERR_NOERROR;
}

unsigned char *
netsnmp_internal_pass_parse(char * buf,
                            char * buf2,
                            size_t * var_len,
                            struct variable *vp)
{
    static long     long_ret;
    static in_addr_t addr_ret;
    int             newlen;
    static oid      objid[MAX_OID_LEN];

    /*
     * buf contains the return type, and buf2 contains the data
     */
    if (!strncasecmp(buf, "string", 6)) {
        buf2[strlen(buf2) - 1] = 0; /* zap the linefeed */
        if (buf2[strlen(buf2) - 1] == '\r')
            buf2[strlen(buf2) - 1] = 0; /* zap the carriage-return */
        *var_len = strlen(buf2);
        vp->type = ASN_OCTET_STR;
        return ((unsigned char *) buf2);
    }
#ifdef NETSNMP_WITH_OPAQUE_SPECIAL_TYPES
    else if (!strncasecmp(buf, "integer64", 9)) {
        static struct counter64 c64;
        uint64_t v64 = strtoull(buf2, NULL, 10);
        c64.high = (unsigned long)(v64 >> 32);
        c64.low  = (unsigned long)(v64 & 0xffffffff);
        *var_len = sizeof(c64);
        vp->type = ASN_OPAQUE_I64;
        return ((unsigned char *) &c64);
    }
#endif
    else if (!strncasecmp(buf, "integer", 7)) {
        *var_len = sizeof(long_ret);
        long_ret = strtol(buf2, NULL, 10);
        vp->type = ASN_INTEGER;
        return ((unsigned char *) &long_ret);
    } else if (!strncasecmp(buf, "unsigned", 8)) {
        *var_len = sizeof(long_ret);
        long_ret = strtoul(buf2, NULL, 10);
        vp->type = ASN_UNSIGNED;
        return ((unsigned char *) &long_ret);
    }
    else if (!strncasecmp(buf, "counter64", 9)) {
        static struct counter64 c64;
        uint64_t v64 = strtoull(buf2, NULL, 10);
        c64.high = (unsigned long)(v64 >> 32);
        c64.low  = (unsigned long)(v64 & 0xffffffff);
        *var_len = sizeof(c64);
        vp->type = ASN_COUNTER64;
        return ((unsigned char *) &c64);
    }
    else if (!strncasecmp(buf, "counter", 7)) {
        *var_len = sizeof(long_ret);
        long_ret = strtoul(buf2, NULL, 10);
        vp->type = ASN_COUNTER;
        return ((unsigned char *) &long_ret);
    } else if (!strncasecmp(buf, "octet", 5)) {
        *var_len = netsnmp_internal_asc2bin(buf2);
        vp->type = ASN_OCTET_STR;
        return ((unsigned char *) buf2);
    } else if (!strncasecmp(buf, "opaque", 6)) {
        *var_len = netsnmp_internal_asc2bin(buf2);
        vp->type = ASN_OPAQUE;
        return ((unsigned char *) buf2);
    } else if (!strncasecmp(buf, "gauge", 5)) {
        *var_len = sizeof(long_ret);
        long_ret = strtoul(buf2, NULL, 10);
        vp->type = ASN_GAUGE;
        return ((unsigned char *) &long_ret);
    } else if (!strncasecmp(buf, "objectid", 8)) {
        newlen = parse_miboid(buf2, objid);
        *var_len = newlen * sizeof(oid);
        vp->type = ASN_OBJECT_ID;
        return ((unsigned char *) objid);
    } else if (!strncasecmp(buf, "timetick", 8)) {
        *var_len = sizeof(long_ret);
        long_ret = strtoul(buf2, NULL, 10);
        vp->type = ASN_TIMETICKS;
        return ((unsigned char *) &long_ret);
    } else if (!strncasecmp(buf, "ipaddress", 9)) {
        newlen = parse_miboid(buf2, objid);
        if (newlen != 4) {
            snmp_log(LOG_ERR, "invalid ipaddress returned:  %s\n", buf2);
            *var_len = 0;
            return (NULL);
        }
        addr_ret =
            (objid[0] << (8 * 3)) + (objid[1] << (8 * 2)) +
            (objid[2] << 8) + objid[3];
        addr_ret = htonl(addr_ret);
        *var_len = sizeof(addr_ret);
        vp->type = ASN_IPADDRESS;
        return ((unsigned char *) &addr_ret);
    }
    *var_len = 0;
    return (NULL);
}

void
netsnmp_internal_pass_set_format(char *buf,
                                 const u_char *var_val,
                                 u_char var_val_type,
                                 size_t var_val_len)
{
    char            buf2[SNMP_MAXBUF];
    long            tmp;
    unsigned long   utmp;

    switch (var_val_type) {
    case ASN_INTEGER:
    case ASN_COUNTER:
    case ASN_GAUGE:
    case ASN_TIMETICKS:
        tmp = *((const long *) var_val);
        switch (var_val_type) {
        case ASN_INTEGER:
            sprintf(buf, "integer %d", (int) tmp);
            break;
        case ASN_COUNTER:
            sprintf(buf, "counter %d", (int) tmp);
            break;
        case ASN_GAUGE:
            sprintf(buf, "gauge %d", (int) tmp);
            break;
        case ASN_TIMETICKS:
            sprintf(buf, "timeticks %d", (int) tmp);
            break;
        }
        break;
    case ASN_IPADDRESS:
        utmp = *((const u_long *) var_val);
        utmp = ntohl(utmp);
        sprintf(buf, "ipaddress %d.%d.%d.%d",
                (int) ((utmp & 0xff000000) >> (8 * 3)),
                (int) ((utmp & 0xff0000) >> (8 * 2)),
                (int) ((utmp & 0xff00) >> (8)),
                (int) ((utmp & 0xff)));
        break;
    case ASN_OCTET_STR:
        if (var_val_len == 0)
            sprintf(buf, "string \"\"");
        else if (netsnmp_internal_bin2asc(var_val, var_val_len, buf2, sizeof(buf2)) ==
                 var_val_len)
            snprintf(buf, SNMP_MAXBUF, "string \"%s\"", buf2);
        else
            snprintf(buf, SNMP_MAXBUF, "octet \"%s\"", buf2);
        break;
    case ASN_OBJECT_ID:
        snprint_mib_oid(buf2, sizeof(buf2), (const oid *) var_val,
                       var_val_len/sizeof(oid));
        snprintf(buf, SNMP_MAXBUF, "objectid \"%s\"", buf2);
        buf[ SNMP_MAXBUF-1 ] = 0;
        break;
    }
}
