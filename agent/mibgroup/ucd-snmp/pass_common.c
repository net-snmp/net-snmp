#include <net-snmp/net-snmp-config.h>

#include <ctype.h>
#if HAVE_STDDEF_H
#include <stddef.h>
#endif
#include <stdio.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "pass_common.h"

#include <net-snmp/net-snmp-includes.h>

int
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

int
netsnmp_internal_bin2asc(char *p, size_t n)
{
    int             i, flag = 0;
    char            buffer[SNMP_MAXBUF];

    /* prevent buffer overflow */
    if ((int)n > (sizeof(buffer) - 1))
        n = sizeof(buffer) - 1;

    for (i = 0; i < (int) n; i++) {
        buffer[i] = p[i];
        if (!isprint(p[i]))
            flag = 1;
    }
    if (flag == 0) {
        p[n] = 0;
        return n;
    }
    for (i = 0; i < (int) n; i++) {
        sprintf(p, "%02x ", (unsigned char) (buffer[i] & 0xff));
        p += 3;
    }
    *--p = 0;
    return 3 * n - 1;
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
