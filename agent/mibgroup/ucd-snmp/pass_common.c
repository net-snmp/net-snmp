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
netsnmp_internal_bin2asc(char *p, size_t n)
{
    int             i, flag = 0;
    char            buffer[SNMP_MAXBUF];

    /* prevent buffer overflow */
    if ((int)n > (sizeof(buffer) - 1))
        n = sizeof(buffer) - 1;

    for (i = 0; i < (int) n; i++) {
        buffer[i] = p[i];
        if (!isprint((unsigned char) (p[i])))
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
    } else if (!strncasecmp(buf, "integer", 7)) {
        *var_len = sizeof(long_ret);
        long_ret = strtol(buf2, NULL, 10);
        vp->type = ASN_INTEGER;
        return ((unsigned char *) &long_ret);
    } else if (!strncasecmp(buf, "unsigned", 8)) {
        *var_len = sizeof(long_ret);
        long_ret = strtoul(buf2, NULL, 10);
        vp->type = ASN_UNSIGNED;
        return ((unsigned char *) &long_ret);
    } else if (!strncasecmp(buf, "counter", 7)) {
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
            sprintf(buf, "integer %d\n", (int) tmp);
            break;
        case ASN_COUNTER:
            sprintf(buf, "counter %d\n", (int) tmp);
            break;
        case ASN_GAUGE:
            sprintf(buf, "gauge %d\n", (int) tmp);
            break;
        case ASN_TIMETICKS:
            sprintf(buf, "timeticks %d\n", (int) tmp);
            break;
        }
        break;
    case ASN_IPADDRESS:
        utmp = *((const u_long *) var_val);
        utmp = ntohl(utmp);
        sprintf(buf, "ipaddress %d.%d.%d.%d\n",
                (int) ((utmp & 0xff000000) >> (8 * 3)),
                (int) ((utmp & 0xff0000) >> (8 * 2)),
                (int) ((utmp & 0xff00) >> (8)),
                (int) ((utmp & 0xff)));
        break;
    case ASN_OCTET_STR:
        memcpy(buf2, var_val, var_val_len);
        if (var_val_len == 0)
            sprintf(buf, "string \"\"\n");
        else if (netsnmp_internal_bin2asc(buf2, var_val_len) ==
                 (int) var_val_len)
            snprintf(buf, SNMP_MAXBUF, "string \"%s\"\n", buf2);
        else
            snprintf(buf, SNMP_MAXBUF, "octet \"%s\"\n", buf2);
        buf[ SNMP_MAXBUF-1 ] = 0;
        break;
    case ASN_OBJECT_ID:
        sprint_mib_oid(buf2, (const oid *) var_val, var_val_len/sizeof(oid));
        snprintf(buf, SNMP_MAXBUF, "objectid \"%s\"\n", buf2);
        buf[ SNMP_MAXBUF-1 ] = 0;
        break;
    }
}
