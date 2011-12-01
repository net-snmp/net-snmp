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
