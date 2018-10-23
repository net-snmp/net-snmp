#include <net-snmp/net-snmp-config.h>
#include <net-snmp/types.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/snmpIPBaseDomain.h>
#include <ctype.h>
#include <stdlib.h>

static int isnumber(const char *cp)
{
        while (isdigit((uint8_t)*cp))
            cp++;
        return *cp == '\0';
}

/**
 * Parse a Net-SNMP endpoint name.
 * @ep_str: Parsed endpoint name.
 * @endpoint: Endpoint specification in the format [<address>]:[<port>] or
 *   <port>.
 *
 * Only overwrite those fields of *@ep_str that have been set in
 * @endpoint. Returns 1 upon success and 0 upon failure.
 */
int netsnmp_parse_ep_str(struct netsnmp_ep_str *ep_str, const char *endpoint)
{
    char *dup, *cp, *addrstr = NULL, *portstr = NULL;
    unsigned port;

    if (!endpoint)
        return 0;

    dup = strdup(endpoint);
    if (!dup)
        return 0;

    cp = dup;
    if (isnumber(cp)) {
        portstr = cp;
    } else {
        if (*cp == '[') {
            addrstr = cp + 1;
            cp = strchr(cp, ']');
            if (cp) {
                cp[0] = '\0';
                cp++;
            } else {
                goto invalid;
            }
        } else if (*cp != ':') {
            addrstr = cp;
            cp = strrchr(cp, ':');
        }
        if (cp && *cp == ':') {
            *cp++ = '\0';
            portstr = cp;
            if (!isnumber(cp))
                goto invalid;
        } else if (cp && *cp) {
            goto invalid;
        }
    }

    if (addrstr)
        strlcpy(ep_str->addr, addrstr, sizeof(ep_str->addr));
    if (portstr) {
        port = atoi(portstr);
        if (port > 0 && port <= 0xffff)
            ep_str->port = port;
        else
            goto invalid;
    }

    free(dup);
    return 1;

invalid:
    free(dup);
    return 0;
}
