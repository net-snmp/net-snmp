#include <net-snmp/net-snmp-config.h>

#include <stdio.h>
#include <sys/types.h>
#include <errno.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/snmpSTDDomain.h>

oid netsnmp_snmpSTDDomain[] = { TRANSPORT_DOMAIN_STD_IP };
static netsnmp_tdomain stdDomain;

/*
 * Return a string representing the address in data, or else the "far end"
 * address if data is NULL.  
 */

static char *
netsnmp_std_fmtaddr(netsnmp_transport *t, void *data, int len)
{
    return strdup("STDInOut");
}



/*
 * You can write something into opaque that will subsequently get passed back 
 * to your send function if you like.  For instance, you might want to
 * remember where a PDU came from, so that you can send a reply there...  
 */

static int
netsnmp_std_recv(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;

    while (rc < 0) {
        rc = read(0, buf, size);
        if (rc < 0 && errno != EINTR) {
            DEBUGMSGTL(("netsnmp_std", " read on stdin failed: %d (\"%s\")\n",
                        errno, strerror(errno)));
            break;
        }
        DEBUGMSGTL(("netsnmp_std", "read on stdin got %d bytes\n", rc));
    }

    return rc;
}



static int
netsnmp_std_send(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;

    while (rc < 0) {
        rc = write(1, buf, size);
        if (rc < 0 && errno != EINTR) {
            break;
        }
    }
    return rc;
}

static int
netsnmp_std_close(netsnmp_transport *t)
{
    /* we don't actually close anything here */
    return 0;
}



static int
netsnmp_std_accept(netsnmp_transport *t)
{
    /* nothing to do here */
    return 0;
}

/*
 * Open a STDIN/STDOUT -based transport for SNMP.
 */

netsnmp_transport *
netsnmp_std_transport(void)
{
    netsnmp_transport *t;

    t = (netsnmp_transport *) malloc(sizeof(netsnmp_transport));
    if (t == NULL) {
        return NULL;
    }
    memset(t, 0, sizeof(netsnmp_transport));

    t->domain = netsnmp_snmpSTDDomain;
    t->domain_length =
        sizeof(netsnmp_snmpSTDDomain) / sizeof(netsnmp_snmpSTDDomain[0]);

    t->sock = 0;
    t->flags = NETSNMP_TRANSPORT_FLAG_STREAM;

    /*
     * Message size is not limited by this transport (hence msgMaxSize
     * is equal to the maximum legal size of an SNMP message).  
     */

    t->msgMaxSize = 0x7fffffff;
    t->f_recv     = netsnmp_std_recv;
    t->f_send     = netsnmp_std_send;
    t->f_close    = netsnmp_std_close;
    t->f_accept   = netsnmp_std_accept;
    t->f_fmtaddr  = netsnmp_std_fmtaddr;

    return t;
}

netsnmp_transport *
netsnmp_std_create_tstring(const char *string, int local)
{
    return netsnmp_std_transport();
}

netsnmp_transport *
netsnmp_std_create_ostring(const u_char * o, size_t o_len, int local)
{
    return netsnmp_std_transport();
}

void
netsnmp_std_ctor(void)
{
    stdDomain.name = netsnmp_snmpSTDDomain;
    stdDomain.name_length = sizeof(netsnmp_snmpSTDDomain) / sizeof(oid);
    stdDomain.prefix = calloc(2, sizeof(char *));
    stdDomain.prefix[0] = "std";

    stdDomain.f_create_from_tstring = netsnmp_std_create_tstring;
    stdDomain.f_create_from_ostring = netsnmp_std_create_ostring;

    netsnmp_tdomain_register(&stdDomain);
}
