#include <net-snmp/net-snmp-config.h>

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
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
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/snmpTLSTCPDomain.h>
#include <net-snmp/library/snmpTCPDomain.h>
#include <net-snmp/library/system.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/snmp_openssl.h>
#include <net-snmp/library/callback.h>

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#ifndef INADDR_NONE
#define INADDR_NONE	-1
#endif

#define WE_ARE_SERVER 0
#define WE_ARE_CLIENT 1

oid             netsnmpTLSTCPDomain[] = { TRANSPORT_DOMAIN_TLS_TCP_IP };
size_t          netsnmpTLSTCPDomain_len = OID_LENGTH(netsnmpTLSTCPDomain);

static netsnmp_tdomain tlstcpDomain;

/*
 * Return a string representing the address in data, or else the "far end"
 * address if data is NULL.  
 */

static char *
netsnmp_tlstcp_fmtaddr(netsnmp_transport *t, void *data, int len)
{
    return netsnmp_ipv4_fmtaddr("TLSTCP", t, data, len);
}
/*
 * You can write something into opaque that will subsequently get passed back 
 * to your send function if you like.  For instance, you might want to
 * remember where a PDU came from, so that you can send a reply there...  
 */

static int
netsnmp_tlstcp_copy(netsnmp_transport *oldt, netsnmp_transport *newt)
{
    _netsnmpTLSBaseData *oldtlsdata = (_netsnmpTLSBaseData *) oldt->data;
    _netsnmpTLSBaseData *newtlsdata = (_netsnmpTLSBaseData *) newt->data;
    oldtlsdata->accepted_bio = NULL;
    oldtlsdata->ssl = NULL;
    newtlsdata->ssl_context = NULL;
    return 0;
}

static int
netsnmp_tlstcp_recv(netsnmp_transport *t, void *buf, int size,
                    void **opaque, int *olength)
{
    int             rc = -1;
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    struct sockaddr *from;
    netsnmp_tmStateReference *tmStateRef = NULL;
    X509            *peer;
    _netsnmpTLSBaseData *tlsdata;

    if (NULL != t && t->sock >= 0 && NULL != t->data) {
        /* create a tmStateRef cache for slow fill-in */
        tmStateRef = SNMP_MALLOC_TYPEDEF(netsnmp_tmStateReference);

        if (tmStateRef == NULL) {
            *opaque = NULL;
            *olength = 0;
            return -1;
        }

        addr_pair = &tmStateRef->addresses;
        tmStateRef->have_addresses = 1;
        from = (struct sockaddr *) &(addr_pair->remote_addr);

        /* read from the BIO */
        tlsdata = t->data;
        rc = SSL_read(tlsdata->ssl, buf, size);
        while (rc <= 0) {
            if (rc == 0) {
                /* XXX closed connection */
                DEBUGMSGTL(("tlstcp", "remote side closed connection\n"));
                /* XXX: openssl cleanup */
                SNMP_FREE(tmStateRef);
                return -1;
            }
            rc = SSL_read(tlsdata->ssl, buf, size);
        }

        DEBUGMSGTL(("tlstcp", "received %d decoded bytes from tls\n", rc));

        if (rc == -1) {
            if (SSL_get_error(tlsdata->ssl, rc) == SSL_ERROR_WANT_READ)
                return -1; /* XXX: it's ok, but what's the right return? */

            _openssl_log_error(rc, tlsdata->ssl, "SSL_read");
            SNMP_FREE(tmStateRef);

            return rc;
        }

        {
            char *str = netsnmp_tlstcp_fmtaddr(NULL, addr_pair, sizeof(netsnmp_indexed_addr_pair));
            DEBUGMSGTL(("tlstcp",
                        "recvfrom fd %d got %d bytes (from %s)\n",
                        t->sock, rc, str));
            free(str);
        }

        netsnmp_tlsbase_wrapup_recv(tmStateRef, tlsdata, opaque, olength);
    } else {
        DEBUGMSGTL(("tlstcp", "recvfrom fd %d err %d (\"%s\")\n",
                    t->sock, errno, strerror(errno)));
        DEBUGMSGTL(("tlstcp", "  tdata = %x\n", (uintptr_t)t->data));
    }
    return rc;
}



static int
netsnmp_tlstcp_send(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;
    netsnmp_tmStateReference *tmStateRef = NULL;
    _netsnmpTLSBaseData *tlsdata;
    
    DEBUGMSGTL(("tlstcp", "sending data\n"));
    if (opaque != NULL && *opaque != NULL &&
        *olength == sizeof(netsnmp_tmStateReference)) {
        tmStateRef = (netsnmp_tmStateReference *) *opaque;
    }

    if (NULL == t->data) {
        snmp_log(LOG_ERR, "netsnmp_tlstcp_send received no incoming data\n");
        return -1;
    }

    tlsdata = t->data;
    
    /* if the first packet and we have no secname, then copy the data */
    if (tlsdata->isclient &&
        !tlsdata->securityName && tmStateRef && tmStateRef->securityNameLen > 0)
        tlsdata->securityName = strdup(tmStateRef->securityName);
        
        
    rc = SSL_write(tlsdata->ssl, buf, size);
    DEBUGMSGTL(("tlstcp", "wrote %d bytes\n", size));
    if (rc < 0) {
        _openssl_log_error(rc, tlsdata->ssl, "SSL_write");
    }

    return rc;
}



static int
netsnmp_tlstcp_close(netsnmp_transport *t)
{
    /* XXX: issue a proper tls closure notification(s) */

    return netsnmp_socketbase_close(t);
}

static int
netsnmp_tlstcp_accept(netsnmp_transport *t)
{
    char           *str = NULL;
    BIO            *accepted_bio;
    int             rc;
    SSL_CTX *ctx;
    SSL     *ssl;
    
    DEBUGMSGTL(("tlstcp", "netsnmp_tlstcp_accept called\n"));
    if (t != NULL && t->sock >= 0) {
        _netsnmpTLSBaseData *tlsdata = (_netsnmpTLSBaseData *) t->data;

        rc = BIO_do_accept(tlsdata->accept_bio);

        if (rc <= 0) {
            snmp_log(LOG_ERR, "BIO_do_accept failed\n");
            _openssl_log_error(rc, NULL, "BIO_do_accept");
            /* XXX: need to close the listening connection here? */
            return -1;
        }

        tlsdata->accepted_bio = accepted_bio = BIO_pop(tlsdata->accept_bio);
        if (!accepted_bio) {
            snmp_log(LOG_ERR, "Failed to pop an accepted bio off the bio staack\n");
            /* XXX: need to close the listening connection here? */
            return -1;
        }

        /* create the OpenSSL TLS context */
        ctx = tlsdata->ssl_context;

        /* create the server's main SSL bio */
        ssl = tlsdata->ssl = SSL_new(ctx);
        if (!tlsdata->ssl) {
            snmp_log(LOG_ERR, "TLSTCP: Falied to create a SSL BIO\n");
            return -1;
        }
        
        SSL_set_bio(ssl, accepted_bio, accepted_bio);
        
        if ((rc = SSL_accept(ssl)) <= 0) {
            snmp_log(LOG_ERR, "TLSTCP: Falied SSL_accept\n");
            return -1;
        }   

#ifdef not_needed_question_mark
        SSL_set_accept_state(tlsdata->ssl);
#endif

        /* XXX: check acceptance criteria here */

        DEBUGMSGTL(("tlstcp", "accept succeeded (from %s) on sock %d\n",
                    str, t->sock));
        free(str);

        /* XXX: check that it returns something so we can free stuff? */
        return BIO_get_fd(tlsdata->accepted_bio, NULL);
    } else {
        return -1;
    }
}


/*
 * Open a TLS-based transport for SNMP.  Local is TRUE if addr is the local
 * address to bind to (i.e. this is a server-type session); otherwise addr is 
 * the remote address to send things to.  
 */

netsnmp_transport *
netsnmp_tlstcp_transport(struct sockaddr_in *addr, int isserver)
{
    netsnmp_transport *t = NULL;
    BIO *bio;
    SSL_CTX *ctx;
    SSL *ssl;
    _netsnmpTLSBaseData *tlsdata;
    char tmpbuf[128];
    int rc;
    
    if (addr == NULL || addr->sin_family != AF_INET) {
        return NULL;
    }

    /* allocate our transport structure */
    t = SNMP_MALLOC_TYPEDEF(netsnmp_transport);
    if (NULL == t) {
        return NULL;
    }
    memset(t, 0, sizeof(netsnmp_transport));

    /* allocate our TLS specific data */
    if (NULL == (tlsdata = netsnmp_tlsbase_allocate_tlsdata(t, isserver)))
        return NULL;

    t->data = tlsdata;
    t->data_length = sizeof(_netsnmpTLSBaseData);

    if (isserver) {
        /* Is the server */
        
        /* Create the socket bio */
        snprintf(tmpbuf, sizeof(tmpbuf), "%d", ntohs(addr->sin_port));
        DEBUGMSGTL(("tlstcp", "listening on tlstcp port %s\n", tmpbuf));
        tlsdata->accept_bio = BIO_new_accept(tmpbuf);
        if (NULL == tlsdata->accept_bio) {
            SNMP_FREE(t);
            SNMP_FREE(tlsdata);
            snmp_log(LOG_ERR, "TLSTCP: Falied to create a accept BIO\n");
            return NULL;
        }

        /* openssl requires an initial accept to bind() the socket */
        if (BIO_do_accept(tlsdata->accept_bio) <= 0) {
            SNMP_FREE(t);
            SNMP_FREE(tlsdata);
            snmp_log(LOG_ERR, "TLSTCP: Falied to do first accept on the TLS accept BIO\n");
            return NULL;
        }

        /* create the OpenSSL TLS context */
        tlsdata->ssl_context =
            sslctx_server_setup(TLSv1_method());

        t->sock = BIO_get_fd(tlsdata->accept_bio, NULL);
        t->flags = NETSNMP_TRANSPORT_FLAG_LISTEN;
    } else {
        /* Is the client */

        /* set up the needed SSL context */
        tlsdata->ssl_context = ctx =
            sslctx_client_setup(TLSv1_method());
        if (!ctx) {
            snmp_log(LOG_ERR, "failed to create TLS context\n");
            return NULL;
        }

        /* create the openssl ok connection string */
        snprintf(tmpbuf, sizeof(tmpbuf), "%s:%d", inet_ntoa(addr->sin_addr),
                 ntohs(addr->sin_port));
        DEBUGMSGTL(("tlstcp", "connecting to tlstcp %s\n", tmpbuf));
        bio = BIO_new_connect(tmpbuf);

        /* actually do the connection */
        if ((rc = BIO_do_connect(bio)) <= 0) {
            snmp_log(LOG_ERR, "tlstcp: failed to connect to %s\n", tmpbuf);
            _openssl_log_error(rc, NULL, "BIO_do_connect");
            /* XXX: free the bio, etc */
            SNMP_FREE(tlsdata);
            SNMP_FREE(t);
            return NULL;
        }
        ssl = tlsdata->ssl = SSL_new(ctx);
        
        SSL_set_bio(ssl, bio, bio);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
        if ((rc = SSL_connect(ssl)) <= 0) {
            snmp_log(LOG_ERR, "tlstcp: failed to ssl_connect\n");
            return NULL;
        }

#ifdef nexttime
        if(SSL_get_verify_result(ssl) != X509_V_OK) {
            SNMP_FREE(tlsdata);
            SNMP_FREE(t);
            snmp_log(LOG_ERR, "failed to verify TLS server credentials\n");
            return NULL;
        }
#endif
        
        t->sock = BIO_get_fd(bio, NULL);
        /* XXX: save state */
    }
        
    /*
     * Set Domain
     */
    t->domain = netsnmpTLSTCPDomain;                                     
    t->domain_length = netsnmpTLSTCPDomain_len;     

    /*
     * 16-bit length field, 8 byte TLS header, 20 byte IPv4 header  
     */

    t->msgMaxSize = 0xffff - 8 - 20;
    t->f_recv     = netsnmp_tlstcp_recv;
    t->f_send     = netsnmp_tlstcp_send;
    t->f_close    = netsnmp_tlstcp_close;
    t->f_accept   = netsnmp_tlstcp_accept;
    t->f_copy     = netsnmp_tlstcp_copy;
    t->f_fmtaddr  = netsnmp_tlstcp_fmtaddr;
    t->flags |= NETSNMP_TRANSPORT_FLAG_TUNNELED | NETSNMP_TRANSPORT_FLAG_STREAM;

    return t;
}

netsnmp_transport *
netsnmp_tlstcp_create_tstring(const char *str, int local,
                               const char *default_target)
{
    struct sockaddr_in addr;

    if (netsnmp_sockaddr_in2(&addr, str, default_target)) {
        return netsnmp_tlstcp_transport(&addr, local);
    } else {
        return NULL;
    }
}


netsnmp_transport *
netsnmp_tlstcp_create_ostring(const u_char * o, size_t o_len, int local)
{
    struct sockaddr_in addr;

    if (o_len == 6) {
        unsigned short porttmp = (o[4] << 8) + o[5];
        addr.sin_family = AF_INET;
        memcpy((u_char *) & (addr.sin_addr.s_addr), o, 4);
        addr.sin_port = htons(porttmp);
        return netsnmp_tlstcp_transport(&addr, local);
    }
    return NULL;
}

void
netsnmp_tlstcp_ctor(void)
{
    DEBUGMSGTL(("tlstcp", "registering TLS constructor\n"));

    /* config settings */

    tlstcpDomain.name = netsnmpTLSTCPDomain;
    tlstcpDomain.name_length = netsnmpTLSTCPDomain_len;
    tlstcpDomain.prefix = (const char**)calloc(2, sizeof(char *));
    tlstcpDomain.prefix[0] = "tlstcp";

    tlstcpDomain.f_create_from_tstring_new = netsnmp_tlstcp_create_tstring;
    tlstcpDomain.f_create_from_ostring = netsnmp_tlstcp_create_ostring;

    netsnmp_tdomain_register(&tlstcpDomain);
}
