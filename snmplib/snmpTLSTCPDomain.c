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
        rc = BIO_read(tlsdata->sslbio, buf, size);
        while (rc <= 0) {
            if (rc == 0) {
                /* XXX closed connection */
                return -1;
            }
            if (!BIO_should_retry(tlsdata->sslbio)) {
                /* XXX: error */
                return -1;
            }
            rc = BIO_read(tlsdata->sslbio, buf, size);
        }

        DEBUGMSGTL(("tlstcp", "received %d decoded bytes from tls\n", rc));

#ifdef DONT_KNOW
        if (BIO_ctrl_pending(cachep->write_bio) > 0) {
            /* we have outgoing data to send; probably TLS negotation */

            u_char outbuf[65535];
            int outsize;
            int rc2;
                
            /* for memory bios, we now read from openssl's write
               buffer (ie, the packet to go out) and send it out
               the tcp port manually */
            outsize = BIO_read(cachep->write_bio, outbuf, sizeof(outbuf));
            if (outsize > 0) {
                /* should always be true. */
#if defined(XXXFIXME) && defined(linux) && defined(IP_PKTINFO)
                /* XXX: before this can work, we need to remember address we
                   received it from (addr_pair) */
                rc2 = netsnmp_tcp_sendto(cachep->sock, addr_pair->local_addr,
                                         addr_pair->if_index, addr_pair->remote_addr,
                                         outbuf, outsize);
#else
                rc2 = sendto(t->sock, outbuf, outsize, 0, &cachep->sockaddr, sizeof(struct sockaddr));
#endif /* linux && IP_PKTINFO */

                if (rc2 == -1) {
                    snmp_log(LOG_ERR, "failed to send a TLS specific packet\n");
                }
            }
        }

        if (SSL_pending(cachep->con)) {
            fprintf(stderr, "ack: got here...  pending\n");
            exit(1);
        }
#endif /* don't know */

        if (rc == -1) {
            _openssl_log_error(rc, tlsdata->ssl, "SSL_read");
            SNMP_FREE(tmStateRef);

            if (SSL_get_error(tlsdata->ssl, rc) == SSL_ERROR_WANT_READ)
                return -1; /* XXX: it's ok, but what's the right return? */
            return rc;
        }

        {
            char *str = netsnmp_tlstcp_fmtaddr(NULL, addr_pair, sizeof(netsnmp_indexed_addr_pair));
            DEBUGMSGTL(("tlstcp",
                        "recvfrom fd %d got %d bytes (from %s)\n",
                        t->sock, rc, str));
            free(str);
        }

        /* XXX: disallow NULL auth/encr algs in our implementations */
        tmStateRef->transportSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

        /* use x509 cert to do lookup to secname if DNE in cachep yet */
        if (!tlsdata->securityName) {
            if (NULL != (peer = SSL_get_peer_certificate(tlsdata->ssl))) {
                X509_NAME *subname;
                char namebuf[1024];
                
                /* we have one */
                subname = X509_get_subject_name(peer);
                X509_NAME_get_text_by_NID(subname, NID_commonName,
                                          namebuf, sizeof(namebuf));
                DEBUGMSGTL(("tlstcp", "got commonname: %s\n",
                            namebuf));
                tlsdata->securityName = strdup(namebuf);
                DEBUGMSGTL(("tlstcp", "set SecName to: %s\n",
                            tlsdata->securityName));
            } else {
                SNMP_FREE(tmStateRef);
                return -1;
            }
        }

        /* XXX: detect and throw out overflow secname sizes rather
           than truncating. */
        strncpy(tmStateRef->securityName, tlsdata->securityName,
                sizeof(tmStateRef->securityName)-1);
        tmStateRef->securityName[sizeof(tmStateRef->securityName)-1] = '\0';
        tmStateRef->securityNameLen = strlen(tmStateRef->securityName);

        *opaque = tmStateRef;
        *olength = sizeof(netsnmp_tmStateReference);

    } else {
        DEBUGMSGTL(("tlstcp", "recvfrom fd %d err %d (\"%s\")\n",
                    t->sock, errno, strerror(errno)));
    }
    return rc;
}



static int
netsnmp_tlstcp_send(netsnmp_transport *t, void *buf, int size,
		 void **opaque, int *olength)
{
    int rc = -1;
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    struct sockaddr *to = NULL;
    netsnmp_tmStateReference *tmStateRef = NULL;
    u_char outbuf[65535];
    _netsnmpTLSBaseData *tlsdata;
    
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
#ifdef NO_ADDR_PAIR_YET
    if (!tlsdata->securityName && tmStateRef && tmStateRef->securityNameLen > 0)
        tlsdata->securityName = strdup(tmStateRef->securityName);
        
        
    {
        char *str = netsnmp_tlstcp_fmtaddr(NULL, (void *) addr_pair,
                                        sizeof(netsnmp_indexed_addr_pair));
        DEBUGMSGTL(("tlstcp", "send %d bytes from %p to %s on fd %d\n",
                    size, buf, str, t->sock));
        free(str);
    }
#endif

    rc = BIO_write(tlsdata->sslbio, buf, size);
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
    struct sockaddr *farend = NULL;
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    int             newsock = -1, sockflags = 0;
    socklen_t       farendlen = sizeof(struct sockaddr_in);
    char           *str = NULL;
    BIO            *accepted_bio;
    
    if (t != NULL && t->sock >= 0) {
        _netsnmpTLSBaseData *tlsdata = (_netsnmpTLSBaseData *) t->data;

        accepted_bio = BIO_pop(tlsdata->accept_bio);
        if (!accepted_bio) {
            snmp_log(LOG_ERR, "Failed to pop an accepted bio off the bio staack\n");
            return -1;
        }

        if (BIO_do_handshake(tlsdata->accept_bio) <= 0) {
            snmp_log(LOG_ERR, "Failed initial handshake\n");
            return -1;
        }

        /* the old data was copied from the initial transport, which
           is fine.  We shouldn't use any of the pointers as is any
           longer but we need to store the new one */
        tlsdata->ssl_context = NULL;
        tlsdata->ssl = NULL;

        /* XXX: I think the sslbio is safe to read/write from */
        tlsdata->accept_bio = accepted_bio;

        DEBUGMSGTL(("netsnmp_tcp", "accept succeeded (from %s)\n", str));
        free(str);

        /* extract the socket */

        /* XXX: check that it returns something so we can free stuff? */
        return BIO_get_fd(tlsdata->accept_bio, NULL);
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
    int portbuf, rc;
    
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
    tlsdata = SNMP_MALLOC_TYPEDEF(_netsnmpTLSBaseData);
    if (NULL == tlsdata) {
        SNMP_FREE(t);
        return NULL;
    }
    t->data = tlsdata;

    if (isserver) {
        /* Is the server */
        tlsdata->isclient = 0;
        
        tlsdata->ssl_context = ctx =
            sslctx_server_setup(TLSv1_server_method());

        /* create the server's main SSL bio */
        tlsdata->sslbio = BIO_new_ssl(ctx, 0);
        if (NULL == tlsdata->sslbio) {
            SNMP_FREE(t);
            SNMP_FREE(tlsdata);
            snmp_log(LOG_ERR, "TLSTCP: Falied to create a SSL BIO\n");
            return NULL;
        }

        /* bind */
        /* & listen */
        /* this is done by creating an accept bio and then chaining
           the secure one on top of it */

        snprintf(tmpbuf, sizeof(tmpbuf), "%d", ntohs(addr->sin_port));
        DEBUGMSGTL(("tlstcp", "listening on tlstcp port %s\n", tmpbuf));
        tlsdata->accept_bio = BIO_new_accept(tmpbuf);
        if (NULL == tlsdata->accept_bio) {
            SNMP_FREE(t);
            SNMP_FREE(tlsdata);
            snmp_log(LOG_ERR, "TLSTCP: Falied to create a accept BIO\n");
            return NULL;
        }
        BIO_set_accept_bios(tlsdata->accept_bio, tlsdata->sslbio);

        /* openssl requires an initial accept */
        if (BIO_do_accept(tlsdata->accept_bio) <= 0) {
            SNMP_FREE(t);
            SNMP_FREE(tlsdata);
            snmp_log(LOG_ERR, "TLSTCP: Falied to do first accept on the TLS accept BIO\n");
            return NULL;
        }
        t->sock = BIO_get_fd(tlsdata->accept_bio, NULL);
    } else {
        /* Is the client */
        tlsdata->isclient = 1;

        /* set up the needed SSL context */
        tlsdata->ssl_context = ctx =
            sslctx_client_setup(TLSv1_client_method());

        tlsdata->sslbio = bio = BIO_new_ssl_connect(ctx);
        BIO_get_ssl(bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);


        snprintf(tmpbuf, sizeof(tmpbuf), "%s:%d", inet_ntoa(addr->sin_addr),
                 ntohs(addr->sin_port));
        BIO_set_conn_hostname(bio, tmpbuf);
        DEBUGMSGTL(("tlstcp", "connecting to tlstcp %s\n",
                    tmpbuf));

        if (rc = BIO_do_connect(bio) <= 0) {
            SNMP_FREE(tlsdata);
            SNMP_FREE(t);
            snmp_log(LOG_ERR, "failed to open connection to TLS server\n");
            snmp_log(LOG_ERR, "openssl error: %s\n",
                     _x509_get_error(rc, "foo"));
            return NULL;
        }

        if(SSL_get_verify_result(ssl) != X509_V_OK) {
            SNMP_FREE(tlsdata);
            SNMP_FREE(t);
            snmp_log(LOG_ERR, "failed to verify TLS server credentials\n");
            return NULL;
        }

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
    t->f_fmtaddr  = netsnmp_udp_fmtaddr;
    t->flags = NETSNMP_TRANSPORT_FLAG_TUNNELED;

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

    netsnmp_init_tlsbase();

    tlstcpDomain.name = netsnmpTLSTCPDomain;
    tlstcpDomain.name_length = netsnmpTLSTCPDomain_len;
    tlstcpDomain.prefix = (const char**)calloc(2, sizeof(char *));
    tlstcpDomain.prefix[0] = "tlstcp";

    tlstcpDomain.f_create_from_tstring_new = netsnmp_tlstcp_create_tstring;
    tlstcpDomain.f_create_from_ostring = netsnmp_tlstcp_create_ostring;

    netsnmp_tdomain_register(&tlstcpDomain);
}
