/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * See the following web pages for useful documentation on this transport:
 * http://www.net-snmp.org/wiki/index.php/TUT:Using_TLS
 * http://www.net-snmp.org/wiki/index.php/Using_DTLS
 */
#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-features.h>

netsnmp_feature_require(cert_util);

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>

#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "../memcheck.h"

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>
#include <net-snmp/library/snmp_assert.h>
#include <net-snmp/library/snmp_impl.h>
#include <net-snmp/library/snmpIPv4BaseDomain.h>
#include <net-snmp/library/snmpSocketBaseDomain.h>
#include <net-snmp/library/snmpTLSBaseDomain.h>
#include <net-snmp/library/snmpTLSTCPDomain.h>
#include <net-snmp/library/snmpTCPDomain.h>
#ifdef NETSNMP_TRANSPORT_TCPIPV6_DOMAIN
#include <net-snmp/library/snmpTCPIPv6Domain.h>
#include <net-snmp/library/snmpIPv6BaseDomain.h>
#endif
#include <net-snmp/library/system.h>
#include <net-snmp/library/tools.h>
#include <net-snmp/library/cert_util.h>
#include <net-snmp/library/snmp_openssl.h>
#include <net-snmp/library/callback.h>
#include "snmpIPBaseDomain.h"
#include "snmpTLSBaseDomain.h"

static void
_tlstcp_format_addr_string(_netsnmpTLSBaseData *tlsdata);

#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#ifndef INADDR_NONE
#define INADDR_NONE	-1
#endif

#define WE_ARE_SERVER 0
#define WE_ARE_CLIENT 1

const oid       netsnmpTLSTCPDomain[] = { TRANSPORT_DOMAIN_TLS_TCP_IP };
size_t          netsnmpTLSTCPDomain_len = OID_LENGTH(netsnmpTLSTCPDomain);

static netsnmp_tdomain tlstcpDomain;

/*
 * Return a string representing the address in data, or else the "far end"
 * address if data is NULL.
 */

static char *
netsnmp_tlstcp_fmtaddr(netsnmp_transport *t, const void *data, int len)
{
    if (t && !data) {
        data = t->data;
        len = t->data_length;
    }

    switch (data ? len : 0) {
    case sizeof(netsnmp_indexed_addr_pair):
#ifdef NETSNMP_TRANSPORT_TCPIPV6_DOMAIN
        if (t->base_transport &&
            t->base_transport->domain == netsnmp_TCPIPv6Domain)
            return netsnmp_ipv6_fmtaddr("TLSTCP", t, data, len);
#endif
        return netsnmp_ipv4_fmtaddr("TLSTCP", t, data, len);
    case sizeof(netsnmp_tmStateReference): {
        const netsnmp_tmStateReference *r = data;
        const netsnmp_indexed_addr_pair *p = &r->addresses;

#ifdef NETSNMP_TRANSPORT_TCPIPV6_DOMAIN
        if (t->base_transport &&
            t->base_transport->domain == netsnmp_TCPIPv6Domain)
            return netsnmp_ipv6_fmtaddr("TLSTCP", t, p, sizeof(*p));
#endif
        return netsnmp_ipv4_fmtaddr("TLSTCP", t, p, sizeof(*p));
    }
    case sizeof(_netsnmpTLSBaseData): {
        const _netsnmpTLSBaseData *b = data;
        char *buf;

        if (asprintf(&buf, "TLSTCP: %s", b->addr_string) < 0)
            buf = NULL;
        return buf;
    }
    case 0:
        return strdup("TLSTCP: unknown");
    default: {
        char *buf;

        if (asprintf(&buf, "TLSTCP: len %d", len) < 0)
            buf = NULL;
        return buf;
    }
    }
}

static void
_tlstcp_sync_socks(netsnmp_transport *t)
{
    if (t && t->base_transport && t->base_transport->sock != t->sock) {
        DEBUGMSGTL(("tlstcp", "Syncing sockets: base %d -> main %d\n",
                    t->base_transport->sock, t->sock));
        t->base_transport->sock = t->sock;
    }
}

static void netsnmp_tlstcp_get_taddr(struct netsnmp_transport_s *t,
                                     void **addr, size_t *addr_len)
{
    *addr_len = t->remote_length;
    *addr = netsnmp_memdup(t->remote, *addr_len);
}

/*
 * You can write something into opaque that will subsequently get passed back
 * to your send function if you like.  For instance, you might want to
 * remember where a PDU came from, so that you can send a reply there...
 */

static int
netsnmp_tlstcp_copy(const netsnmp_transport *oldt, netsnmp_transport *newt)
{
    _netsnmpTLSBaseData *oldtlsdata = (_netsnmpTLSBaseData *) oldt->data;
    _netsnmpTLSBaseData *newtlsdata = (_netsnmpTLSBaseData *) newt->data;

    newtlsdata->ssl = oldtlsdata->ssl;
    oldtlsdata->ssl = NULL;
    newtlsdata->ssl_context = NULL;
    newtlsdata->accept_bio = NULL;

    if (oldtlsdata->addr_string)
        newtlsdata->addr_string = strdup(oldtlsdata->addr_string);
    if (oldtlsdata->securityName)
        newtlsdata->securityName = strdup(oldtlsdata->securityName);
    if (oldtlsdata->our_identity)
        newtlsdata->our_identity = strdup(oldtlsdata->our_identity);
    if (oldtlsdata->their_identity)
        newtlsdata->their_identity = strdup(oldtlsdata->their_identity);
    if (oldtlsdata->their_fingerprint)
        newtlsdata->their_fingerprint = strdup(oldtlsdata->their_fingerprint);
    if (oldtlsdata->their_hostname)
        newtlsdata->their_hostname = strdup(oldtlsdata->their_hostname);
    if (oldtlsdata->trust_cert)
        newtlsdata->trust_cert = strdup(oldtlsdata->trust_cert);
    if (oldtlsdata->addr)
        newtlsdata->addr = netsnmp_memdup(oldtlsdata->addr,
                                          sizeof(*oldtlsdata->addr));

    return 0;
}

static int
netsnmp_tlstcp_run_handshake(netsnmp_transport *t)
{
    _netsnmpTLSBaseData *tlsdata = t->data;
    SSL *ssl = tlsdata->ssl;
    BIO *write_bio = SSL_get_wbio(ssl);
    BIO *read_bio = SSL_get_rbio(ssl);
    char buf[4096];
    int ssl_err;
    int bytes;
    int rc;

    while (1) {
        rc = SSL_connect(ssl);
        if (rc == 1) {
            /* Flush final handshake messages */
            while ((bytes = BIO_read(write_bio, buf, sizeof(buf))) > 0) {
                int sent = t->base_transport->f_send(t->base_transport, buf, bytes, NULL, NULL);
                if (sent < 0) {
                    snmp_log(LOG_ERR, "TLSTCP: handshake flush failed\n");
                    return -1;
                }
            }
            return 1; /* Success */
        }
        ssl_err = SSL_get_error(ssl, rc);

        /* Check if we have data to write to socket */
        while ((bytes = BIO_read(write_bio, buf, sizeof(buf))) > 0) {
            int sent;

            sent = t->base_transport->f_send(t->base_transport, buf, bytes,
                                             NULL, NULL);
            if (sent < 0) {
                snmp_log(LOG_ERR, "TLSTCP: handshake send failed\n");
                return -1;
            }
        }

        if (ssl_err == SSL_ERROR_WANT_READ) {
            /* We need to read from socket and write to read_bio */
            void *opaque = NULL;
            int olen = 0;

            bytes = t->base_transport->f_recv(t->base_transport, buf,
                                              sizeof(buf), &opaque, &olen);
            free(opaque);
            if (bytes < 0) {
                snmp_log(LOG_ERR, "TLSTCP: handshake recv failed\n");
                return -1;
            }
            if (bytes == 0) {
                snmp_log(LOG_ERR, "TLSTCP: handshake recv connection closed\n");
                return -1;
            }
            BIO_write(read_bio, buf, bytes);
        } else if (ssl_err == SSL_ERROR_WANT_WRITE) {
            continue;
        } else {
            _openssl_log_error(rc, ssl, "SSL_connect");
            return -1;
        }
    }
}

static int
netsnmp_tlstcp_run_handshake_server(SSL *ssl, int newsock)
{
    BIO *read_bio = SSL_get_rbio(ssl);
    BIO *write_bio = SSL_get_wbio(ssl);
    char buf[4096];
    int ssl_err;
    int bytes;
    int rc;

    while (1) {
        rc = SSL_accept(ssl);
        if (rc == 1) {
            /* Flush final handshake messages */
            while ((bytes = BIO_read(write_bio, buf, sizeof(buf))) > 0) {
                int sent;

                sent = send(newsock, (const char *)buf, bytes, 0);
                if (sent < 0) {
                    snmp_log(LOG_ERR, "TLSTCP: server handshake flush failed\n");
                    return -1;
                }
            }
            return 1; /* Success */
        }
        ssl_err = SSL_get_error(ssl, rc);

        /* Check if we have data to write to socket */
        while ((bytes = BIO_read(write_bio, buf, sizeof(buf))) > 0) {
            int sent = send(newsock, buf, bytes, 0);
            if (sent < 0) {
                snmp_log(LOG_ERR, "TLSTCP: server handshake send failed\n");
                return -1;
            }
        }

        if (ssl_err == SSL_ERROR_WANT_READ) {
            /* We need to read from socket and write to read_bio */
            bytes = recv(newsock, buf, sizeof(buf), 0);
            if (bytes < 0) {
                snmp_log(LOG_ERR, "TLSTCP: server handshake recv failed\n");
                return -1;
            }
            if (bytes == 0) {
                snmp_log(LOG_ERR,
                         "TLSTCP: server handshake recv connection closed\n");
                return -1;
            }
            BIO_write(read_bio, buf, bytes);
        } else if (ssl_err == SSL_ERROR_WANT_WRITE) {
            continue;
        } else {
            snmp_log(LOG_ERR, "TLSTCP: Failed SSL_accept\n");
            _openssl_log_error(rc, ssl, "SSL_accept");
            return -1;
        }
    }
}

static int
netsnmp_tlstcp_recv(netsnmp_transport *t, void *buf, int size,
                    void **opaque, int *olength)
{
    int             rc = -1;
    netsnmp_tmStateReference *tmStateRef = NULL;
    _netsnmpTLSBaseData *tlsdata;
    int bytes_read_total = 0;
    char raw_buf[4096];
    char out_buf[4096];
    int bytes_read;
    BIO *write_bio;
    BIO *read_bio;
    int out_bytes;
    int got_eof = 0;
    SSL *ssl;
    int err;

    if (NULL == t || t->sock < 0 || NULL == t->data) {
        snmp_log(LOG_ERR,
                 "tlstcp received an invalid invocation with missing data\n");
        DEBUGMSGTL(("tlstcp", "recvfrom fd %d err %d (\"%s\")\n",
                    (t ? t->sock : -1), errno, strerror(errno)));
        if (t)
            DEBUGMSGTL(("tlstcp", "  tdata = %p", t->data));
        DEBUGMSGTL(("tlstcp", "\n"));
        return -1;
    }

    _tlstcp_sync_socks(t);

    tlsdata = t->data;
    ssl = tlsdata->ssl;
    if (!ssl) {
        snmp_log(LOG_ERR,
                 "tlstcp received an invalid invocation without ssl data\n");
        return -1;
    }

    read_bio = SSL_get_rbio(ssl);
    write_bio = SSL_get_wbio(ssl);

    /* 1. Read raw ciphertext from base transport */
    do {
        void *recv_opaque = NULL;
        int recv_olen = 0;

        bytes_read = t->base_transport->f_recv(t->base_transport, raw_buf,
                                               sizeof(raw_buf), &recv_opaque,
                                               &recv_olen);
        free(recv_opaque);

        DEBUGMSGTL(("tlstcp", "base recv returned %d\n", bytes_read));
        if (bytes_read > 0) {
            bytes_read_total += bytes_read;
            BIO_write(read_bio, raw_buf, bytes_read);
            DEBUGMSGTL(("tlstcp", "wrote %d bytes of ciphertext to read_bio\n",
                        bytes_read));
        } else if (bytes_read == 0) {
            DEBUGMSGTL(("tlstcp", "remote side closed connection\n"));
            got_eof = 1;
            break;
        } else {
            if (errno != EAGAIN &&
                (EAGAIN == EWOULDBLOCK || errno != EWOULDBLOCK) &&
                errno != EINTR) {
                DEBUGMSGTL(("tlstcp", "base recv error: %d\n", errno));
                if (bytes_read_total > 0) {
                    got_eof = 1;
                    break;
                }
                return -1;
            }
        }
    } while (bytes_read > 0);

    if (bytes_read_total > 0)
        tlsdata->want_read = 0;

    /* 2. Read decrypted plaintext from SSL */
    tmStateRef = SNMP_MALLOC_TYPEDEF(netsnmp_tmStateReference);

    if (tmStateRef == NULL) {
        *opaque = NULL;
        *olength = 0;
        return -1;
    }

    /* Set the transportDomain */
    memcpy(tmStateRef->transportDomain,
           netsnmpTLSTCPDomain, sizeof(netsnmpTLSTCPDomain[0]) *
           netsnmpTLSTCPDomain_len);
    tmStateRef->transportDomainLen = netsnmpTLSTCPDomain_len;
    if (tlsdata->addr) {
        memcpy(&tmStateRef->addresses, tlsdata->addr,
               sizeof(netsnmp_indexed_addr_pair));
        tmStateRef->have_addresses = 1;
    } else {
        tmStateRef->have_addresses = 0;
    }

    rc = SSL_read(ssl, buf, size);
    MAKE_MEM_DEFINED(&rc, sizeof(rc));
    if (rc > 0)
        MAKE_MEM_DEFINED(buf, rc);

    err = SSL_get_error(ssl, rc);

    /* Check if SSL wants to write something */
    while ((out_bytes = BIO_read(write_bio, out_buf, sizeof(out_buf))) > 0) {
        DEBUGMSGTL(("tlstcp",
                    "recv: writing %d bytes of ciphertext to base transport\n",
                    out_bytes));
        t->base_transport->f_send(t->base_transport, out_buf, out_bytes, NULL,
                                  NULL);
    }

    if (rc <= 0) {
        if ((err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) &&
            !got_eof) {
            if (err == SSL_ERROR_WANT_READ) {
                tlsdata->want_read = 1;
                DEBUGMSGTL(("tlstcp", "SSL_read wanted read (want_read=1)\n"));
            }
            t->flags |= NETSNMP_TRANSPORT_FLAG_EMPTY_PKT;
            SNMP_FREE(tmStateRef);
            return 0;
        }
        if (rc == 0 || err == SSL_ERROR_ZERO_RETURN || got_eof) {
            DEBUGMSGTL(("tlstcp",
                        "remote side closed connection (SSL or socket)\n"));
            SNMP_FREE(tmStateRef);
            return -1;
        }
        _openssl_log_error(rc, ssl, "SSL_read");
        SNMP_FREE(tmStateRef);
        return rc;
    }

    DEBUGMSGTL(("tlstcp", "received %d decoded bytes from tls\n", rc));

    /* log the packet */
    DEBUGIF("tlstcp") {
        char *str = netsnmp_tlstcp_fmtaddr(t, NULL, 0);
        DEBUGMSGTL(("tlstcp",
                    "recvfrom fd %d got %d bytes (from %s)\n",
                    t->sock, rc, str));
        free(str);
    }

    /* Other wrap-up things common to TLS and DTLS */
    if (netsnmp_tlsbase_wrapup_recv(tmStateRef, tlsdata, opaque, olength) !=
        SNMPERR_SUCCESS)
        return SNMPERR_GENERR;

    return rc;
}

static int
netsnmp_tlstcp_pending(netsnmp_transport *t)
{
    _netsnmpTLSBaseData *tlsdata = t->data;

    if (tlsdata && tlsdata->ssl) {
        BIO *read_bio = SSL_get_rbio(tlsdata->ssl);
        int ssl_p = SSL_pending(tlsdata->ssl);
        int bio_p = read_bio ? BIO_pending(read_bio) : 0;

        if (ssl_p > 0 || (bio_p > 0 && !tlsdata->want_read)) {
            DEBUGMSGTL(("tlstcp", "pending: SSL %d, BIO %d (want_read %d)\n",
                        ssl_p, bio_p, tlsdata->want_read));
            return 1;
        }
    }
    return 0;
}

static int
netsnmp_tlstcp_send(netsnmp_transport *t, const void *buf, int size,
                    void **opaque, int *olength)
{
    int rc = -1;
    const netsnmp_tmStateReference *tmStateRef = NULL;
    _netsnmpTLSBaseData *tlsdata;
    char out_buf[4096];
    BIO *write_bio;
    int out_bytes;
    SSL *ssl;

    DEBUGTRACETOK("tlstcp");

    if (opaque != NULL && *opaque != NULL &&
        *olength == sizeof(netsnmp_tmStateReference)) {
        tmStateRef = (const netsnmp_tmStateReference *) *opaque;
    } else {
        snmp_log(LOG_ERR, "TLSTCP was called with an invalid state; possibly the wrong security model is in use.  It should be 'tsm'.\n");
        snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONINVALIDCACHES);
        return SNMPERR_GENERR;
    }

    if (NULL == t->data) {
        snmp_log(LOG_ERR, "netsnmp_tlstcp_send received no incoming data\n");
        return -1;
    }

    _tlstcp_sync_socks(t);

    tlsdata = t->data;
    ssl = tlsdata->ssl;

    if (!ssl) {
        snmp_log(LOG_ERR, "tlstcp_send was called without a SSL connection.\n");
        return SNMPERR_GENERR;
    }

    if ((tlsdata->flags & NETSNMP_TLSBASE_IS_CLIENT) &&
        !tlsdata->securityName && tmStateRef && tmStateRef->securityNameLen > 0)
        tlsdata->securityName = strdup(tmStateRef->securityName);

    write_bio = SSL_get_wbio(ssl);

    rc = SSL_write(ssl, buf, size);
    DEBUGMSGTL(("tlstcp", "wrote %d bytes to ssl\n", size));
    if (rc <= 0) {
        int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            /* try to send anyway */
        } else {
            _openssl_log_error(rc, ssl, "SSL_write");
            return rc;
        }
    }

    while ((out_bytes = BIO_read(write_bio, out_buf, sizeof(out_buf))) > 0) {
        int sent;
        DEBUGMSGTL(("tlstcp", "writing %d bytes of ciphertext to base transport\n", out_bytes));
        sent = t->base_transport->f_send(t->base_transport, out_buf, out_bytes, NULL, NULL);
        DEBUGMSGTL(("tlstcp", "base transport sent %d bytes\n", sent));
        if (sent < 0) {
            snmp_log(LOG_ERR, "TLSTCP: send failed\n");
            return -1;
        }
    }

    return rc;
}



static int
netsnmp_tlstcp_close(netsnmp_transport *t)
{
    _netsnmpTLSBaseData *tlsdata;
    char out_buf[4096];
    BIO *write_bio;
    int out_bytes;
    int rc = 0;

    if (NULL == t || NULL == t->data)
        return -1;

    if (t->flags & NETSNMP_TLSBASE_IS_CLIENT)
        snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONCLIENTCLOSES);
    else
        snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONSERVERCLOSES);

    tlsdata = t->data;

    _tlstcp_sync_socks(t);

    DEBUGMSGTL(("tlstcp", "Shutting down SSL connection\n"));
    if (tlsdata->ssl) {
        SSL_shutdown(tlsdata->ssl);
        /* Flush write_bio */
        write_bio = SSL_get_wbio(tlsdata->ssl);
        if (write_bio) {
            while ((out_bytes = BIO_read(write_bio, out_buf, sizeof(out_buf))) >
                   0) {
                if (t->base_transport) {
                    t->base_transport->f_send(t->base_transport, out_buf,
                                              out_bytes, NULL, NULL);
                } else if (t->sock >= 0) {
                    send(t->sock, out_buf, out_bytes, 0);
                }
            }
        }
    }

    netsnmp_tlsbase_free_tlsdata(tlsdata);
    t->data = NULL;

    if (t->base_transport) {
        rc = t->base_transport->f_close(t->base_transport);
        netsnmp_transport_free(t->base_transport);
        t->base_transport = NULL;
        t->sock = -1;
    } else if (t->sock >= 0) {
        rc = netsnmp_socketbase_close(t);
    }

    return rc;
}

static int
netsnmp_tlstcp_accept(netsnmp_transport *t)
{
    _netsnmpTLSBaseData *tlsdata = t->data;
    BIO *read_bio, *write_bio;
    int newsock;
    SSL *ssl;
    int rc;

    DEBUGMSGTL(("tlstcp", "netsnmp_tlstcp_accept called\n"));

    if (!t->base_transport) {
        snmp_log(LOG_ERR, "TLSTCP: missing base transport in accept\n");
        return -1;
    }

    newsock = t->base_transport->f_accept(t->base_transport);
    if (newsock < 0)
        return -1;

    if (t->base_transport->data) {
        if (!tlsdata->addr) {
            tlsdata->addr = malloc(sizeof(netsnmp_indexed_addr_pair));
        }
        if (tlsdata->addr) {
            memcpy(tlsdata->addr, t->base_transport->data,
                   sizeof(netsnmp_indexed_addr_pair));
            _tlstcp_format_addr_string(tlsdata);
        }
    }

    /* Ensure newsock is blocking for handshake */
    netsnmp_set_non_blocking_mode(newsock, FALSE);

    ssl = SSL_new(tlsdata->ssl_context);
    if (!ssl) {
        snmp_log(LOG_ERR,
                 "TLSTCP: Failed to create SSL object for accepted connection\n");
        goto close_newsock;
    }

    read_bio = BIO_new(BIO_s_mem());
    write_bio = BIO_new(BIO_s_mem());
    if (!read_bio || !write_bio) {
        snmp_log(LOG_ERR, "TLSTCP: Failed to create memory BIOs\n");
        BIO_free(read_bio);
        BIO_free(write_bio);
        goto free_ssl;
    }
    SSL_set_bio(ssl, read_bio, write_bio);
    SSL_set_accept_state(ssl);

    rc = netsnmp_tlstcp_run_handshake_server(ssl, newsock);
    if (rc <= 0)
        goto free_ssl;

    if (netsnmp_tlsbase_verify_client_cert(ssl, tlsdata) != SNMPERR_SUCCESS) {
        snmp_log(LOG_ERR, "TLSTCP: Failed checking client certificate\n");
        snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONINVALIDCLIENTCERTIFICATES);
        SSL_shutdown(ssl);
        goto free_ssl;
    }

    DEBUGMSGTL(("tlstcp", "accept succeeded on sock %d\n", newsock));

    snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONACCEPTS);

    /* Make newsock non-blocking again before returning */
    netsnmp_set_non_blocking_mode(newsock, TRUE);

    tlsdata->ssl = ssl;

    return newsock;

free_ssl:
    SSL_free(ssl);

close_newsock:
#ifdef HAVE_CLOSESOCKET
    closesocket(newsock);
#else
    close(newsock);
#endif
    return -1;
}

static netsnmp_transport *
netsnmp_tlstcp_open_client(netsnmp_transport *t)
{
    _netsnmpTLSBaseData *tlsdata = t->data;
    _netsnmp_verify_info *verify_info;
    BIO *read_bio, *write_bio;
    SSL_CTX *ctx;
    SSL *ssl;
    int rc = 0;

    snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONOPENS);

    if (!t->base_transport) {
        snmp_log(LOG_ERR, "TLSTCP: missing base transport\n");
        return NULL;
    }

    /* set up the needed SSL context */
    tlsdata->ssl_context = ctx = sslctx_client_setup(TLS_method(), tlsdata);
    if (!ctx) {
        snmp_log(LOG_ERR, "failed to create TLS context\n");
        goto err_free_tlsdata;
    }

    DEBUGMSGTL(("tlstcp", "connecting to tlstcp %s\n",
                tlsdata->addr_string));
    SNMP_FREE(t->remote);
    t->remote = strdup(tlsdata->addr_string);
    t->remote_length = strlen(tlsdata->addr_string) + 1;

    /* Create the SSL layer */
    ssl = tlsdata->ssl = SSL_new(ctx);
    if (NULL == ssl) {
        snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONOPENERRORS);
        snmp_log(LOG_ERR, "tlstcp: failed to create a SSL connection\n");
        goto err_free_tlsdata;
    }

    read_bio = BIO_new(BIO_s_mem());
    write_bio = BIO_new(BIO_s_mem());
    if (!read_bio || !write_bio) {
        snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONOPENERRORS);
        snmp_log(LOG_ERR, "tlstcp: failed to create memory BIOs\n");
        BIO_free(read_bio);
        BIO_free(write_bio);
        goto err_free_ssl;
    }

    /* Bind the SSL layer to the BIOs */
    SSL_set_bio(ssl, read_bio, write_bio);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    verify_info = SNMP_MALLOC_TYPEDEF(_netsnmp_verify_info);
    if (NULL == verify_info) {
        snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONOPENERRORS);
        snmp_log(LOG_ERR, "tlstcp: failed to allocate verify_info\n");
        goto err_free_ssl;
    }

    SSL_set_ex_data(ssl, tls_get_verify_info_index(), verify_info);

    /* Run handshake (blocking during open) */
    rc = netsnmp_tlstcp_run_handshake(t);
    if (rc <= 0) {
        snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONOPENERRORS);
        snmp_log(LOG_ERR, "tlstcp: failed to ssl_connect\n");
        goto err_free_ssl;
    }

    if (netsnmp_tlsbase_verify_server_cert(ssl, tlsdata) != SNMPERR_SUCCESS) {
        snmp_increment_statistic(STAT_TLSTM_SNMPTLSTMSESSIONUNKNOWNSERVERCERTIFICATE);
        snmp_log(LOG_ERR, "tlstcp: failed to verify ssl certificate\n");
        goto err_free_ssl;
    }

    t->sock = t->base_transport->sock;
    if (t->sock >= 0) {
        if (netsnmp_set_non_blocking_mode(t->sock, TRUE) < 0) {
            DEBUGMSGTL(("tlstcp", "couldn't set non-blocking mode on client fd %d\n",
                        t->sock));
        }
    }

    return t;

err_free_ssl:
err_free_tlsdata:
    netsnmp_tlsbase_free_tlsdata(tlsdata);
    t->data = NULL;
    return NULL;
}

static netsnmp_transport *
netsnmp_tlstcp_open_server(netsnmp_transport *t)
{
    _netsnmpTLSBaseData *tlsdata = t->data;

    if (!t->base_transport) {
        snmp_log(LOG_ERR, "TLSTCP: missing base transport\n");
        return NULL;
    }

#ifndef NETSNMP_NO_LISTEN_SUPPORT
    DEBUGMSGTL(("tlstcp", "listening on tlstcp port %s\n",
                tlsdata->addr_string));
    SNMP_FREE(t->local);
    t->local = strdup(tlsdata->addr_string);
    t->local_length = strlen(tlsdata->addr_string) + 1;

    /* create the OpenSSL TLS context */
    tlsdata->ssl_context = sslctx_server_setup(TLS_method());
    if (NULL == tlsdata->ssl_context) {
        return NULL;
    }

    t->sock = t->base_transport->sock;
    if (t->sock >= 0) {
        if (netsnmp_set_non_blocking_mode(t->sock, TRUE) < 0) {
            DEBUGMSGTL(("tlstcp", "couldn't set non-blocking mode on server fd %d\n",
                        t->sock));
        }
    }
    t->flags |= NETSNMP_TRANSPORT_FLAG_LISTEN;
#else /* NETSNMP_NO_LISTEN_SUPPORT */
    return NULL;
#endif /* NETSNMP_NO_LISTEN_SUPPORT */

    return t;
}

netsnmp_transport *
netsnmp_tlstcp_open(netsnmp_transport *t)
{
    _netsnmpTLSBaseData *tlsdata;

    netsnmp_assert_or_return(t != NULL, NULL);
    netsnmp_assert_or_return(t->data != NULL, NULL);
    netsnmp_assert_or_return(sizeof(_netsnmpTLSBaseData) == t->data_length,
                             NULL);

    tlsdata = t->data;

    if (tlsdata->flags & NETSNMP_TLSBASE_IS_CLIENT)
        return netsnmp_tlstcp_open_client(t);
    else
        return netsnmp_tlstcp_open_server(t);
}

static void
_tlstcp_format_addr_string(_netsnmpTLSBaseData *tlsdata)
{
    char buf[128];
    if (!tlsdata || !tlsdata->addr)
        return;

    if (tlsdata->addr_string) {
        free(tlsdata->addr_string);
        tlsdata->addr_string = NULL;
    }

    if (tlsdata->addr->remote_addr.sa.sa_family == AF_INET) {
        char a[16];
        snprintf(buf, sizeof(buf), "%s:%hu",
                 inet_ntop(AF_INET, &tlsdata->addr->remote_addr.sin.sin_addr,
                           a, sizeof(a)),
                 ntohs(tlsdata->addr->remote_addr.sin.sin_port));
        tlsdata->addr_string = strdup(buf);
    }
#ifdef NETSNMP_TRANSPORT_TCPIPV6_DOMAIN
    else if (tlsdata->addr->remote_addr.sa.sa_family == AF_INET6) {
        char a[64];
        snprintf(buf, sizeof(buf), "[%s]:%hu",
                 inet_ntop(AF_INET6, &tlsdata->addr->remote_addr.sin6.sin6_addr,
                           a, sizeof(a)),
                 ntohs(tlsdata->addr->remote_addr.sin6.sin6_port));
        tlsdata->addr_string = strdup(buf);
    }
#endif
}

/*
 * Create a TLS-based transport for SNMP.  Local is TRUE if addr is the local
 * address to bind to (i.e. this is a server-type session); otherwise addr is
 * the remote address to send things to.
 */

static netsnmp_transport *
_tlstcp_transport_common(netsnmp_transport *t, int local)
{
    char *tmp = NULL;
    int tmp_len = 0;

    if (NULL == t)
        return NULL;

    /* Save base transport for clients; need in send/recv functions later */
    if (t->data) {
        tmp = t->data;
        tmp_len = t->data_length;
        t->data = NULL;
    }
    t->base_transport = netsnmp_transport_copy(t);

    if (tmp) {
        t->data = tmp;
        t->data_length = tmp_len;
    }

    if (NULL != t->data &&
        t->data_length == sizeof(netsnmp_indexed_addr_pair)) {
        _netsnmpTLSBaseData *tlsdata =
            netsnmp_tlsbase_allocate_tlsdata(t, local);
        tlsdata->addr = (netsnmp_indexed_addr_pair *) t->data;
        t->data = tlsdata;
        t->data_length = sizeof(_netsnmpTLSBaseData);

        /* Format addr_string from tlsdata->addr */
        _tlstcp_format_addr_string(tlsdata);
    }

    t->domain = netsnmpTLSTCPDomain;
    t->domain_length = netsnmpTLSTCPDomain_len;

    t->f_recv          = netsnmp_tlstcp_recv;
    t->f_send          = netsnmp_tlstcp_send;
    t->f_open          = netsnmp_tlstcp_open;
    t->f_close         = netsnmp_tlstcp_close;
    t->f_accept        = netsnmp_tlstcp_accept;
    t->f_copy          = netsnmp_tlstcp_copy;
    t->f_pending       = netsnmp_tlstcp_pending;
    t->f_config        = netsnmp_tlsbase_config;
    t->f_setup_session = netsnmp_tlsbase_session_init;
    t->f_fmtaddr       = netsnmp_tlstcp_fmtaddr;
    t->f_get_taddr     = netsnmp_tlstcp_get_taddr;

    t->flags |= NETSNMP_TRANSPORT_FLAG_TUNNELED | NETSNMP_TRANSPORT_FLAG_STREAM;

    return t;
}

static netsnmp_transport *
netsnmp_tlstcp_transport(const struct netsnmp_ep *ep, int local)
{
    netsnmp_transport *t = NULL;

#ifdef NETSNMP_TRANSPORT_TCPIPV6_DOMAIN
    if (ep->a.sin.sin_family == AF_INET6) {
        t = netsnmp_tcp6_transport(ep, local);
    } else
#endif
    {
        t = netsnmp_tcp_transport(ep, local);
    }

    if (!t)
        return NULL;

    t = _tlstcp_transport_common(t, local);
    if (!t)
        return NULL;

    return t;
}

netsnmp_transport *
netsnmp_tlstcp_create_tstring(const char *str, int local,
                               const char *default_target)
{
    _netsnmpTLSBaseData *tlsdata;
    netsnmp_transport *t = NULL;
    struct netsnmp_ep ep;
    const char *cp;
    char buf[SPRINT_MAX_LEN];

    if (netsnmp_sockaddr_in3(&ep, str, default_target)) {
        t = netsnmp_tlstcp_transport(&ep, local);
    }
#ifdef NETSNMP_TRANSPORT_TCPIPV6_DOMAIN
    else if (netsnmp_sockaddr_in6_3(&ep, str, default_target)) {
        t = netsnmp_tlstcp_transport(&ep, local);
    }
#endif

    if (!t)
        return NULL;

    /* see if we can extract the remote hostname */
    if (!local && t->data && str) {
        tlsdata = (_netsnmpTLSBaseData *)t->data;
        /* search for a : */
        if (NULL != (cp = strrchr(str, ':'))) {
            sprintf(buf, "%.*s", (int) SNMP_MIN(cp - str, sizeof(buf) - 1),
                    str);
        } else {
            /* else the entire spec is a host name only */
            strlcpy(buf, str, sizeof(buf));
        }
        tlsdata->their_hostname = strdup(buf);
    }

    return t;
}


netsnmp_transport *
netsnmp_tlstcp_create_ostring(const void *o, size_t o_len, int local)
{
    struct netsnmp_ep ep;

    memset(&ep, 0, sizeof(ep));
    if (netsnmp_ipv4_ostring_to_sockaddr(&ep.a.sin, o, o_len))
        return netsnmp_tlstcp_transport(&ep, local);
#ifdef NETSNMP_TRANSPORT_TCPIPV6_DOMAIN
    else if (netsnmp_ipv6_ostring_to_sockaddr(&ep.a.sin6, o, o_len))
        return netsnmp_tlstcp_transport(&ep, local);
#endif
    else
        return NULL;
}

void
netsnmp_tlstcp_ctor(void)
{
    DEBUGMSGTL(("tlstcp", "registering TLS constructor\n"));

    /* config settings */

    tlstcpDomain.name = netsnmpTLSTCPDomain;
    tlstcpDomain.name_length = netsnmpTLSTCPDomain_len;
    tlstcpDomain.prefix = calloc(3, sizeof(char *));
    if (!tlstcpDomain.prefix) {
        snmp_log(LOG_ERR, "calloc() failed - out of memory\n");
        return;
    }
    tlstcpDomain.prefix[0] = "tlstcp";
    tlstcpDomain.prefix[1] = "tls";

    tlstcpDomain.f_create_from_tstring_new = netsnmp_tlstcp_create_tstring;
    tlstcpDomain.f_create_from_ostring     = netsnmp_tlstcp_create_ostring;

    netsnmp_tdomain_register(&tlstcpDomain);
}
