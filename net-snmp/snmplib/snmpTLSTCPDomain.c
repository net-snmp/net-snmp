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

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>
#include <net-snmp/config_api.h>

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/snmpTLSUDPDomain.h>
#include <net-snmp/library/snmpUDPDomain.h>
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

oid             netsnmpTLSUDPDomain[] = { TRANSPORT_DOMAIN_TLS_TCP_IP };
size_t          netsnmpTLSUDPDomain_len = OID_LENGTH(netsnmpTLSTCPDomain);

static netsnmp_tdomain tlsudpDomain;

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
    socklen_t       fromlen = sizeof(struct sockaddr);
    netsnmp_indexed_addr_pair *addr_pair = NULL;
    struct sockaddr *from;
    netsnmp_tmStateReference *tmStateRef = NULL;
    X509            *peer;

    if (t != NULL && t->sock >= 0) {
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

	while (rc < 0) {
#if defined(linux) && defined(IP_PKTINFO)
            rc = netsnmp_tcp_recvfrom(t->sock, buf, size, from, &fromlen,
                            &(addr_pair->local_addr), &(addr_pair->if_index));
#else
            rc = recvfrom(t->sock, buf, size, NETSNMP_DONTWAIT, from, &fromlen);
#endif /* linux && IP_PKTINFO */
	    if (rc < 0 && errno != EINTR) {
		break;
	    }
	}

        DEBUGMSGTL(("tlstcp", "received %d raw bytes on way to tls\n", rc));
        if (rc < 0) {
            DEBUGMSGTL(("tlstcp", "recvfrom fd %d err %d (\"%s\")\n",
                        t->sock, errno, strerror(errno)));
            SNMP_FREE(tmStateRef);
            return -1;
        }

        if (rc >= 0) {
            /* now that we have the from address filled in, we can look up
               the openssl context and have openssl read and process
               appropriately */

            /* if we don't have a cachep for this connection then
               we're receiving something new and are the server
               side */
            /* XXX: allow for a SNMP client to never accept new conns? */
            bio_cache *cachep =
                find_or_create_bio_cache(t->sock, &addr_pair->remote_addr,
                                         WE_ARE_SERVER);
            if (NULL == cachep) {
                SNMP_FREE(tmStateRef);
                return -1;
            }

            /* write the received buffer to the memory-based input bio */
            BIO_write(cachep->bio, buf, rc);

            /* XXX: in Wes' other example we do a SSL_pending() call
               too to ensure we're ready to read...  it's possible
               that buffered stuff in openssl won't be caught by the
               net-snmp select loop because it's already been pulled
               out; need to deal with this) */
            rc = SSL_read(cachep->con, buf, size);
            
            DEBUGMSGTL(("tlstcp", "received %d decoded bytes from tls\n", rc));

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

            if (rc == -1) {
                _openssl_log_error(rc, cachep->con, "SSL_read");
                SNMP_FREE(tmStateRef);

                if (SSL_get_error(cachep->con, rc) == SSL_ERROR_WANT_READ)
                    return -1; /* XXX: it's ok, but what's the right return? */
                return rc;
            }

            {
                char *str = netsnmp_tcp_fmtaddr(NULL, addr_pair, sizeof(netsnmp_indexed_addr_pair));
                DEBUGMSGTL(("tlstcp",
                            "recvfrom fd %d got %d bytes (from %s)\n",
                            t->sock, rc, str));
                free(str);
            }

            /* XXX: disallow NULL auth/encr algs in our implementations */
            tmStateRef->transportSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

            /* use x509 cert to do lookup to secname if DNE in cachep yet */
            if (!cachep->securityName) {
                if (NULL != (peer = SSL_get_peer_certificate(cachep->con))) {
                    X509_NAME *subname;
                    char namebuf[1024];
                
                    /* we have one */
                    subname = X509_get_subject_name(peer);
                    X509_NAME_get_text_by_NID(subname, NID_commonName,
                                              namebuf, sizeof(namebuf));
                    DEBUGMSGTL(("tlstcp", "got commonname: %s\n",
                                namebuf));
                    cachep->securityName = strdup(namebuf);
                    DEBUGMSGTL(("tlstcp", "set SecName to: %s\n",
                                cachep->securityName));
                } else {
                    SNMP_FREE(tmStateRef);
                    return -1;
                }
            }

            /* XXX: detect and throw out overflow secname sizes rather
               than truncating. */
            strncpy(tmStateRef->securityName, cachep->securityName,
                    sizeof(tmStateRef->securityName)-1);
            tmStateRef->securityName[sizeof(tmStateRef->securityName)-1] = '\0';
            tmStateRef->securityNameLen = strlen(tmStateRef->securityName);

            *opaque = tmStateRef;
            *olength = sizeof(netsnmp_tmStateReference);

        } else {
            DEBUGMSGTL(("tlstcp", "recvfrom fd %d err %d (\"%s\")\n",
                        t->sock, errno, strerror(errno)));
        }
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
    bio_cache *cachep = NULL;
    netsnmp_tmStateReference *tmStateRef = NULL;
    u_char outbuf[65535];
    
    if (opaque != NULL && *opaque != NULL &&
        *olength == sizeof(netsnmp_tmStateReference)) {
        tmStateRef = (netsnmp_tmStateReference *) *opaque;

        if (tmStateRef->have_addresses)
            addr_pair = &(tmStateRef->addresses);
        else if (t != NULL && t->data != NULL &&
                 t->data_length == sizeof(netsnmp_indexed_addr_pair))
            addr_pair = (netsnmp_indexed_addr_pair *) (t->data);
    } else if (t != NULL && t->data != NULL &&
               t->data_length == sizeof(netsnmp_indexed_addr_pair)) {
        addr_pair = (netsnmp_indexed_addr_pair *) (t->data);
    }

    if (NULL == addr_pair) {
        snmp_log(LOG_ERR, "tlstcp_send: can't get address to send to\n");
        return -1;
    }

    to = (struct sockaddr *) &(addr_pair->remote_addr);

    if (NULL == to || NULL == t || t->sock <= 0) {
        snmp_log(LOG_ERR, "invalid netsnmp_tlstcp_send usage\n");
        return -1;
    }

    /* we're always a client if we're sending to something unknown yet */
    if (NULL ==
        (cachep = find_or_create_bio_cache(t->sock, &addr_pair->remote_addr,
                                           WE_ARE_CLIENT)))
        return -1;

    if (!cachep->securityName && tmStateRef && tmStateRef->securityNameLen > 0)
        cachep->securityName = strdup(tmStateRef->securityName);
        
        
    {
        char *str = netsnmp_tcp_fmtaddr(NULL, (void *) addr_pair,
                                        sizeof(netsnmp_indexed_addr_pair));
        DEBUGMSGTL(("tlstcp", "send %d bytes from %p to %s on fd %d\n",
                    size, buf, str, t->sock));
        free(str);
    }
    rc = SSL_write(cachep->con, buf, size);
    if (rc < 0) {
        _openssl_log_error(rc, cachep->con, "SSL_write");
    }

    /* for memory bios, we now read from openssl's write buffer (ie,
       the packet to go out) and send it out the tcp port manually */
    rc = BIO_read(cachep->write_bio, outbuf, sizeof(outbuf));
    if (rc <= 0) {
        /* in theory an ok thing */
        return 0;
    }
#if defined(FIXME) && defined(linux) && defined(IP_PKTINFO)
    /* XXX: before this can work, we need to remember address we
       received it from (addr_pair) */
    rc = netsnmp_tcp_sendto(cachep->sock, &cachep->sockaddr  remote  addr_pair ? &(addr_pair->local_addr) : NULL, to, outbuf, rc);
#else
    rc = sendto(t->sock, outbuf, rc, 0, &cachep->sockaddr, sizeof(struct sockaddr));
#endif /* linux && IP_PKTINFO */

    return rc;
}



static int
netsnmp_tlstcp_close(netsnmp_transport *t)
{
    /* XXX: issue a proper tls closure notification(s) */

    return netsnmp_socketbase_close(t);
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
    tlsdata = SNMP_MALLOC_TYPEDEF(tlsdata);
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

        /* bind */
        /* listen */

    } else {
        /* Is the client */
        tlsdata->isclient = 1;
        bio = BIO_new_ssl_connect(ctx);
        BIO_get_ssl(bio, &ssl);
        SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

        /* set up the needed SSL context */
        tlsdata->ssl_context = ctx =
            sslctx_clienct_setup(TLSv1_client_method());

        BIO_set_conn_hostname(bio, addr);

        if (BIO_do_connect(bio) <= 0) {
            SNMP_FREE(tlsdata);
            SNMP_FREE(t);
            snmp_log(LOG_ERR, "failed to open connection to TLS server\n");
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
    t->f_accept   = NULL;
    t->f_fmtaddr  = netsnmp_tcp_fmtaddr;
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
