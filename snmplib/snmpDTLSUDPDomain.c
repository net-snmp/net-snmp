/* Portions of this file are subject to the following copyright(s).  See
 * the Net-SNMP's COPYING file for more details and other copyrights
 * that may apply:
 */
/*
 * Portions of this file are copyrighted by:
 * Copyright Copyright 2003 Sun Microsystems, Inc. All rights reserved.
 * Use is subject to license terms specified in the COPYING file
 * distributed with the Net-SNMP package.
 */

/*
 * NOTE: THIS IS AN EXPERIMENTAL IMPLEMENTATION AND NOT YET SUITABLE
 * FOR PRODUCTION USE
 *
 * THERE are KNOWN security ISSUES with THIS code!
 * (if nothing else, you can't tie certificates to certain hosts/users)
 */

/*
 * ---------- Creating Certificates ----------
 *
 * Example pub/priv key creation steps using openssl (replace for-user
 * with the appropriate name, etc (e.g. for a user you might use their
 * first.last name and for a server, use it's hostname or something)
 *
 *   1) create the CSR file first:
 *
 *         openssl req -days 365 -new -out for-user.csr -keyout for-user.priv
 *
 *   2) Optionally remove the passphrase if you hate that sort of thing
 *      (obviously not recommended; useful on servers without password prompts)
 *
 *         openssl rsa -in for-user.priv -out for-user.insecure.priv
 *
 *   3) Create a self-signed key from the CSR:
 *
 *      openssl x509 -set_serial `date +%Y%m%d` -in for-user.csr -out for-user.cert -req -signkey for-user.insecure.priv -days 365
 *
 *
 * These can then be used by the config tokens for both the client and
 * the server:
 *
 * ---------- Creating a CA for issuing certs ----------
 *
 * TBD
 *
 * ---------- Configuration ----------
 *
 * In the snmp.conf file, you should specify the following
 * types of configuration lines:
 *
 * To tell the client which keys *it* should use to authenticate with:
 *
 *   defX509ClientPriv /path/to/for-user.insecure.priv
 *   defX509ClientPub  /path/to/for-user.insecure.cert
 *
 * To tell the client to only a list of servers:
 *
 *   defX509ServerCerts /path/to/server-certs.certs
 *
 *   (server-certs.certs can be created by simply cat'ing multiple
 *    server cert files into ones big file)
 *
 * To tell the server it's certs to offer:
 *
 *   defX509ServerPub  /path/to/server1.insecure.cert
 *   defX509ServerPriv /path/to/server1.insecure.priv
 *
 * To tell the server which keys it should accept from clients:
 *
 *   defX509ClientCerts /path/to/client-certs.certs
 *
 * To authorize for R/W a particular CommonName from those certs:
 *
 *   rwuser "John Doe"
 *
 */

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
#include <net-snmp/library/snmpDTLSUDPDomain.h>
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

oid             netsnmpDTLSUDPDomain[] = { TRANSPORT_DOMAIN_DTLS_UDP_IP };
size_t          netsnmpDTLSUDPDomain_len = OID_LENGTH(netsnmpDTLSUDPDomain);

static netsnmp_tdomain dtlsudpDomain;

/* this stores openssl credentials for each connection since openssl
   can't do it for us at the moment; hopefully future versions will
   change */
typedef struct bio_cache_s {
   BIO *bio;
   BIO *write_bio;
   struct sockaddr_in sockaddr;
   uint32_t ipv4addr;
   u_short portnum;
   SSL *con;
   SSL_CTX *ctx;
   struct bio_cache_s *next;
   int msgnum;
   int sock;
   char *securityName;
} bio_cache;

bio_cache *biocache = NULL;

/* this stores remote connections in a list to search through */
/* XXX: optimize for searching */
/* XXX: handle state issues for new connections to reduce DOS issues */
/*      (TLS should do this, but openssl can't do more than one ctx per sock */
/* XXX: put a timer on the cache for expirary purposes */
static bio_cache *find_bio_cache(struct sockaddr_in *from_addr) {
    bio_cache *cachep = NULL;
    cachep = biocache;
    while(cachep) {

        if (cachep->ipv4addr == from_addr->sin_addr.s_addr &&
            cachep->portnum == from_addr->sin_port) {
            /* found an existing connection */
            break;
        }
            
        cachep = cachep->next;
    }
    return cachep;
}

/* XXX: lots of malloc/state cleanup needed */
#define DIEHERE(msg) { snmp_log(LOG_ERR, "%s\n", msg); return NULL; }

static bio_cache *
start_new_cached_connection(int sock, struct sockaddr_in *remote_addr,
                            int we_are_client) {
    bio_cache *cachep = NULL;
    BIO *keybio = NULL;

    if (!sock)
        DIEHERE("no socket passed in to start_new_cached_connection\n");
    if (!remote_addr)
        DIEHERE("no remote_addr passed in to start_new_cached_connection\n");
        
    cachep = SNMP_MALLOC_TYPEDEF(bio_cache);
    if (!cachep)
        return NULL;
    
    DEBUGMSGTL(("dtlsudp", "starting a new connection\n"));
    cachep->next = biocache;
    biocache = cachep;

    cachep->ipv4addr = remote_addr->sin_addr.s_addr;
    cachep->portnum = remote_addr->sin_port;
    cachep->sock = sock;
    memcpy(&cachep->sockaddr, remote_addr, sizeof(*remote_addr));

    if (we_are_client) {
        DEBUGMSGTL(("dtlsudp", "starting a new connection as a client to sock: %d\n", sock));
        cachep->con = SSL_new(get_client_ctx());

        /* XXX: session setting 735 */

        /* create a bio */

        cachep->bio = BIO_new(BIO_s_mem()); /* The one openssl reads from */
        cachep->write_bio = BIO_new(BIO_s_mem()); /* openssl writes to */

        BIO_set_mem_eof_return(cachep->bio, -1);
        BIO_set_mem_eof_return(cachep->write_bio, -1);

        SSL_set_bio(cachep->con, cachep->bio, cachep->write_bio);
        SSL_set_connect_state(cachep->con);
        
    } else {
        /* we're the server */

        cachep->bio = BIO_new(BIO_s_mem()); /* The one openssl reads from */

        if (!cachep->bio)
            DIEHERE("failed to create the read bio");

        cachep->write_bio = BIO_new(BIO_s_mem()); /* openssl writes to */

        if (!cachep->write_bio) {
            DIEHERE("failed to create the write bio");
            BIO_free(cachep->bio);
        }

        BIO_set_mem_eof_return(cachep->bio, -1);
        BIO_set_mem_eof_return(cachep->write_bio, -1);

        cachep->con = SSL_new(get_server_ctx());

        if (!cachep->con) {
            BIO_free(cachep->bio);
            BIO_free(cachep->write_bio);
            DIEHERE("failed to create the write bio");
        }
        
        /* turn on cookie exchange */
        /* XXX: we need to only create cache entries when cookies succeed */
        SSL_set_options(cachep->con, SSL_OP_COOKIE_EXCHANGE);

        /* set the bios that openssl should read from and write to */
        /* (and we'll do the opposite) */
        SSL_set_bio(cachep->con, cachep->bio, cachep->write_bio);
        SSL_set_accept_state(cachep->con);

    }

    return cachep;
}

static bio_cache *
find_or_create_bio_cache(int sock, struct sockaddr_in *from_addr,
                         int we_are_client) {
    bio_cache *cachep = find_bio_cache(from_addr);
    if (NULL == cachep) {
        /* none found; need to start a new context */
        cachep = start_new_cached_connection(sock, from_addr, we_are_client);
        if (NULL == cachep) {
            snmp_log(LOG_ERR, "failed to open a new dtls connection\n");
        }
    }
    return cachep;
}       

/*
 * You can write something into opaque that will subsequently get passed back 
 * to your send function if you like.  For instance, you might want to
 * remember where a PDU came from, so that you can send a reply there...  
 */

static int
netsnmp_dtlsudp_recv(netsnmp_transport *t, void *buf, int size,
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
            rc = netsnmp_udp_recvfrom(t->sock, buf, size, from, &fromlen,
                            &(addr_pair->local_addr), &(addr_pair->if_index));
#else
            rc = recvfrom(t->sock, buf, size, NETSNMP_DONTWAIT, from, &fromlen);
#endif /* linux && IP_PKTINFO */
	    if (rc < 0 && errno != EINTR) {
		break;
	    }
	}

        DEBUGMSGTL(("dtlsudp", "received %d raw bytes on way to dtls\n", rc));
        if (rc < 0) {
            DEBUGMSGTL(("dtlsudp", "recvfrom fd %d err %d (\"%s\")\n",
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
            
            DEBUGMSGTL(("dtlsudp", "received %d decoded bytes from dtls\n", rc));

            if (BIO_ctrl_pending(cachep->write_bio) > 0) {
                /* we have outgoing data to send; probably DTLS negotation */

                u_char outbuf[65535];
                int outsize;
                int rc2;
                
                /* for memory bios, we now read from openssl's write
                   buffer (ie, the packet to go out) and send it out
                   the udp port manually */
                outsize = BIO_read(cachep->write_bio, outbuf, sizeof(outbuf));
                if (outsize > 0) {
                    /* should always be true. */
#if defined(XXXFIXME) && defined(linux) && defined(IP_PKTINFO)
                /* XXX: before this can work, we need to remember address we
                   received it from (addr_pair) */
                    rc2 = netsnmp_udp_sendto(cachep->sock, addr_pair->local_addr,
                                    addr_pair->if_index, addr_pair->remote_addr,
                                    outbuf, outsize);
#else
                    rc2 = sendto(t->sock, outbuf, outsize, 0, &cachep->sockaddr, sizeof(struct sockaddr));
#endif /* linux && IP_PKTINFO */

                    if (rc2 == -1) {
                        snmp_log(LOG_ERR, "failed to send a DTLS specific packet\n");
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
                char *str = netsnmp_udp_fmtaddr(NULL, addr_pair, sizeof(netsnmp_indexed_addr_pair));
                DEBUGMSGTL(("dtlsudp",
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
                    DEBUGMSGTL(("dtlsudp", "got commonname: %s\n",
                                namebuf));
                    cachep->securityName = strdup(namebuf);
                    DEBUGMSGTL(("dtlsudp", "set SecName to: %s\n",
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
            DEBUGMSGTL(("dtlsudp", "recvfrom fd %d err %d (\"%s\")\n",
                        t->sock, errno, strerror(errno)));
        }
    }
    return rc;
}



static int
netsnmp_dtlsudp_send(netsnmp_transport *t, void *buf, int size,
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
        snmp_log(LOG_ERR, "dtlsudp_send: can't get address to send to\n");
        return -1;
    }

    to = (struct sockaddr *) &(addr_pair->remote_addr);

    if (NULL == to || NULL == t || t->sock <= 0) {
        snmp_log(LOG_ERR, "invalid netsnmp_dtlsudp_send usage\n");
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
        char *str = netsnmp_udp_fmtaddr(NULL, (void *) addr_pair,
                                        sizeof(netsnmp_indexed_addr_pair));
        DEBUGMSGTL(("dtlsudp", "send %d bytes from %p to %s on fd %d\n",
                    size, buf, str, t->sock));
        free(str);
    }
    rc = SSL_write(cachep->con, buf, size);
    if (rc < 0) {
        _openssl_log_error(rc, cachep->con, "SSL_write");
    }

    /* for memory bios, we now read from openssl's write buffer (ie,
       the packet to go out) and send it out the udp port manually */
    rc = BIO_read(cachep->write_bio, outbuf, sizeof(outbuf));
    if (rc <= 0) {
        /* in theory an ok thing */
        return 0;
    }
#if defined(FIXME) && defined(linux) && defined(IP_PKTINFO)
    /* XXX: before this can work, we need to remember address we
       received it from (addr_pair) */
    rc = netsnmp_udp_sendto(cachep->sock, &cachep->sockaddr  remote  addr_pair ? &(addr_pair->local_addr) : NULL, to, outbuf, rc);
#else
    rc = sendto(t->sock, outbuf, rc, 0, &cachep->sockaddr, sizeof(struct sockaddr));
#endif /* linux && IP_PKTINFO */

    return rc;
}



static int
netsnmp_dtlsudp_close(netsnmp_transport *t)
{
    /* XXX: issue a proper dtls closure notification(s) */

    return netsnmp_socketbase_close(t);
}

/*
 * Open a DTLS-based transport for SNMP.  Local is TRUE if addr is the local
 * address to bind to (i.e. this is a server-type session); otherwise addr is 
 * the remote address to send things to.  
 */

netsnmp_transport *
netsnmp_dtlsudp_transport(struct sockaddr_in *addr, int local)
{
    netsnmp_transport *t = NULL;
    
    t = netsnmp_udpipv4base_transport(addr, local);
    if (NULL == t) {
        return NULL;
    }

    if (!local) {
        /* dtls needs to bind the socket for SSL_write to work */
        if (connect(t->sock, (struct sockaddr *) addr, sizeof(*addr)) == -1)
            snmp_log(LOG_ERR, "dtls: failed to connect\n");
    }

    /* XXX: Potentially set sock opts here (SO_SNDBUF/SO_RCV_BUF) */      
    /* XXX: and buf size */        


    /*
     * Set Domain
     */
    t->domain = netsnmpDTLSUDPDomain;                                     
    t->domain_length = netsnmpDTLSUDPDomain_len;     

    /*
     * 16-bit length field, 8 byte DTLS header, 20 byte IPv4 header  
     */

    t->msgMaxSize = 0xffff - 8 - 20;
    t->f_recv     = netsnmp_dtlsudp_recv;
    t->f_send     = netsnmp_dtlsudp_send;
    t->f_close    = netsnmp_dtlsudp_close;
    t->f_accept   = NULL;
    t->f_fmtaddr  = netsnmp_udp_fmtaddr;
    t->flags = NETSNMP_TRANSPORT_FLAG_TUNNELED;

    return t;
}


void
netsnmp_dtlsudp_agent_config_tokens_register(void)
{
}




netsnmp_transport *
netsnmp_dtlsudp_create_tstring(const char *str, int local,
                               const char *default_target)
{
    struct sockaddr_in addr;

    if (netsnmp_sockaddr_in2(&addr, str, default_target)) {
        return netsnmp_dtlsudp_transport(&addr, local);
    } else {
        return NULL;
    }
}


netsnmp_transport *
netsnmp_dtlsudp_create_ostring(const u_char * o, size_t o_len, int local)
{
    struct sockaddr_in addr;

    if (o_len == 6) {
        unsigned short porttmp = (o[4] << 8) + o[5];
        addr.sin_family = AF_INET;
        memcpy((u_char *) & (addr.sin_addr.s_addr), o, 4);
        addr.sin_port = htons(porttmp);
        return netsnmp_dtlsudp_transport(&addr, local);
    }
    return NULL;
}

void
netsnmp_dtlsudp_ctor(void)
{
    DEBUGMSGTL(("dtlsudp", "registering DTLS constructor\n"));

    /* config settings */

    netsnmp_init_tlsbase();

    dtlsudpDomain.name = netsnmpDTLSUDPDomain;
    dtlsudpDomain.name_length = netsnmpDTLSUDPDomain_len;
    dtlsudpDomain.prefix = (const char**)calloc(2, sizeof(char *));
    dtlsudpDomain.prefix[0] = "dtlsudp";

    dtlsudpDomain.f_create_from_tstring_new = netsnmp_dtlsudp_create_tstring;
    dtlsudpDomain.f_create_from_ostring = netsnmp_dtlsudp_create_ostring;

    netsnmp_tdomain_register(&dtlsudpDomain);
}
