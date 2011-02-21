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

#if HAVE_WINSOCK_H
#include <winsock2.h>
#include <ws2tcpip.h>
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

#ifdef  MSG_DONTWAIT
#define NETSNMP_DONTWAIT MSG_DONTWAIT
#else
#define NETSNMP_DONTWAIT 0
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

/*
 * cached SSL context information
 * (in theory we may want more than one per client/server but it's
 * unlikely and a CPU and memory waste unless we do need more than one)
 */
SSL_CTX *client_ctx, *server_ctx;

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

static const char * _x509_get_error(int x509failvalue, const char *location) {
    static const char *reason = NULL;
    
    /* XXX: use this instead: X509_verify_cert_error_string(err) */

    switch (x509failvalue) {
    case X509_V_OK:
        reason = "X509_V_OK";
        break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        reason = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT";
        break;
    case X509_V_ERR_UNABLE_TO_GET_CRL:
        reason = "X509_V_ERR_UNABLE_TO_GET_CRL";
        break;
    case X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE:
        reason = "X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE";
        break;
    case X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE:
        reason = "X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE";
        break;
    case X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY:
        reason = "X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY";
        break;
    case X509_V_ERR_CERT_SIGNATURE_FAILURE:
        reason = "X509_V_ERR_CERT_SIGNATURE_FAILURE";
        break;
    case X509_V_ERR_CRL_SIGNATURE_FAILURE:
        reason = "X509_V_ERR_CRL_SIGNATURE_FAILURE";
        break;
    case X509_V_ERR_CERT_NOT_YET_VALID:
        reason = "X509_V_ERR_CERT_NOT_YET_VALID";
        break;
    case X509_V_ERR_CERT_HAS_EXPIRED:
        reason = "X509_V_ERR_CERT_HAS_EXPIRED";
        break;
    case X509_V_ERR_CRL_NOT_YET_VALID:
        reason = "X509_V_ERR_CRL_NOT_YET_VALID";
        break;
    case X509_V_ERR_CRL_HAS_EXPIRED:
        reason = "X509_V_ERR_CRL_HAS_EXPIRED";
        break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD:
        reason = "X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD";
        break;
    case X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD:
        reason = "X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD";
        break;
    case X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD:
        reason = "X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD";
        break;
    case X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD:
        reason = "X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD";
        break;
    case X509_V_ERR_OUT_OF_MEM:
        reason = "X509_V_ERR_OUT_OF_MEM";
        break;
    case X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT:
        reason = "X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT";
        break;
    case X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN:
        reason = "X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN";
        break;
    case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        reason = "X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY";
        break;
    case X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE:
        reason = "X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE";
        break;
    case X509_V_ERR_CERT_CHAIN_TOO_LONG:
        reason = "X509_V_ERR_CERT_CHAIN_TOO_LONG";
        break;
    case X509_V_ERR_CERT_REVOKED:
        reason = "X509_V_ERR_CERT_REVOKED";
        break;
    case X509_V_ERR_INVALID_CA:
        reason = "X509_V_ERR_INVALID_CA";
        break;
    case X509_V_ERR_PATH_LENGTH_EXCEEDED:
        reason = "X509_V_ERR_PATH_LENGTH_EXCEEDED";
        break;
    case X509_V_ERR_INVALID_PURPOSE:
        reason = "X509_V_ERR_INVALID_PURPOSE";
        break;
    case X509_V_ERR_CERT_UNTRUSTED:
        reason = "X509_V_ERR_CERT_UNTRUSTED";
        break;
    case X509_V_ERR_CERT_REJECTED:
        reason = "X509_V_ERR_CERT_REJECTED";
        break;
    case X509_V_ERR_SUBJECT_ISSUER_MISMATCH:
        reason = "X509_V_ERR_SUBJECT_ISSUER_MISMATCH";
        break;
    case X509_V_ERR_AKID_SKID_MISMATCH:
        reason = "X509_V_ERR_AKID_SKID_MISMATCH";
        break;
    case X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH:
        reason = "X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH";
        break;
    case X509_V_ERR_KEYUSAGE_NO_CERTSIGN:
        reason = "X509_V_ERR_KEYUSAGE_NO_CERTSIGN";
        break;
    case X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER:
        reason = "X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER";
        break;
    case X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION:
        reason = "X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION";
        break;
    case X509_V_ERR_KEYUSAGE_NO_CRL_SIGN:
        reason = "X509_V_ERR_KEYUSAGE_NO_CRL_SIGN";
        break;
    case X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION:
        reason = "X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION";
        break;
    case X509_V_ERR_INVALID_NON_CA:
        reason = "X509_V_ERR_INVALID_NON_CA";
        break;
    case X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED:
        reason = "X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED";
        break;
    case X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE:
        reason = "X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE";
        break;
    case X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED:
        reason = "X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED";
        break;
    case X509_V_ERR_INVALID_EXTENSION:
        reason = "X509_V_ERR_INVALID_EXTENSION";
        break;
    case X509_V_ERR_INVALID_POLICY_EXTENSION:
        reason = "X509_V_ERR_INVALID_POLICY_EXTENSION";
        break;
    case X509_V_ERR_NO_EXPLICIT_POLICY:
        reason = "X509_V_ERR_NO_EXPLICIT_POLICY";
        break;
    case X509_V_ERR_UNNESTED_RESOURCE:
        reason = "X509_V_ERR_UNNESTED_RESOURCE";
        break;
    case X509_V_ERR_APPLICATION_VERIFICATION:
        reason = "X509_V_ERR_APPLICATION_VERIFICATION";
    default:
        reason = "unknown failure code";
    }

    return reason;
}

int verify_callback(int ok, X509_STORE_CTX *ctx) {
    int err, depth;
    char buf[1024];
    X509 *thecert;

    thecert = X509_STORE_CTX_get_current_cert(ctx);
    err = X509_STORE_CTX_get_error(ctx);
    depth = X509_STORE_CTX_get_error_depth(ctx);
    
    /* things to do: */

    X509_NAME_oneline(X509_get_subject_name(thecert), buf, sizeof(buf));
    DEBUGMSGTL(("dtlsudp_x509",
                "Cert: %s\n", buf));


    DEBUGMSGTL(("dtlsudp_x509",
                " verify value: %d, depth=%d, error code=%d, error string=%s\n",
                ok, depth, err, _x509_get_error(err, "verify callback")));

    /* check if we allow self-signed certs */
    if (netsnmp_ds_get_boolean(NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_ALLOW_SELF_SIGNED) &&
        (X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT == err ||
         X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN == err)) {
        DEBUGMSGTL(("dtlsudp_x509", "  accepting a self-signed certificate\n"));
        return 1;
    }
    
    
    DEBUGMSGTL(("dtlsudp_x509", "  returing the passed in value of %d\n", ok));
    return(ok);
}

static void _openssl_log_error(int rc, SSL *con, const char *location) {
    const char *reason;

    if (rc == -1) {
        int sslnum = SSL_get_error(con, rc);

        switch(sslnum) {
        case SSL_ERROR_NONE:
            reason = "SSL_ERROR_NONE";
            break;

        case SSL_ERROR_SSL:
            reason = "SSL_ERROR_SSL";
            break;

        case SSL_ERROR_WANT_READ:
            reason = "SSL_ERROR_WANT_READ";
            break;

        case SSL_ERROR_WANT_WRITE:
            reason = "SSL_ERROR_WANT_WRITE";
            break;

        case SSL_ERROR_WANT_X509_LOOKUP:
            reason = "SSL_ERROR_WANT_X509_LOOKUP";
            break;

        case SSL_ERROR_SYSCALL:
            reason = "SSL_ERROR_SYSCALL";
            snmp_log(LOG_ERR, "DTLS error: %s: rc=%d, sslerror = %d (%s): system_error=%d (%s)\n",
                     location, rc, sslnum, reason, errno, strerror(errno));
            return;

        case SSL_ERROR_ZERO_RETURN:
            reason = "SSL_ERROR_ZERO_RETURN";
            break;

        case SSL_ERROR_WANT_CONNECT:
            reason = "SSL_ERROR_WANT_CONNECT";
            break;

        case SSL_ERROR_WANT_ACCEPT:
            reason = "SSL_ERROR_WANT_ACCEPT";
            break;
            
        default:
            reason = "unknown";
        }

        snmp_log(LOG_ERR, "DTLS error: %s: rc=%d, sslerror = %d (%s)\n",
                 location, rc, sslnum, reason);
    }
}

/* XXX: lots of malloc/state cleanup needed */
#define DIEHERE(msg) { snmp_log(LOG_ERR, "%s\n", msg); return NULL; }

static bio_cache *
start_new_cached_connection(int sock, struct sockaddr_in *remote_addr,
                            int we_are_client) {
    bio_cache *cachep = NULL;

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
        cachep->con = SSL_new(client_ctx);

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

        cachep->con = SSL_new(server_ctx);

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
    netsnmp_addr_pair *addr_pair = NULL;
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
            rc = netsnmp_udp_recvfrom(t->sock, buf, size, from, &fromlen, &(addr_pair->local_addr));
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
                    rc2 = netsnmp_udp_sendto(cachep->sock, addr_pair->local_addr, addr_pair->remote_addr, outbuf, outsize);
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
                char *str = netsnmp_udp_fmtaddr(NULL, addr_pair, sizeof(netsnmp_addr_pair));
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
    netsnmp_addr_pair *addr_pair = NULL;
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
                 t->data_length == sizeof(netsnmp_addr_pair))
            addr_pair = (netsnmp_addr_pair *) (t->data);
    } else if (t != NULL && t->data != NULL &&
               t->data_length == sizeof(netsnmp_addr_pair)) {
        addr_pair = (netsnmp_addr_pair *) (t->data);
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
                                        sizeof(netsnmp_addr_pair));
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
    int rc = -1;
    /* XXX: issue a proper dtls closure notification(s) */
    if (t->sock >= 0) {
#ifndef HAVE_CLOSESOCKET
        rc = close(t->sock);
#else
        rc = closesocket(t->sock);
#endif
        t->sock = -1;
    }
    return rc;
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
    int             rc = 0;
    char           *str = NULL;
    char           *client_socket = NULL;
    netsnmp_addr_pair addr_pair;

    if (addr == NULL || addr->sin_family != AF_INET) {
        return NULL;
    }

    memset(&addr_pair, 0, sizeof(netsnmp_addr_pair));
    memcpy(&(addr_pair.remote_addr), addr, sizeof(struct sockaddr_in));

    t = SNMP_MALLOC_TYPEDEF(netsnmp_transport);
    if (t == NULL) {
        return NULL;
    }

    str = netsnmp_udp_fmtaddr(NULL, (void *)&addr_pair,
                                 sizeof(netsnmp_addr_pair));
    DEBUGMSGTL(("dtlsudp", "open %s %s\n", local ? "local" : "remote",
                str));
    free(str);

    t->domain = netsnmpDTLSUDPDomain;
    t->domain_length = netsnmpDTLSUDPDomain_len;

    t->sock = socket(PF_INET, SOCK_DGRAM, 0);
    DEBUGMSGTL(("dtlsudp", "openned socket %d as local=%d\n", t->sock,
                local));
    if (t->sock < 0) {
        netsnmp_transport_free(t);
        return NULL;
    }

    /* XXX: Potentially set sock opts here (SO_SNDBUF/SO_RCV_BUF) */
    /* XXX: and buf size */
    _netsnmp_udp_sockopt_set(t->sock, local);

    if (local) {
        /*
         * This session is inteneded as a server, so we must bind on to the
         * given IP address, which may include an interface address, or could
         * be INADDR_ANY, but certainly includes a port number.
         */

      t->local = (u_char *) malloc(6);
        if (t->local == NULL) {
            netsnmp_transport_free(t);
            return NULL;
        }
        memcpy(t->local, (u_char *) & (addr->sin_addr.s_addr), 4);
        t->local[4] = (htons(addr->sin_port) & 0xff00) >> 8;
        t->local[5] = (htons(addr->sin_port) & 0x00ff) >> 0;
        t->local_length = 6;

#if defined(linux) && defined(IP_PKTINFO)
        { 
            int sockopt = 1;
            if (setsockopt(t->sock, SOL_IP, IP_PKTINFO, &sockopt, sizeof sockopt) == -1) {
                DEBUGMSGTL(("dtlsudp", "couldn't set IP_PKTINFO: %s\n",
                    strerror(errno)));
                netsnmp_transport_free(t);
                return NULL;
            }
            DEBUGMSGTL(("dtlsudp", "set IP_PKTINFO\n"));
        }
#endif
        rc = bind(t->sock, (struct sockaddr *) addr,
                  sizeof(struct sockaddr));
        if (rc != 0) {
            netsnmp_dtlsudp_close(t);
            netsnmp_transport_free(t);
            return NULL;
        }
        t->data = NULL;
        t->data_length = 0;
    } else {
        /*
         * This is a client session.  If we've been given a
         * client address to send from, then bind to that.
         * Otherwise the send will use "something sensible".
         */
        client_socket = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                              NETSNMP_DS_LIB_CLIENT_ADDR);
        if (client_socket) {
            struct sockaddr_in client_addr;
            netsnmp_sockaddr_in2(&client_addr, client_socket, NULL);
            addr_pair.local_addr = client_addr.sin_addr;
            client_addr.sin_port = 0;
            DEBUGMSGTL(("dtlsudp", "binding socket: %d\n", t->sock));
            rc = bind(t->sock, (struct sockaddr *)&client_addr,
                  sizeof(struct sockaddr));
            if ( rc != 0 ) {
                DEBUGMSGTL(("dtlsudp", "failed to bind for clientaddr: %d %s\n",
                            errno, strerror(errno)));
                netsnmp_dtlsudp_close(t);
                netsnmp_transport_free(t);
                return NULL;
            }
        }

        str = netsnmp_udp_fmtaddr(NULL, (void *)&addr_pair,
                 sizeof(netsnmp_addr_pair));
        DEBUGMSGTL(("dtlsudp", "client open %s\n", str));
        free(str);

        /*
         * Save the (remote) address in the
         * transport-specific data pointer for later use by netsnmp_dtlsudp_send.
         */

        t->data = SNMP_MALLOC_TYPEDEF(netsnmp_addr_pair);
        t->remote = (u_char *)malloc(6);
        if (t->data == NULL || t->remote == NULL) {
            netsnmp_transport_free(t);
            return NULL;
        }
        memcpy(t->remote, (u_char *) & (addr->sin_addr.s_addr), 4);
        t->remote[4] = (htons(addr->sin_port) & 0xff00) >> 8;
        t->remote[5] = (htons(addr->sin_port) & 0x00ff) >> 0;
        t->remote_length = 6;
        memcpy(t->data, &addr_pair, sizeof(netsnmp_addr_pair));
        t->data_length = sizeof(netsnmp_addr_pair);

        /* dtls needs to bind the socket for SSL_write to work */
        if (connect(t->sock, (struct sockaddr *) addr, sizeof(*addr)) == -1)
            snmp_log(LOG_ERR, "dtls: failed to connect\n");

    }

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

#define LOGANDDIE(msg) { snmp_log(LOG_ERR, "%s\n", msg); return 0; }

static int have_done_init = 0;

static int
dtlsudp_bootstrap(int majorid, int minorid, void *serverarg, void *clientarg) {
    const char *certfile;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    BIO *keybio = NULL;

    /* don't do this more than once */
    if (have_done_init)
        return 0;
    have_done_init = 1;

    /***********************************************************************
     * Set up the client context
     */
    client_ctx = SSL_CTX_new(DTLSv1_client_method());
    if (!client_ctx) {
        LOGANDDIE("can't create a new context");
    }
    SSL_CTX_set_read_ahead (client_ctx, 1); /* Required for DTLS */
        
    SSL_CTX_set_verify(client_ctx,
                       SSL_VERIFY_PEER|
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
                       SSL_VERIFY_CLIENT_ONCE,
                       &verify_callback);

    keybio = BIO_new(BIO_s_file());
    if (!keybio)
        LOGANDDIE ("error creating bio for reading public key");

    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_CLIENT_PUB);

    DEBUGMSGTL(("dtlsudp", "using public key: %s\n", certfile));
    if (BIO_read_filename(keybio, certfile) <=0)
        LOGANDDIE ("error reading public key");

    cert = PEM_read_bio_X509_AUX(keybio, NULL, NULL, NULL);
    if (!cert)
        LOGANDDIE("failed to load public key");

    /* XXX: mem leak on previous keybio? */

    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_CLIENT_PRIV);

    keybio = BIO_new(BIO_s_file());
    if (!keybio)
        LOGANDDIE ("error creating bio for reading private key");

    DEBUGMSGTL(("dtlsudp", "using private key: %s\n", certfile));
    if (!keybio ||
        BIO_read_filename(keybio, certfile) <= 0)
        LOGANDDIE ("error reading private key");

    key = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    
    if (!key)
        LOGANDDIE("failed to load private key");


    if (SSL_CTX_use_certificate(client_ctx, cert) <= 0)
        LOGANDDIE("failed to set the certificate to use");

    if (SSL_CTX_use_PrivateKey(client_ctx, key) <= 0)
        LOGANDDIE("failed to set the private key to use");

    if (!SSL_CTX_check_private_key(client_ctx))
        LOGANDDIE("public and private keys incompatible");
    

    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_SERVER_CERTS);

    /* XXX: also need to match individual cert to indiv. host */

    if(! SSL_CTX_load_verify_locations(client_ctx, certfile, NULL)) {
        LOGANDDIE("failed to load truststore");
        /* Handle failed load here */
    }

    if (!SSL_CTX_set_default_verify_paths(client_ctx)) {
        LOGANDDIE ("failed to set default verify path");
    }

    /***********************************************************************
     * Set up the server context
     */
    /* setting up for ssl */
    server_ctx = SSL_CTX_new(DTLSv1_server_method());
    if (!server_ctx) {
        LOGANDDIE("can't create a new context");
    }

    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_SERVER_PUB);

    if (SSL_CTX_use_certificate_file(server_ctx, certfile,
                                     SSL_FILETYPE_PEM) < 1) {
        LOGANDDIE("faild to load cert");
    }
    
    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_SERVER_PRIV);

    if (SSL_CTX_use_PrivateKey_file(server_ctx, certfile, SSL_FILETYPE_PEM) < 1) {
        LOGANDDIE("faild to load key");
    }

    SSL_CTX_set_read_ahead(server_ctx, 1);


    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_CLIENT_CERTS);
    if(! SSL_CTX_load_verify_locations(server_ctx, certfile, NULL)) {
        LOGANDDIE("failed to load truststore");
        /* Handle failed load here */
    }

    SSL_CTX_set_verify(server_ctx,
                       SSL_VERIFY_PEER|
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
                       SSL_VERIFY_CLIENT_ONCE,
                       &verify_callback);

    return 0;
}


void
netsnmp_dtlsudp_ctor(void)
{
    DEBUGMSGTL(("dtlsudp", "registering DTLS constructor\n"));

    /* config settings */

    /* bootstrap ssl since we'll need it */
    netsnmp_init_openssl();

    /*
     * for the client
     */

    /* pem file of valid server CERT CAs */
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defX509ServerCerts",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_X509_SERVER_CERTS);

    /* the public client cert to authenticate with */
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defX509ClientPub",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_X509_CLIENT_PUB);

    /* the private client cert to authenticate with */
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defX509ClientPriv",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_X509_CLIENT_PRIV);

    /*
     * for the server
     */

    /* The list of valid client keys to accept (or CAs I think) */
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defX509ClientCerts",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_X509_CLIENT_CERTS);

    /* The X509 server key to use */
    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defX509ServerPub",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_X509_SERVER_PUB);

    netsnmp_ds_register_config(ASN_OCTET_STR, "snmp", "defX509ServerPriv",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_X509_SERVER_PRIV);

    netsnmp_ds_register_config(ASN_BOOLEAN, "snmp", "AllowSelfSignedX509",
                               NETSNMP_DS_LIBRARY_ID,
                               NETSNMP_DS_LIB_ALLOW_SELF_SIGNED);

    /*
     * register our boot-strapping needs
     */
    snmp_register_callback(SNMP_CALLBACK_LIBRARY,
			   SNMP_CALLBACK_POST_READ_CONFIG,
			   dtlsudp_bootstrap, NULL);

    dtlsudpDomain.name = netsnmpDTLSUDPDomain;
    dtlsudpDomain.name_length = netsnmpDTLSUDPDomain_len;
    dtlsudpDomain.prefix = (const char**)calloc(2, sizeof(char *));
    dtlsudpDomain.prefix[0] = "dtlsudp";

    dtlsudpDomain.f_create_from_tstring_new = netsnmp_dtlsudp_create_tstring;
    dtlsudpDomain.f_create_from_ostring = netsnmp_dtlsudp_create_ostring;

    netsnmp_tdomain_register(&dtlsudpDomain);
}
