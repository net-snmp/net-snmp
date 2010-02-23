#include <net-snmp/net-snmp-config.h>

#if HAVE_DMALLOC_H
#include <dmalloc.h>
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
#include <errno.h>

/* OpenSSL Includes */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

#include <net-snmp/types.h>
#include <net-snmp/library/snmpTLSBaseDomain.h>
#include <net-snmp/library/snmp_openssl.h>
#include <net-snmp/library/default_store.h>
#include <net-snmp/library/callback.h>
#include <net-snmp/library/snmp_logging.h>
#include <net-snmp/library/snmp_api.h>
#include <net-snmp/library/snmp_debug.h>

#define LOGANDDIE(msg) { snmp_log(LOG_ERR, "%s\n", msg); return 0; }

/*
 * cached SSL context information
 * (in theory we may want more than one per client/server but it's
 * unlikely and a CPU and memory waste unless we do need more than one)
 */
SSL_CTX *client_ctx, *server_ctx;

SSL_CTX *get_client_ctx(void) {
    return client_ctx;
}

SSL_CTX *get_server_ctx(void) {
    return server_ctx;
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

SSL_CTX *
sslctx_client_setup(SSL_METHOD *method) {
    BIO *keybio = NULL;
    X509 *cert = NULL;
    const char *certfile;
    EVP_PKEY *key = NULL;
    SSL_CTX *the_ctx;

    /***********************************************************************
     * Set up the client context
     */
    the_ctx = SSL_CTX_new(method);
    if (!the_ctx) {
        snmp_log(LOG_ERR, "ack: %x\n", the_ctx);
        LOGANDDIE("can't create a new context");
    }
    SSL_CTX_set_read_ahead (the_ctx, 1); /* Required for DTLS */
        
    SSL_CTX_set_verify(the_ctx,
                       SSL_VERIFY_PEER|
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
                       SSL_VERIFY_CLIENT_ONCE,
                       &verify_callback);

    keybio = BIO_new(BIO_s_file());
    if (!keybio)
        LOGANDDIE ("error creating bio for reading public key");

    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_CLIENT_PUB);

    DEBUGMSGTL(("sslctx_client", "using public key: %s\n", certfile));
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

    DEBUGMSGTL(("sslctx_client", "using private key: %s\n", certfile));
    if (!keybio ||
        BIO_read_filename(keybio, certfile) <= 0)
        LOGANDDIE ("error reading private key");

    key = PEM_read_bio_PrivateKey(keybio, NULL, NULL, NULL);
    
    if (!key)
        LOGANDDIE("failed to load private key");


    if (SSL_CTX_use_certificate(the_ctx, cert) <= 0)
        LOGANDDIE("failed to set the certificate to use");

    if (SSL_CTX_use_PrivateKey(the_ctx, key) <= 0)
        LOGANDDIE("failed to set the private key to use");

    if (!SSL_CTX_check_private_key(the_ctx))
        LOGANDDIE("public and private keys incompatible");
    

    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_SERVER_CERTS);

    /* XXX: also need to match individual cert to indiv. host */

    if(! SSL_CTX_load_verify_locations(the_ctx, certfile, NULL)) {
        LOGANDDIE("failed to load truststore");
        /* Handle failed load here */
    }

    if (!SSL_CTX_set_default_verify_paths(the_ctx)) {
        LOGANDDIE ("failed to set default verify path");
    }

    return the_ctx;
}

SSL_CTX *
sslctx_server_setup(SSL_METHOD *method) {
    const char *certfile;

    /***********************************************************************
     * Set up the server context
     */
    /* setting up for ssl */
    SSL_CTX *the_ctx = SSL_CTX_new(method);
    if (!the_ctx) {
        LOGANDDIE("can't create a new context");
    }

    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_SERVER_PUB);

    if (SSL_CTX_use_certificate_file(the_ctx, certfile,
                                     SSL_FILETYPE_PEM) < 1) {
        LOGANDDIE("faild to load cert");
    }
    
    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_SERVER_PRIV);

    if (SSL_CTX_use_PrivateKey_file(the_ctx, certfile, SSL_FILETYPE_PEM) < 1) {
        LOGANDDIE("faild to load key");
    }

    SSL_CTX_set_read_ahead(the_ctx, 1); /* XXX: DTLS only? */


    certfile = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                     NETSNMP_DS_LIB_X509_CLIENT_CERTS);
    if(! SSL_CTX_load_verify_locations(the_ctx, certfile, NULL)) {
        LOGANDDIE("failed to load truststore");
        /* Handle failed load here */
    }

    SSL_CTX_set_verify(the_ctx,
                       SSL_VERIFY_PEER|
                       SSL_VERIFY_FAIL_IF_NO_PEER_CERT|
                       SSL_VERIFY_CLIENT_ONCE,
                       &verify_callback);

    return the_ctx;
}

static int have_done_bootstrap = 0;

static int
tls_bootstrap(int majorid, int minorid, void *serverarg, void *clientarg) {
    const char *certfile;
    EVP_PKEY *key = NULL;
    X509 *cert = NULL;
    BIO *keybio = NULL;

    /* don't do this more than once */
    if (have_done_bootstrap)
        return 0;
    have_done_bootstrap = 1;

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

static int have_inited = 0;
void
netsnmp_init_tlsbase(void) {

    /* bootstrap ssl since we'll need it */
    netsnmp_init_openssl();

    /* only do this once */
    if (have_inited)
        return;
    have_inited = 1;

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
			   tls_bootstrap, NULL);

}

const char * _x509_get_error(int x509failvalue, const char *location) {
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

void _openssl_log_error(int rc, SSL *con, const char *location) {
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
            snmp_log(LOG_ERR, "TLS error: %s: rc=%d, sslerror = %d (%s): system_error=%d (%s)\n",
                     location, rc, sslnum, reason, errno, strerror(errno));
            snmp_log(LOG_ERR, "TLS Error: %s\n",
                     ERR_reason_error_string(ERR_get_error()));
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

        snmp_log(LOG_ERR, "TLS error: %s: rc=%d, sslerror = %d (%s)\n",
                 location, rc, sslnum, reason);

        snmp_log(LOG_ERR, "TLS Error: %s\n",
                 ERR_reason_error_string(ERR_get_error()));
    }
}
