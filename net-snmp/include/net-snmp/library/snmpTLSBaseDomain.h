#ifndef _SNMPTLSBASEDOMAIN_H
#define _SNMPTLSBASEDOMAIN_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/asn1.h>

/* OpenSSL Includes */
#include "openssl/bio.h"
#include "openssl/ssl.h"
#include "openssl/err.h"

/*
 * Prototypes
 */

    void netsnmp_init_tlsbase(void);
    const char * _x509_get_error(int x509failvalue, const char *location);
    void _openssl_log_error(int rc, SSL *con, const char *location);

    /* will likely go away */
    SSL_CTX *get_client_ctx(void);
    SSL_CTX *get_server_ctx(void);

    SSL_CTX *sslctx_client_setup(SSL_METHOD *);
    SSL_CTX *sslctx_server_setup(SSL_METHOD *);

    /*
     * _Internal_ structures
     */
    typedef struct _netsnmpTLSBaseData_s {
       char     isclient;
       SSL_CTX *ssl_context;
       SSL     *ssl;
       BIO     *sslbio;
       BIO     *accept_bio;
       char    *securityName;
    } _netsnmpTLSBaseData;

#ifdef __cplusplus
}
#endif
#endif/*_SNMPTLSBASEDOMAIN_H*/
