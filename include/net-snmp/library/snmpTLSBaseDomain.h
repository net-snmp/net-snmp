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

#define NETSNMP_TLSBASE_IS_CLIENT 0x01

    /*
     * _Internal_ structures
     */
    typedef struct _netsnmpTLSBaseData_s {
       int     flags;
       SSL_CTX *ssl_context;
       SSL     *ssl;
       BIO     *sslbio;
       BIO     *accept_bio;
       BIO     *accepted_bio;
       char    *securityName;
       struct sockaddr_in addr;
    } _netsnmpTLSBaseData;

    _netsnmpTLSBaseData *netsnmp_tlsbase_allocate_tlsdata(netsnmp_transport *t,
                                                          int isserver);
    int netsnmp_tlsbase_wrapup_recv(netsnmp_tmStateReference *tmStateRef,
                                    _netsnmpTLSBaseData *tlsdata,
                                    void **opaque, int *olength);
#ifdef __cplusplus
}
#endif
#endif/*_SNMPTLSBASEDOMAIN_H*/
