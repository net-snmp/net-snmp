/*
 * Header file for the OpenSSL Wrapper
 */

#ifndef SNMP_OPENSSL_H
#define SNMP_OPENSSL_H

#include <openssl/dh.h>

#ifdef __cplusplus
extern          "C" {
#endif

    NETSNMP_IMPORT
    void netsnmp_init_openssl(void);

    NETSNMP_IMPORT
    int DH_set0_pqg(DH *dh, BIGNUM *p, BIGNUM *q, BIGNUM *g);
    NETSNMP_IMPORT
    void DH_get0_pqg(const DH *dh, const BIGNUM **p, const BIGNUM **q,
                     const BIGNUM **g);
    NETSNMP_IMPORT
    void DH_get0_key(const DH *dh, const BIGNUM **pub_key,
                     const BIGNUM **priv_key);

#ifdef __cplusplus
}
#endif
#endif                          /* SNMP_OPENSSL_H */
