/*
 * Header file for the OpenSSL Wrapper
 */

#ifndef SNMP_OPENSSL_H
#define SNMP_OPENSSL_H

#ifdef __cplusplus
extern          "C" {
#endif

    void netsnmp_init_openssl(void);

    void netsnmp_openssl_cert_dump_names(X509 *xcert);

    char *netsnmp_openssl_cert_get_commonName(X509 *xcert, char **buf,
                                              int *len);
    char *netsnmp_openssl_cert_get_subjectName(X509 *xcert, char **buf,
                                               int *len);

#ifdef __cplusplus
}
#endif
#endif                          /* SNMP_OPENSSL_H */
