#ifndef _SNMPTLSBASEDOMAIN_H
#define _SNMPTLSBASEDOMAIN_H

#ifdef __cplusplus
extern          "C" {
#endif

#include <net-snmp/library/snmp_transport.h>
#include <net-snmp/library/asn1.h>

/*
 * Prototypes
 */

    void netsnmp_init_tlsbase(void);
    const char * _x509_get_error(int x509failvalue, const char *location);

    /* will likely go away */
    SSL_CTX *get_client_ctx(void);
    SSL_CTX *get_server_ctx(void);

#ifdef __cplusplus
}
#endif
#endif/*_SNMPTLSBASEDOMAIN_H*/
