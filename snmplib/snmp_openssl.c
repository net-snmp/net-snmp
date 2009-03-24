/*
 * snmptsmsm.c
 *
 * This code merely does openssl initialization so that multilpe
 * modules are safe to call netsnmp_init_openssl() for bootstrapping
 * without worrying about other callers that may have already done so.
 */

#include <net-snmp/net-snmp-config.h>

#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/library/snmp_openssl.h>

#if defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL)

#include <openssl/evp.h>
#include <openssl/ssl.h>

static u_char have_started_already = 0;

void netsnmp_init_openssl(void) {

    /* avoid duplicate calls */
    if (have_started_already)
        return;
    have_started_already = 1;

    DEBUGMSGTL(("snmp_openssl", "initializing\n"));

    /* Initializing OpenSSL */
    SSL_library_init();
    SSL_load_error_strings();
    ERR_load_BIO_strings();
    OpenSSL_add_all_algorithms();
}

#endif /* NETSNMP_USE_OPENSSL && HAVE_LIBSSL */
