#ifndef NETSNMP_CERT_UTIL_H

#if defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL)

#include <net-snmp/types.h>

#ifdef  __cplusplus
extern "C" {
#endif

    /*************************************************************************
     *
     * function pointer definitions
     *
     *************************************************************************/

void netsnmp_certs_init(void);
void netsnmp_certs_shutdown(void);


#ifdef __cplusplus
}
#endif

#endif /* defined(NETSNMP_USE_OPENSSL) && defined(HAVE_LIBSSL) */

#endif /* NETSNMP_CERT_UTIL_H */

