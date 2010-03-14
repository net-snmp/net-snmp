#ifndef NETSNMP_CERT_UTIL_H

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

#endif /* NETSNMP_CERT_UTIL_H */

