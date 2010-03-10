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

void init_cert_util(void);
void shutdown_certs(void);


#ifdef __cplusplus
}
#endif

#endif /* NETSNMP_CERT_UTIL_H */

