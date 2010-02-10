#ifndef SNMPUDPBASEDOMAIN_H
#define SNMPUDPBASEDOMAIN_H

#ifdef __cplusplus
extern          "C" {
#endif

/*
 * Prototypes
 */
    void _netsnmp_udp_sockopt_set(int fd, int local);
    int netsnmp_udpbase_recv(netsnmp_transport *t, void *buf, int size,
                             void **opaque, int *olength);
    int netsnmp_udpbase_send(netsnmp_transport *t, void *buf, int size,
                             void **opaque, int *olength);

#endif /* SNMPUDPBASEDOMAIN_H */
