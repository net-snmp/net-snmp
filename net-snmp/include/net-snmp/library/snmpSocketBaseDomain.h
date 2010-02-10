#ifndef SNMPSOCKETBASEDOMAIN_H
#define SNMPSOCKETBASEDOMAIN_H

#ifdef __cplusplus
extern          "C" {
#endif

/*
 * Prototypes
 */
    int netsnmp_socketbase_close(netsnmp_transport *t);
    int netsnmp_sock_buffer_set(int s, int optname, int local, int size);

#endif /* SNMPSOCKETBASEDOMAIN_H */
