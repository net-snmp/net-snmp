#ifndef SNMPTRAPD_AUTH_H
#define SNMPTRAPD_AUTH_H

void init_netsnmp_trapd_auth(void);
int netsnmp_trapd_auth(netsnmp_pdu *pdu, netsnmp_transport *transport,
                       netsnmp_trapd_handler *handler);


#endif /* SNMPTRAPD_AUTH_H */
