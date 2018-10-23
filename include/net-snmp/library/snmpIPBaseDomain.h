#ifndef _SNMPIPBASEDOMAIN_H_
#define _SNMPIPBASEDOMAIN_H_

/**
 * SNMP endpoint with the network name in ASCII format.
 * @addr: Network address or host name as an ASCII string.
 * @port: Port number in host byte format.
 */
struct netsnmp_ep_str {
    char     addr[64];
    uint16_t port;
};

int netsnmp_parse_ep_str(struct netsnmp_ep_str *ep_str, const char *endpoint);

#endif /* _SNMPIPBASEDOMAIN_H_ */
