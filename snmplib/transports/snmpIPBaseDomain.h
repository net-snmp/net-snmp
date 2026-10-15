#ifndef _SNMPIPBASEDOMAIN_H_
#define _SNMPIPBASEDOMAIN_H_

#include <net-snmp/types.h>
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif
#include <net-snmp/library/snmp_transport.h>

/*
 * Size of a buffer that can hold a network interface name, including the
 * terminating '\0'.
 */
#if defined(IF_NAMESIZE) && IF_NAMESIZE > 16
#define NETSNMP_IF_NAMESIZE IF_NAMESIZE
#else
#define NETSNMP_IF_NAMESIZE 16
#endif

/**
 * SNMP endpoint specification.
 * @param a     Address family, network address and port number.
 * @param iface Network interface name in ASCII format. May be empty.
 * @param scope IPv6 scope (zone) interface name in ASCII format. May be empty.
 */
struct netsnmp_ep {
    union {
        struct sockaddr_in  sin;
#if defined(NETSNMP_TRANSPORT_UDPIPV6_DOMAIN) || \
    defined(NETSNMP_TRANSPORT_TCPIPV6_DOMAIN)
        struct sockaddr_in6 sin6;
#endif
    } a;
    char iface[16];
    char scope[NETSNMP_IF_NAMESIZE];
};

typedef struct netsnmp_scoped_addr_pair_s {
    netsnmp_indexed_addr_pair addr_pair;
    char remote_scope[NETSNMP_IF_NAMESIZE];
} netsnmp_scoped_addr_pair;

/**
 * SNMP endpoint with the network name in ASCII format.
 * @param addr Network address or host name as an ASCII string.
 * @param iface Network interface, e.g. "lo".
 * @param port Port number. "" means that no port number has been specified. "0"
 *   means "bind to any port".
 */
struct netsnmp_ep_str {
    char     *addr;
    char     iface[16];
    char     port[6];
};

struct netsnmp_transport_s;

int netsnmp_parse_ep_str(struct netsnmp_ep_str *ep_str, const char *endpoint);
int netsnmp_bindtodevice(NETSNMP_SOCKET sock, const char *iface);
void netsnmp_bind_ep_iface(NETSNMP_SOCKET sock, const struct netsnmp_ep *ep,
                           const char *token);
unsigned netsnmp_if_nametoindex(const char *ifname);
int netsnmp_ipbase_session_init(struct netsnmp_transport_s *transport,
                                struct snmp_session *sess);

#endif /* _SNMPIPBASEDOMAIN_H_ */
