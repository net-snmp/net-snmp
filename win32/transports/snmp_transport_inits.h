#ifdef NETSNMP_ENABLE_IPV6
netsnmp_udpipv6_ctor();
netsnmp_tcpipv6_ctor();
#endif
netsnmp_udp_ctor();
netsnmp_tcp_ctor();
/*netsnmp_alias_ctor();*/
