/*
 * HEADER Testing netsnmp_parse_ep_str()
 */

struct one_test_data {
    const char *in;
    int res;
    struct { const char *addr; const char *iface; const char *port; } expected;
};

static struct one_test_data test_data[] = {
    { "9999",              1, { "",         "",   "9999" } },
    { ":777",              1, { "",         "",   "777"  } },
    { "hostname:777",      1, { "hostname", "",   "777"  } },
    { "hostname",          1, { "hostname", "",   ""     } },
    { "1.2.3.4",           1, { "1.2.3.4",  "",   ""     } },
    { "hostname@if",       1, { "hostname", "if", ""     } },
    { "hostname@if:833",   1, { "hostname", "if", "833"  } },
    { "[hostname]@if:833", 1, { "hostname", "if", "833"  } },
    { "[hostname]?",       0, {                          } },
    { "[hostname",         0, {                          } },
    { "@if:844",           1, { "",         "if", "844"  } },
    { "::1",               1, { "::1",      "",   ""     } },
    { "::1@if",            1, { "::1",      "if", ""     } },
    { "1::2",              1, { "1::2",     "",   ""     } },
    { "[::1]",             1, { "::1",      "",   ""     } },
    { "[::1]:0",           1, { "::1",      "",   "0"    } },
    { "[::1]:2",           1, { "::1",      "",   "2"    } },
    { "[::1]@if:2",        1, { "::1",      "if", "2"    } },
    { "[::1]:2@if",        0, {                          } },
};

SOCK_STARTUP;

{
    int i;

    for (i = 0; i < sizeof(test_data) / sizeof(test_data[0]); i++) {
        const struct one_test_data *p = &test_data[i];
        struct netsnmp_ep_str ep_str;
        int res;

        memset(&ep_str, 0, sizeof(ep_str));
        res = netsnmp_parse_ep_str(&ep_str, p->in);
        OKF(res == p->res, ("%s: return value %d <> %d", p->in, res, p->res));
        if (res && p->res) {
            OKF((!ep_str.addr && !p->expected.addr[0]) ||
                strcmp(ep_str.addr,  p->expected.addr)  == 0,
                ("%s: network address %s <> %s", p->in, ep_str.addr,
                 p->expected.addr));
            OKF(strcmp(ep_str.iface, p->expected.iface) == 0,
                ("%s: network interface %s <> %s", p->in, ep_str.iface,
                 p->expected.iface));
            OKF(strcmp(ep_str.port, p->expected.port) == 0,
                ("%s: port %s <> %s", p->in, ep_str.port, p->expected.port));
        }
        free(ep_str.addr);
    }

    {
        extern int netsnmp_sockaddr_in3(struct netsnmp_ep *ep,
                                        const char *inpeername,
                                        const char *default_target);
        struct netsnmp_ep ep;

        OK(netsnmp_sockaddr_in3(&ep, NULL, "127.0.0.1:1161") == 1,
           "netsnmp_sockaddr_in3 NULL inpeername with default_target");
        OK(ep.a.sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
           ep.a.sin.sin_port == htons(1161),
           "netsnmp_sockaddr_in3 uses default_target addr and port");

        OK(netsnmp_sockaddr_in3(&ep, ":2161", "127.0.0.1:1161") == 1,
           "netsnmp_sockaddr_in3 port-only inpeername with default_target");
        OK(ep.a.sin.sin_addr.s_addr == htonl(INADDR_LOOPBACK) &&
           ep.a.sin.sin_port == htons(2161),
           "netsnmp_sockaddr_in3 preserves default_target addr on port override");
    }
#ifdef NETSNMP_ENABLE_IPV6
    {
        extern int netsnmp_sockaddr_in6_3(struct netsnmp_ep *ep,
                                          const char *inpeername,
                                          const char *default_target);
        struct netsnmp_ep ep6;

        OK(netsnmp_sockaddr_in6_3(&ep6, NULL, "[::1]:1161") == 1,
           "netsnmp_sockaddr_in6_3 NULL inpeername with default_target");
        OK(memcmp(&ep6.a.sin6.sin6_addr, &in6addr_loopback,
                  sizeof(in6addr_loopback)) == 0 &&
           ep6.a.sin6.sin6_port == htons(1161),
           "netsnmp_sockaddr_in6_3 uses default_target addr and port");

        OK(netsnmp_sockaddr_in6_3(&ep6, ":2161", "[::1]:1161") == 1,
           "netsnmp_sockaddr_in6_3 port-only inpeername with default_target");
        OK(memcmp(&ep6.a.sin6.sin6_addr, &in6addr_loopback,
                  sizeof(in6addr_loopback)) == 0 &&
           ep6.a.sin6.sin6_port == htons(2161),
           "netsnmp_sockaddr_in6_3 preserves default_target addr on port override");

        OK(netsnmp_sockaddr_in6_3(&ep6, "[fe80::2%1]@vrf0:1161", NULL) == 1,
           "netsnmp_sockaddr_in6_3 scoped address with interface");
        OK(strcmp(ep6.scope, "1") == 0 && strcmp(ep6.iface, "vrf0") == 0 &&
           ep6.a.sin6.sin6_port == htons(1161),
           "netsnmp_sockaddr_in6_3 separates scope and iface");
        {
            char long_scope[NETSNMP_IF_NAMESIZE + 16];
            char peer[sizeof(long_scope) + 32];

            memset(long_scope, 'a', sizeof(long_scope) - 1);
            long_scope[sizeof(long_scope) - 1] = '\0';
            snprintf(peer, sizeof(peer), "[fe80::2%%%s]:1161", long_scope);
            OK(netsnmp_sockaddr_in6_3(&ep6, peer, NULL) == 0,
               "netsnmp_sockaddr_in6_3 rejects a scope name that is too long");
        }
        OK(netsnmp_if_nametoindex("10g0") == 0,
           "netsnmp_if_nametoindex rejects absent digit-prefixed interface");
        OK(netsnmp_if_nametoindex("-1") == 0 &&
           netsnmp_if_nametoindex("+1") == 0 &&
           netsnmp_if_nametoindex(" 1") == 0 &&
           netsnmp_if_nametoindex("4294967297") == 0,
           "netsnmp_if_nametoindex rejects signed, padded and out-of-range indices");
        OK(netsnmp_if_nametoindex("4294967295") == 4294967295U,
           "netsnmp_if_nametoindex accepts UINT_MAX");
#if defined(NETSNMP_TRANSPORT_UDPIPV6_DOMAIN) && \
    defined(HAVE_STRUCT_SOCKADDR_IN6_SIN6_SCOPE_ID)
        {
            netsnmp_transport *t;

            OK(netsnmp_sockaddr_in6_3(&ep6, "[::1%1]:1161", NULL) == 1,
               "netsnmp_sockaddr_in6_3 [::1%1]:1161");
            t = netsnmp_udp6_transport(&ep6, 0);
            if (t) {
                netsnmp_scoped_addr_pair *scoped_pair = t->data;
                char *fmt;
                int rc;

                OK(t->data_length == sizeof(*scoped_pair) &&
                   strcmp(scoped_pair->remote_scope, "1") == 0 &&
                   scoped_pair->addr_pair.remote_addr.sin6.sin6_scope_id == 1,
                   "netsnmp_udp6_transport stores remote_scope");

                /* Numeric scopes are not re-resolved. */
                scoped_pair->addr_pair.remote_addr.sin6.sin6_scope_id = 9999;
                (void)t->f_send(t, "x", 1, NULL, NULL);
                OK(scoped_pair->addr_pair.remote_addr.sin6.sin6_scope_id == 9999,
                   "netsnmp_udp6_send does not re-resolve a numeric scope");

#if defined(HAVE_IF_INDEXTONAME) && defined(HAVE_IF_NAMETOINDEX)
                {
                    char ifname[NETSNMP_IF_NAMESIZE];

                    if (if_indextoname(1, ifname)) {
                        /*
                         * Simulate interface recreation assigning a new
                         * ifindex.
                         */
                        scoped_pair->addr_pair.remote_addr.sin6.sin6_scope_id =
                            9999;
                        ((struct sockaddr_in6 *)t->remote)->sin6_scope_id =
                            9999;
                        strlcpy(scoped_pair->remote_scope, ifname,
                                sizeof(scoped_pair->remote_scope));
                        (void)t->f_send(t, "x", 1, NULL, NULL);
                        OK(scoped_pair->addr_pair.remote_addr.sin6.sin6_scope_id == 1 &&
                           ((struct sockaddr_in6 *)t->remote)->sin6_scope_id == 1,
                           "netsnmp_udp6_send refreshes stale sin6_scope_id from remote_scope");
                    }
                }
#endif

                /* Simulate missing scoped interface. */
                strlcpy(scoped_pair->remote_scope, "nonexistent0",
                        sizeof(scoped_pair->remote_scope));
                errno = 0;
                rc = t->f_send(t, "x", 1, NULL, NULL);
                OK(rc == -1 && errno == EINVAL &&
                   scoped_pair->addr_pair.remote_addr.sin6.sin6_scope_id == 0 &&
                   ((struct sockaddr_in6 *)t->remote)->sin6_scope_id == 0,
                   "netsnmp_udp6_send fails with EINVAL when remote_scope does not exist");

                fmt = t->f_fmtaddr(t, NULL, 0);
                OK(fmt != NULL &&
                   strstr(fmt, "[::1%nonexistent0]:1161") != NULL,
                   "netsnmp_udp6_fmtaddr formats unresolved remote_scope");
                free(fmt);

                t->f_close(t);
                netsnmp_transport_free(t);
            }
        }
#endif
    }
#endif
}

SOCK_CLEANUP;
