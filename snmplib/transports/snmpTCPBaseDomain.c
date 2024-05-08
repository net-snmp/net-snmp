#include <net-snmp/net-snmp-config.h>

#include <net-snmp/types.h>
#include <net-snmp/library/snmpTCPBaseDomain.h>

#include <stdio.h>
#include <sys/types.h>
#include <errno.h>

#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <net-snmp/types.h>
#include <net-snmp/output_api.h>

#include <net-snmp/library/snmp_transport.h>

/*
 * You can write something into opaque that will subsequently get passed back 
 * to your send function if you like.  For instance, you might want to
 * remember where a PDU came from, so that you can send a reply there...  
 */

int netsnmp_tcpbase_recv(netsnmp_transport *t, void *buf, int size,
                         void **opaque, int *olength)
{
    int rc = -1;

    if (t != NULL && t->sock >= 0) {
	while (rc < 0) {
	    rc = recvfrom(t->sock, buf, size, 0, NULL, NULL);
	    if (rc < 0 && errno != EINTR) {
		DEBUGMSGTL(("netsnmp_tcpbase", "recv fd %d err %d (\"%s\")\n",
			    t->sock, errno, strerror(errno)));
		break;
	    }
	    DEBUGMSGTL(("netsnmp_tcpbase", "recv fd %d got %d bytes\n",
			t->sock, rc));
	}
    } else {
        return -1;
    }

    if (opaque != NULL && olength != NULL) {
        if (t->data_length > 0) {
            if ((*opaque = malloc(t->data_length)) != NULL) {
                memcpy(*opaque, t->data, t->data_length);
                *olength = t->data_length;
            } else {
                *olength = 0;
            }
        } else {
            *opaque = NULL;
            *olength = 0;
        }
    }

    return rc;
}

int netsnmp_tcpbase_send(netsnmp_transport *t, const void *buf, int size,
                         void **opaque, int *olength) {
    int rc = -1;

    if (t != NULL && t->sock >= 0) {
	while (rc < 0) {
	    rc = sendto(t->sock, buf, size, 0, NULL, 0);
	    if (rc < 0 && errno != EINTR) {
		break;
	    }
	}
    }
    return rc;
}


int netsnmp_tcpbase_session_init(struct netsnmp_transport_s *transport,
                                 struct snmp_session *sess) {
    if (!sess) {
        DEBUGMSGTL(("netsnmp_tcpbase", "session pointer is NULL\n"));
        return SNMPERR_SUCCESS;
    }
    
    union {
        struct sockaddr     sa;
        struct sockaddr_in  sin;
        struct sockaddr_in6 sin6;
    } ss;
    socklen_t len = sizeof(ss);
    if (getsockname(transport->sock, (struct sockaddr *)&ss, &len) == -1) {
        DEBUGMSGTL(("netsnmp_tcpbase", "getsockname error %s\n", strerror(errno)));
        return SNMPERR_SUCCESS;
    }
    switch (ss.sa.sa_family) {
    case AF_INET:
        sess->local_port = ntohs(ss.sin.sin_port);
        break;
    case AF_INET6:
        sess->local_port = ntohs(ss.sin6.sin6_port);
        break;
    default:
        DEBUGMSGTL(("netsnmp_tcpbase", "unsupported address family %d\n",
                    ss.sa.sa_family));
        return SNMPERR_SUCCESS;
    }
    
    DEBUGMSGTL(("netsnmp_tcpbase", "local port number %d\n", sess->local_port));
    
    return SNMPERR_SUCCESS;
}
