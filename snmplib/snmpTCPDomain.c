#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "asn1.h"
#include "snmp_debug.h"
#include "snmp_transport.h"
#include "snmpUDPDomain.h"
#include "snmpTCPDomain.h"


#ifndef SNMP_STREAM_QUEUE_LEN
#define SNMP_STREAM_QUEUE_LEN  5
#endif


const oid snmpTCPDomain[8] = { 1, 3, 6, 1, 3, 91, 1, 1 };
static snmp_tdomain tcpDomain;


/*  Return a string representing the address in data, or else the "far end"
    address if data is NULL.  */

char	       *snmp_tcp_fmtaddr	(snmp_transport *t,
					 void *data, int len)
{
  struct sockaddr_in *to = NULL;

  if (data != NULL && len == sizeof(struct sockaddr_in)) {
    to = (struct sockaddr_in *)data;
  } else if (t != NULL && t->data != NULL &&
	     t->data_length == sizeof(struct sockaddr_in)) {
    to = (struct sockaddr_in *)t->data;
  }
  if (to == NULL) {
    return strdup("TCP: unknown");
  } else {
    char tmp[32];

    /*  Here we just print the IP address of the peer for compatibility
	purposes.  It would be nice if we could include the port number and
	some indication of the domain (c.f. AAL5PVC).  */

    sprintf(tmp, "%s", inet_ntoa(to->sin_addr));
    return strdup(tmp);
  }
}



/*  You can write something into opaque that will subsequently get passed back 
    to your send function if you like.  For instance, you might want to
    remember where a PDU came from, so that you can send a reply there...  */

int		snmp_tcp_recv	(snmp_transport *t, void *buf, int size,
				 void **opaque, int *olength)
{
  int rc = 0;

  if (t != NULL && t->sock >= 0) {
    rc = recv(t->sock, buf, size, 0);
    DEBUGMSGTL(("snmp_tcp_recv", "recv fd %d got %d bytes\n", t->sock, rc));
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
      *opaque  = NULL;
      *olength = 0;
    }
  }

  return rc;
}



int		snmp_tcp_send	(snmp_transport *t, void *buf, int size,
				 void **opaque, int *olength)
{
  int rc = 0;

  if (t != NULL && t->sock >= 0) {
    rc = send(t->sock, buf, size, 0);
  } else {
    return -1;
  }
  return rc;
}



int		snmp_tcp_close	(snmp_transport *t)
{
  int rc = 0;
  if (t != NULL && t->sock >= 0) {
    DEBUGMSGTL(("snmp_tcp_close", "fd %d\n", t->sock));
#ifndef HAVE_CLOSESOCKET
    rc = close(t->sock);
#else
    rc = closesocket(t->sock);
#endif
    t->sock = -1;
    return rc;
  } else {
    return -1;
  }
}



int		snmp_tcp_accept	(snmp_transport *t)
{
  struct sockaddr *farend = NULL;
  int newsock = -1, farendlen = sizeof(struct sockaddr_in), sockflags = 0;
  char *string = NULL;

  farend = (struct sockaddr *)malloc(sizeof(struct sockaddr_in));

  if (farend == NULL) {
    /*  Indicate that the acceptance of this socket failed.  */
    DEBUGMSGTL(("snmp_tcp_accept", "malloc failed\n"));
    return -1;
  }

  if (t != NULL && t->sock >= 0) {
    newsock = accept(t->sock, farend, &farendlen);

    if (newsock < 0) {
      DEBUGMSGTL(("snmp_tcp_accept", "accept failed\n"));
      free(farend);
      return newsock;
    }

    if (t->data != NULL) {
      free(t->data);
    }

    t->data = farend;
    t->data_length = farendlen;
    string = snmp_tcp_fmtaddr(NULL, farend, farendlen);
    DEBUGMSGTL(("snmp_tcp_accept", "accept succeeded (from %s)\n", string));
    free(string);

    /*  Try to make the new socket blocking.  */

#ifdef WIN32
    ioctlsocket(newsock, FIONBIO, &sockflags);
#else
    if ((sockflags = fcntl(newsock, F_GETFL, 0)) >= 0) {
      fcntl(newsock, F_SETFL, (sockflags & ~O_NONBLOCK));
    } else {
      DEBUGMSGTL(("snmp_tcp_accept", "couldn't f_getfl of fd %d\n", newsock));
    }
#endif

    return newsock;
  } else {
    free(farend);
    return -1;
  }
}



/*  Open a TCP-based transport for SNMP.  Local is TRUE if addr is the local
    address to bind to (i.e. this is a server-type session); otherwise addr is 
    the remote address to send things to.  */

snmp_transport		*snmp_tcp_transport	(struct sockaddr_in *addr,
						 int local)
{
  snmp_transport *t = NULL;
  int rc = 0;


  if (addr == NULL || addr->sin_family != AF_INET) {
    return NULL;
  }

  t = (snmp_transport *)malloc(sizeof(snmp_transport));
  if (t == NULL) {
    return NULL;
  }
  memset(t, 0, sizeof(snmp_transport));

  t->data = malloc(sizeof(struct sockaddr_in));
  if (t->data == NULL) {
    snmp_transport_free(t);
    return NULL;
  }
  t->data_length = sizeof(struct sockaddr_in);
  memcpy(t->data, addr, sizeof(struct sockaddr_in));

  t->domain = snmpTCPDomain;
  t->domain_length = sizeof(snmpTCPDomain)/sizeof(snmpTCPDomain[0]);

  t->sock = socket(PF_INET, SOCK_STREAM, 0);
  if (t->sock < 0) {
    snmp_transport_free(t);
    return NULL;
  }

  t->flags = SNMP_TRANSPORT_FLAG_STREAM;

  if (local) {
    int sockflags = 0, opt = 1;
    
    /*  This session is inteneded as a server, so we must bind to the given 
	IP address (which may include an interface address, or could be
	INADDR_ANY, but will always include a port number.  */
    
    t->flags |= SNMP_TRANSPORT_FLAG_LISTEN;
    t->local = malloc(6);
    if (t->local == NULL) {
      snmp_transport_free(t);
      return NULL;
    }
    memcpy(t->local, (u_char *)&(addr->sin_addr.s_addr), 4);
    t->local[4] = (addr->sin_port & 0xff00) >> 8;
    t->local[5] = (addr->sin_port & 0x00ff) >> 0;
    t->local_length = 6;

    /*  We should set SO_REUSEADDR too.  */
    
    setsockopt(t->sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    rc = bind(t->sock, (struct sockaddr *)addr, sizeof(struct sockaddr));
    if (rc != 0) {
      snmp_tcp_close(t);
      snmp_transport_free(t);
      return NULL;
    }

    /*  Since we are going to be letting select() tell us when connections are 
	ready to be accept()ed, we need to make the socket n0n-blocking to
	avoid the race condition described in W. R. Stevens, ``Unix Network
	Programming Volume I Second Edition'', pp. 422--4, which could
	otherwise wedge the agent.  */

#ifdef WIN32
    opt = 1;
    ioctlsocket(t->sock, FIONBIO, &opt);
#else
    sockflags = fcntl(t->sock, F_GETFL, 0);
    fcntl(t->sock, F_SETFL, sockflags | O_NONBLOCK);
#endif

    /*  Now sit here and wait for connections to arrive.  */

    rc = listen(t->sock, SNMP_STREAM_QUEUE_LEN);
    if (rc != 0) {
      snmp_tcp_close(t);
      snmp_transport_free(t);
      return NULL;
    }
  } else {
    t->remote = malloc(6);
    if (t->remote == NULL) {
      snmp_transport_free(t);
      return NULL;
    }
    memcpy(t->remote, (u_char *)&(addr->sin_addr.s_addr), 4);
    t->remote[4] = (addr->sin_port & 0xff00) >> 8;
    t->remote[5] = (addr->sin_port & 0x00ff) >> 0;
    t->remote_length = 6;

    /*  This is a client-type session, so attempt to connect to the far end.
	We don't go non-blocking here because it's not obvious what you'd then
	do if you tried to do snmp_sends before the connection had completed.
	So this can block.  */

    rc = connect(t->sock, (struct sockaddr *)addr, sizeof(struct sockaddr));

    if (rc < 0) {
      snmp_tcp_close(t);
      snmp_transport_free(t);
      return NULL;
    }
  }

  /*  Message size is not limited by this transport (hence msgMaxSize
      is equal to the maximum legal size of an SNMP message).  */

  t->msgMaxSize  = 0x7fffffff;
  t->f_recv      = snmp_tcp_recv;
  t->f_send      = snmp_tcp_send;
  t->f_close     = snmp_tcp_close;
  t->f_accept    = snmp_tcp_accept;
  t->f_fmtaddr   = snmp_tcp_fmtaddr;

  return t;
}



snmp_transport	*snmp_tcp_create		(const char *string, int local)
{
  struct sockaddr_in addr;

  if (snmp_sockaddr_in(&addr, string, 0)) {
    return snmp_tcp_transport(&addr, local);
  } else {
    return NULL;
  }
}



void		snmp_tcp_ctor			(void)
{
  tcpDomain.name        = snmpTCPDomain;
  tcpDomain.name_length = sizeof(snmpTCPDomain)/sizeof(oid);
  tcpDomain.f_create	= snmp_tcp_create;
  tcpDomain.prefix      = calloc(2, sizeof(char *));
  tcpDomain.prefix[0]   = "tcp";

  snmp_tdomain_register(&tcpDomain);
}
