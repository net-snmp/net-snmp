#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
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
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_debug.h"
#include "snmp_logging.h"
#include "default_store.h"
#include "snmp_transport.h"
#include "snmpUnixDomain.h"


#ifndef SNMP_STREAM_QUEUE_LEN
#define SNMP_STREAM_QUEUE_LEN  5
#endif

#ifndef SUN_LEN
/*  Evaluate to actual length of the `sockaddr_un' structure.  */
#define SUN_LEN(ptr) ((size_t) (((struct sockaddr_un *) 0)->sun_path)         \
                      + strlen ((ptr)->sun_path))
#endif

const oid ucdSnmpUnixDomain[9] = { UCDAVIS_MIB, 251, 2 };
static snmp_tdomain unixDomain;


/*  This is the structure we use to hold transport-specific data.  */

typedef struct _sockaddr_un_pair {
  int			local;
  struct sockaddr_un	server;
  struct sockaddr_un	client;
} sockaddr_un_pair;


/*  Return a string representing the address in data, or else the "far end"
    address if data is NULL.  */

char	       *snmp_unix_fmtaddr	(snmp_transport *t,
					 void *data, int len)
{
  struct sockaddr_un *to = NULL;

  if (data != NULL) {
    to = (struct sockaddr_un *)data;
  } else if (t != NULL && t->data != NULL) {
    to = &(((sockaddr_un_pair *)t->data)->server);
    len = SUN_LEN(to);
  }
  if (to == NULL) {
    /*  "Local IPC" is the Posix.1g term for Unix domain protocols, according
	to W. R. Stevens, ``Unix Network Programming Volume I Second
	Edition'', p. 374.  */
    return strdup("Local IPC: unknown");
  } else if (to->sun_path[0] == 0) {
    /*  This is an abstract name.  We could render it as hex or something but
	let's not worry about that for now.  */
    return strdup("Local IPC: abstract");
  } else {
    char *tmp = (char *)malloc(16 + len);
    if (tmp != NULL) {
      sprintf(tmp, "Local IPC: %s", to->sun_path);
    }
    return tmp;
  }
}



/*  You can write something into opaque that will subsequently get passed back 
    to your send function if you like.  For instance, you might want to
    remember where a PDU came from, so that you can send a reply there...  */

int		snmp_unix_recv	(snmp_transport *t, void *buf, int size,
				 void **opaque, int *olength) 
{
  int rc = -1;

  *opaque  = NULL;
  *olength = 0;
  if (t != NULL && t->sock >= 0) {
    rc = recv(t->sock, buf, size, 0);
    DEBUGMSGTL(("snmp_unix_recv", "recv fd %d got %d bytes\n", t->sock, rc));
    return rc;
  } else {
    return -1;
  }
}



int		snmp_unix_send	(snmp_transport *t, void *buf, int size,
				 void **opaque, int *olength)
{
  int rc = 0;

  if (t != NULL && t->sock >= 0) {
    DEBUGMSGTL(("snmp_unix_send", "%d bytes from %p on fd %d\n",
		size, buf, t->sock));
    rc = send(t->sock, buf, size, 0);
    return rc;
  } else {
    return -1;
  }
}



int		snmp_unix_close	(snmp_transport *t)
{
  int rc = 0;
  sockaddr_un_pair *sup = (sockaddr_un_pair *)t->data;

  if (t->sock >= 0) {
#ifndef HAVE_CLOSESOCKET
    rc = close(t->sock);
#else
    rc = closesocket(t->sock);
#endif
    t->sock = -1;
    if (sup != NULL) {
      if (sup->local) {
	DEBUGMSGTL(("snmp_unix_close", "server unlink(\"%s\")\n",
		    sup->server.sun_path));
	unlink(sup->server.sun_path);
      } else {
	DEBUGMSGTL(("snmp_unix_close", "client unlink(\"%s\")\n",
		    sup->client.sun_path));
	unlink(sup->client.sun_path);
      }
    }
    return rc;
  } else {
    return -1;
  }
}



int		snmp_unix_accept	(snmp_transport *t)
{
  struct sockaddr *farend = NULL;
  int newsock = -1, farendlen = sizeof(struct sockaddr_un);

  farend = (struct sockaddr *)malloc(farendlen);

  if (farend == NULL) {
    /*  Indicate that the acceptance of this socket failed.  */
    DEBUGMSGTL(("snmp_unix_accept", "malloc failed\n"));
    return -1;
  }
  memset(farend, 0, farendlen);

  if (t != NULL && t->sock >= 0) {
    newsock = accept(t->sock, farend, &farendlen);

    if (newsock < 0) {
      DEBUGMSGTL(("snmp_unix_accept", "accept failed rc %d errno %d \"%s\"\n",
		  newsock, errno, strerror(errno)));
      free(farend);
      return newsock;
    }

    if (t->data != NULL) {
      free(t->data);
    }

    DEBUGMSGTL(("snmp_unix_accept", "accept succeeded (farend %p len %d)\n",
		farend, farendlen));
    t->data = farend;
    t->data_length = sizeof(struct sockaddr_un);
    return newsock;
  } else {
    free(farend);
    return -1;
  }
}



/*  Open a Unix-domain transport for SNMP.  Local is TRUE if addr is the local 
    address to bind to (i.e. this is a server-type session); otherwise addr is 
    the remote address to send things to (and we make up a temporary name for
    the local end of the connection).  */

snmp_transport		*snmp_unix_transport	(struct sockaddr_un *addr,
						 int local)
{
  snmp_transport *t = NULL;
  sockaddr_un_pair *sup = NULL;
  int rc = 0;
  char *string = NULL;

  if (addr == NULL || addr->sun_family != AF_UNIX) {
    return NULL;
  }

  t = (snmp_transport *)malloc(sizeof(snmp_transport));
  if (t == NULL) {
    return NULL;
  }

  string = snmp_unix_fmtaddr(NULL, (void *)addr, sizeof(struct sockaddr_un));
  DEBUGMSGTL(("snmp_unix", "open %s %s\n", local?"local":"remote", string));
  free(string);

  memset(t, 0, sizeof(snmp_transport));

  t->domain = ucdSnmpUnixDomain;
  t->domain_length = sizeof(ucdSnmpUnixDomain)/sizeof(ucdSnmpUnixDomain[0]);

  t->data = malloc(sizeof(sockaddr_un_pair));
  if (t->data == NULL) {
    snmp_transport_free(t);
    return NULL;
  }
  memset(t->data, 0, sizeof(sockaddr_un_pair));
  t->data_length = sizeof(sockaddr_un_pair);
  sup = (sockaddr_un_pair *)t->data;

  t->sock = socket(PF_UNIX, SOCK_STREAM, 0);
  if (t->sock < 0) {
    snmp_transport_free(t);
    return NULL;
  }

  t->flags = SNMP_TRANSPORT_FLAG_STREAM;

  if (local) {
    t->local = malloc(strlen(addr->sun_path));
    if (t->local == NULL) {
      snmp_transport_free(t);
      return NULL;
    }
    memcpy(t->local, addr->sun_path, strlen(addr->sun_path));
    t->local_length = strlen(addr->sun_path);

    /*  This session is inteneded as a server, so we must bind to the given
	path (unlinking it first, to avoid errors).  */

    t->flags |= SNMP_TRANSPORT_FLAG_LISTEN;

    unlink(addr->sun_path);
    rc = bind(t->sock, (struct sockaddr *)addr, SUN_LEN(addr));
    if (rc != 0) {
      DEBUGMSGTL(("snmp_unix_transport",
		  "couldn't bind \"%s\", errno %d (%s)\n",
		  addr->sun_path, errno, strerror(errno)));
      snmp_unix_close(t);
      snmp_transport_free(t);
      return NULL;
    }
    
    /*  Save the address in the transport-specific data pointer for later use
	by snmp_unix_close.  */

    sup->server.sun_family = AF_UNIX;
    strcpy(sup->server.sun_path, addr->sun_path);
    sup->local = 1;

    /*  Now sit here and listen for connections to arrive.  */

    rc = listen(t->sock, SNMP_STREAM_QUEUE_LEN);
    if (rc != 0) {
      DEBUGMSGTL(("snmp_unix_transport",
		  "couldn't listen to \"%s\", errno %d (%s)\n",
		  addr->sun_path, errno, strerror(errno)));
      snmp_unix_close(t);
      snmp_transport_free(t);
    }

  } else {
    t->remote = malloc(strlen(addr->sun_path));
    if (t->remote == NULL) {
      snmp_transport_free(t);
      return NULL;
    }
    memcpy(t->remote, addr->sun_path, strlen(addr->sun_path));
    t->remote_length = strlen(addr->sun_path);

    rc = connect(t->sock, (struct sockaddr *)addr, sizeof(struct sockaddr_un));
    if (rc != 0) {
      DEBUGMSGTL(("snmp_unix_transport",
		  "couldn't connect to \"%s\", errno %d (%s)\n",
		  addr->sun_path, errno, strerror(errno)));
      snmp_unix_close(t);
      snmp_transport_free(t);
      return NULL;
    }

    /*  Save the remote address in the transport-specific data pointer for
	later use by snmp_unix_send.  */

    sup->server.sun_family = AF_UNIX;
    strcpy(sup->server.sun_path, addr->sun_path);
    sup->local = 0;
  }

  /*  Message size is not limited by this transport (hence msgMaxSize
      is equal to the maximum legal size of an SNMP message).  */

  t->msgMaxSize  = 0x7fffffff;
  t->f_recv      = snmp_unix_recv;
  t->f_send      = snmp_unix_send;
  t->f_close     = snmp_unix_close;
  t->f_accept    = snmp_unix_accept;
  t->f_fmtaddr   = snmp_unix_fmtaddr;

  return t;
}

snmp_transport	*snmp_unix_create		(const char *string, int local)
{
  struct sockaddr_un addr;

  if ((string != NULL) && (strlen(string) < sizeof(addr.sun_path))) {
    addr.sun_family = AF_UNIX;
    memset(addr.sun_path, 0, sizeof(addr.sun_path));
    strncpy(addr.sun_path, string, sizeof(addr.sun_path) - 1);
    return snmp_unix_transport(&addr, local);
  } else {
    if (string != NULL) {
      snmp_log(LOG_ERR, "Path too long for Unix domain transport\n");
    }
    return NULL;
  }
}

void		snmp_unix_ctor			(void)
{
  unixDomain.name        = ucdSnmpUnixDomain;
  unixDomain.name_length = sizeof(ucdSnmpUnixDomain)/sizeof(oid);
  unixDomain.f_create    = snmp_unix_create;
  unixDomain.prefix      = calloc(2, sizeof(char *));
  unixDomain.prefix[0]   = "unix";

  snmp_tdomain_register(&unixDomain);
}
