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
#include <atm.h>

#include "asn1.h"
#include "snmp.h"
#include "snmp_debug.h"
#include "default_store.h"
#include "snmp_transport.h"
#include "snmpAAL5PVCDomain.h"


const oid ucdSnmpAAL5PVCDomain[9] = { UCDAVIS_MIB, 251, 3 };
static snmp_tdomain aal5pvcDomain;


/*  Return a string representing the address in data, or else the "far end"
    address if data is NULL.  */

char	       *snmp_aal5pvc_fmtaddr	(snmp_transport *t,
					 void *data, int len)
{
  struct sockaddr_atmpvc *to = NULL;

  if (data != NULL && len == sizeof(struct sockaddr_atmpvc)) {
    to = (struct sockaddr_atmpvc *)data;
  } else if (t != NULL && t->data != NULL &&
	     t->data_length == sizeof(struct sockaddr_atmpvc)) {
    to = (struct sockaddr_atmpvc *)t->data;
  }
  if (to == NULL) {
    return strdup("AAL5 PVC: unknown");
  } else {
    char tmp[64];
    sprintf(tmp, "AAL5 PVC: %hd.%hd.%d", to->sap_addr.itf, to->sap_addr.vpi,
	    to->sap_addr.vci);
    return strdup(tmp);
  }
}



/*  You can write something into opaque that will subsequently get passed back 
    to your send function if you like.  For instance, you might want to
    remember where a PDU came from, so that you can send a reply there...  */

int		snmp_aal5pvc_recv(snmp_transport *t, void *buf, int size,
				  void **opaque, int *olength) 
{
  int rc = -1;

  if (t != NULL && t->sock >= 0) {
    rc = recv(t->sock, buf, size, 0);

    if (rc >= 0) {
      char *string = snmp_aal5pvc_fmtaddr(t, NULL, 0);
      DEBUGMSGTL(("snmp_aal5pvc_recv","recv on fd %d got %d bytes (from %s)\n",
		  t->sock, rc, string));
      free(string);
    } else {
      DEBUGMSGTL(("snmp_aal5pvc_recv", "recv on fd %d FAILED (rc %d)\n",
		  t->sock, rc));
    }
    *opaque  = NULL;
    *olength = 0;
  }
  return rc;
}



int		snmp_aal5pvc_send(snmp_transport *t, void *buf, int size,
				  void **opaque, int *olength)
{
  int rc = 0;
  struct sockaddr *to = NULL;

  if (opaque != NULL && *opaque != NULL &&
      *olength == sizeof(struct sockaddr_atmpvc)) {
    to = (struct sockaddr *)(*opaque);
  } else if (t != NULL && t->data != NULL &&
	     t->data_length == sizeof(struct sockaddr_atmpvc)) {
    to = (struct sockaddr *)(t->data);
  }

  if (to != NULL && t != NULL && t->sock >= 0) {
    char *string = NULL;
    string = snmp_aal5pvc_fmtaddr(NULL, (void *)to,
				  sizeof(struct sockaddr_atmpvc));
    DEBUGMSGTL(("snmp_aal5pvc_send", "%d bytes from %p to %s on fd %d\n",
		size, buf, string, t->sock));
    free(string);
    rc = send(t->sock, buf, size, 0);
    return rc;
  } else {
    return -1;
  }
}



int		snmp_aal5pvc_close	(snmp_transport *t)
{
  int rc = 0;

  if (t->sock >= 0) {
    DEBUGMSGTL(("snmp_aal5pvc", "close fd %d\n", t->sock));
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



/*  Open an AAL5 PVC transport for SNMP.  Local is TRUE if addr is the local 
    NSAP to bind to (i.e. this is a server-type session); otherwise addr is 
    the remote NSAP to send things to.  */

snmp_transport		*snmp_aal5pvc_transport	(struct sockaddr_atmpvc *addr,
						 int local)
{
  char *string = NULL;
  struct atm_qos qos;
  snmp_transport *t = NULL;

  if (addr == NULL || addr->sap_family != AF_ATMPVC) {
    return NULL;
  }

  t = (snmp_transport *)malloc(sizeof(snmp_transport));
  if (t == NULL) {
    return NULL;
  }

  string = snmp_aal5pvc_fmtaddr(NULL, (void *)addr,
				sizeof(struct sockaddr_atmpvc));
  DEBUGMSGTL(("snmp_aal5pvc", "open %s %s\n", local?"local":"remote", string));
  free(string);

  memset(t, 0, sizeof(snmp_transport));

  t->domain = ucdSnmpAAL5PVCDomain;
  t->domain_length =
    sizeof(ucdSnmpAAL5PVCDomain)/sizeof(ucdSnmpAAL5PVCDomain[0]);

  t->sock = socket(PF_ATMPVC, SOCK_DGRAM, 0);
  if (t->sock < 0) {
    DEBUGMSGTL(("snmp_aal5pvc", "socket failed (%s)\n", strerror(errno)));
    snmp_transport_free(t);
    return NULL;
  }
  DEBUGMSGTL(("snmp_aal5pvc", "fd %d opened\n", t->sock));

  /*  Set up the QOS parameters.  */

  memset(&qos, 0, sizeof(struct atm_qos));
  qos.aal = ATM_AAL5;
  qos.rxtp.traffic_class = ATM_UBR;
  qos.rxtp.max_sdu = SNMP_MAX_LEN;  /*  Hmm -- this is a bit small?  */
  qos.txtp = qos.rxtp;

  if (setsockopt(t->sock, SOL_ATM, SO_ATMQOS, &qos, sizeof(qos)) < 0) {
    DEBUGMSGTL(("snmp_aal5pvc", "setsockopt failed (%s)\n", strerror(errno)));
    snmp_aal5pvc_close(t);
    snmp_transport_free(t);
    return NULL;
  }

  if (local) {
    t->local = malloc(8);
    if (t->local == NULL) {
      snmp_transport_free(t);
      return NULL;
    }
    t->local[0] = (addr->sap_addr.itf & 0xff00) >> 8;
    t->local[1] = (addr->sap_addr.itf & 0x00ff) >> 0;
    t->local[2] = (addr->sap_addr.vpi & 0xff00) >> 8;
    t->local[3] = (addr->sap_addr.vpi & 0x00ff) >> 0;
    t->local[4] = (addr->sap_addr.vci & 0xff000000) >> 24;
    t->local[5] = (addr->sap_addr.vci & 0x00ff0000) >> 16;
    t->local[6] = (addr->sap_addr.vci & 0x0000ff00) >>  8;
    t->local[7] = (addr->sap_addr.vci & 0x000000ff) >>  0;
    t->local_length = 8;

    if (bind(t->sock, (struct sockaddr *)addr,
	     sizeof(struct sockaddr_atmpvc)) < 0) {
      DEBUGMSGTL(("snmp_aal5pvc", "bind failed (%s)\n", strerror(errno)));
      snmp_aal5pvc_close(t);
      snmp_transport_free(t);
      return NULL;      
    }
  } else {
    t->remote = malloc(8);
    if (t->remote == NULL) {
      snmp_transport_free(t);
      return NULL;
    }
    t->remote[0] = (addr->sap_addr.itf & 0xff00) >> 8;
    t->remote[1] = (addr->sap_addr.itf & 0x00ff) >> 0;
    t->remote[2] = (addr->sap_addr.vpi & 0xff00) >> 8;
    t->remote[3] = (addr->sap_addr.vpi & 0x00ff) >> 0;
    t->remote[4] = (addr->sap_addr.vci & 0xff000000) >> 24;
    t->remote[5] = (addr->sap_addr.vci & 0x00ff0000) >> 16;
    t->remote[6] = (addr->sap_addr.vci & 0x0000ff00) >>  8;
    t->remote[7] = (addr->sap_addr.vci & 0x000000ff) >>  0;
    t->remote_length = 8;

    if (connect(t->sock, (struct sockaddr *)addr,
		sizeof(struct sockaddr_atmpvc)) < 0) {
      DEBUGMSGTL(("snmp_aal5pvc", "connect failed (%s)\n", strerror(errno)));
      snmp_aal5pvc_close(t);
      snmp_transport_free(t);
      return NULL;      
    }
  }

  t->data = malloc(sizeof(struct sockaddr_atmpvc));
  if (t->data == NULL) {
    snmp_transport_free(t);
    return NULL;
  }
  memcpy(t->data, addr, sizeof(struct sockaddr_atmpvc));
  t->data_length = sizeof(struct sockaddr_atmpvc);

  /*  16-bit length field in the trailer, no headers.  */

  t->msgMaxSize  = 0xffff;
  t->f_recv      = snmp_aal5pvc_recv;
  t->f_send      = snmp_aal5pvc_send;
  t->f_close     = snmp_aal5pvc_close;
  t->f_accept    = NULL;
  t->f_fmtaddr   = snmp_aal5pvc_fmtaddr;

  return t;
}



snmp_transport	*snmp_aal5pvc_create_tstring	(const char *string, int local)
{
  struct sockaddr_atmpvc addr;
  
  if (string != NULL) {
    addr.sap_family = AF_ATMPVC;

    if (sscanf(string, "%hd.%hd.%d", &(addr.sap_addr.itf),
	       &(addr.sap_addr.vpi), &(addr.sap_addr.vci)) == 3) {
      return snmp_aal5pvc_transport(&addr, local);
    } else if (sscanf(string, "%hd.%d",
		      &(addr.sap_addr.vpi), &(addr.sap_addr.vci)) == 2) {
      addr.sap_addr.itf = 0;
      return snmp_aal5pvc_transport(&addr, local);
    } else if (sscanf(string, "%d",
		      &(addr.sap_addr.vci)) == 1) {
      addr.sap_addr.itf = 0;
      addr.sap_addr.vpi = 0;
      return snmp_aal5pvc_transport(&addr, local);
    } else {
      return NULL;
    }
  } else {
    return NULL;
  }
}



snmp_transport	*snmp_aal5pvc_create_ostring	(const u_char *o, size_t o_len,
						 int local)
{
  struct sockaddr_atmpvc addr;

  if (o_len == 8) {
    addr.sap_family = AF_ATMPVC;
    addr.sap_addr.itf = (o[0] <<  8) + (o[1] <<  0);
    addr.sap_addr.vpi = (o[2] <<  8) + (o[3] <<  0);
    addr.sap_addr.vci = (o[4] << 24) + (o[5] << 16) + (o[6] <<  8) + (o[7] << 0);
    return snmp_aal5pvc_transport(&addr, local);
  }

  return NULL;
}



void		snmp_aal5pvc_ctor		(void)
{
  aal5pvcDomain.name        = ucdSnmpAAL5PVCDomain;
  aal5pvcDomain.name_length = sizeof(ucdSnmpAAL5PVCDomain)/sizeof(oid);
  aal5pvcDomain.prefix      = calloc(3, sizeof(char *));
  aal5pvcDomain.prefix[0]   = "aal5pvc";
  aal5pvcDomain.prefix[1]   = "pvc";

  aal5pvcDomain.f_create_from_tstring = snmp_aal5pvc_create_tstring;
  aal5pvcDomain.f_create_from_ostring = snmp_aal5pvc_create_ostring;

  snmp_tdomain_register(&aal5pvcDomain);
}
