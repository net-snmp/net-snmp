#include <config.h>

#include <stdio.h>
#include <sys/types.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif

#include "snmp_transport.h"



/*  The standard SNMP domains.  */

const oid snmpUDPDomain[]	= { 1, 3, 6, 1, 6, 1, 1 };
const oid snmpCLNSDomain[]	= { 1, 3, 6, 1, 6, 1, 2 };
const oid snmpCONSDomain[]	= { 1, 3, 6, 1, 6, 1, 3 };
const oid snmpDDPDomain[]	= { 1, 3, 6, 1, 6, 1, 4 };
const oid snmpIPXDomain[]	= { 1, 3, 6, 1, 6, 1, 5 };



/*  Make a deep copy of an snmp_transport.  */

snmp_transport	       *snmp_transport_copy	(snmp_transport *t)
{
  snmp_transport *n = NULL;

  n = (snmp_transport *)malloc(sizeof(snmp_transport));
  if (n == NULL) {
    return NULL;
  }
  memset(n, 0, sizeof(snmp_transport));

  if (t->domain != NULL) {
    n->domain = t->domain;
    n->domain_length = t->domain_length;
  } else {
    n->domain = NULL;
    n->domain_length = 0;
  }

  if (t->local != NULL) {
    n->local = malloc(t->local_length);
    if (n->local == NULL) {
      snmp_transport_free(n);
      return NULL;
    }
    n->local_length = t->local_length;
    memcpy(n->local, t->local, t->local_length);
  } else {
    n->local = NULL;
    n->local_length = 0;
  }

  if (t->remote != NULL) {
    n->remote = malloc(t->remote_length);
    if (n->remote == NULL) {
      snmp_transport_free(n);
      return NULL;
    }
    n->remote_length = t->remote_length;
    memcpy(n->remote, t->remote, t->remote_length);
  } else {
    n->remote = NULL;
    n->remote_length = 0;
  }

  if (t->data != NULL && t->data_length > 0) {
    n->data = malloc(t->data_length);
    if (n->data == NULL) {
      snmp_transport_free(n);
      return NULL;
    }
    n->data_length = t->data_length;
    memcpy(n->data, t->data, t->data_length);
  } else {
    n->data = NULL;
    n->data_length = 0;
  }

  n->f_accept  = t->f_accept;
  n->f_recv    = t->f_recv;
  n->f_send    = t->f_send;
  n->f_close   = t->f_close;
  n->f_fmtaddr = t->f_fmtaddr;
  n->sock      = t->sock;
  n->flags     = t->flags;

  return n;
}



void		     	snmp_transport_free	(snmp_transport *t)
{
  if (t->local != NULL) {
    free(t->local);
  }
  if (t->remote != NULL) {
    free(t->remote);
  }
  if (t->data != NULL) {
    free(t->data);
  }
  free(t);
}
