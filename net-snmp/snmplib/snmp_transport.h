#ifndef _SNMP_TRANSPORT_H
#define _SNMP_TRANSPORT_H

#include <sys/types.h>
#include "asn1.h"

#ifdef __cplusplus
extern "C" {
#endif



/*  Some transport-type flags.  */

#define		SNMP_TRANSPORT_FLAG_STREAM	0x01
#define		SNMP_TRANSPORT_FLAG_LISTEN	0x02



/*  The standard SNMP domains.  */

const oid snmpUDPDomain[7];	/* 	= { 1, 3, 6, 1, 6, 1, 1 };  */
const oid snmpCLNSDomain[7];	/*	= { 1, 3, 6, 1, 6, 1, 2 };  */
const oid snmpCONSDomain[7];	/* 	= { 1, 3, 6, 1, 6, 1, 3 };  */
const oid snmpDDPDomain[7];	/* 	= { 1, 3, 6, 1, 6, 1, 4 };  */
const oid snmpIPXDomain[7];	/*	= { 1, 3, 6, 1, 6, 1, 5 };  */



/*  Structure which defines the transport-independent API.  */

typedef struct _snmp_transport {
  /*  The transport domain object identifier.  */

  const oid	*domain;
  int		 domain_length;		/*  In sub-IDs, not octets.  */

  /*  Local transport address (in relevant SNMP-style encoding).  */

  unsigned char	*local;
  int		 local_length;		/*  In octets.  */

  /*  Remote transport address (in relevant SNMP-style encoding).  */

  unsigned char	*remote;
  int		 remote_length;		/*  In octets.  */

  /*  The actual socket.  */

  int		 sock;

  /*  Flags (see above).  */

  unsigned int	flags;

  /*  Protocol specific opaque data pointer.  */

  void	       	*data;
  int		 data_length;

  /*  Callbacks.  */

  /*               this pointer, fd, buf, size, *opaque, *opaque_length  */

  int	(*f_recv) (struct _snmp_transport *, void *, int, void **, int *);
  int	(*f_send) (struct _snmp_transport *, void *, int, void **, int *);
  int	(*f_close)(struct _snmp_transport *);

  /*  This callback is only necessary for stream-oriented transports.  */

  int	(*f_accept)  (struct _snmp_transport *);

  /*  Optional callback to format a transport address.  */

  char *(*f_fmtaddr) (struct _snmp_transport *, void *, int);
} snmp_transport;



/*  Some utility functions.  */


/*  Return an exact (deep) copy of t, or NULL if there is a memory allocation
    problem (for instance).  */

snmp_transport	       *snmp_transport_copy	(snmp_transport *t);


/*  Free an snmp_transport.  */

void		     	snmp_transport_free	(snmp_transport *t);

#ifdef __cplusplus
}
#endif

#endif/*_SNMP_TRANSPORT_H*/
