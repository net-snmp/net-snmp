#ifndef _SNMP_TRANSPORT_H
#define _SNMP_TRANSPORT_H

#include <sys/types.h>
#include "asn1.h"

#ifdef __cplusplus
extern "C" {
#endif



/*  Some transport-type constants.  */

#ifndef SNMP_STREAM_QUEUE_LEN
#define		SNMP_STREAM_QUEUE_LEN		5
#endif



/*  Some transport-type flags.  */

#define		SNMP_TRANSPORT_FLAG_STREAM	0x01
#define		SNMP_TRANSPORT_FLAG_LISTEN	0x02



/*  The standard SNMP domains.  */

extern const oid snmpUDPDomain[7];	/* 	= { 1, 3, 6, 1, 6, 1, 1 };  */
extern const oid snmpCLNSDomain[7];	/*	= { 1, 3, 6, 1, 6, 1, 2 };  */
extern const oid snmpCONSDomain[7];	/* 	= { 1, 3, 6, 1, 6, 1, 3 };  */
extern const oid snmpDDPDomain[7];	/* 	= { 1, 3, 6, 1, 6, 1, 4 };  */
extern const oid snmpIPXDomain[7];	/*	= { 1, 3, 6, 1, 6, 1, 5 };  */



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

  /*  Maximum size of PDU that can be sent/received by this transport.  */

  size_t	 msgMaxSize;

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

typedef struct snmp_transport_list_s {
   snmp_transport *transport;
   struct snmp_transport_list_s *next;
} snmp_transport_list;

typedef struct _snmp_tdomain {
  const oid		*name;
  size_t		 name_length;
  const char 	       **prefix;
  snmp_transport	*(*f_create_from_tstring)(const char *, int);
  snmp_transport	*(*f_create_from_ostring)(const u_char *, size_t, int);

  struct _snmp_tdomain	*next;
} snmp_tdomain;


/*  Some utility functions.  */

int snmp_transport_add_to_list(snmp_transport_list **transport_list,
                               snmp_transport *transport);
int snmp_transport_remove_from_list(snmp_transport_list **transport_list,
                                    snmp_transport *transport);
    

/*  Return an exact (deep) copy of t, or NULL if there is a memory allocation
    problem (for instance).  */

snmp_transport	       *snmp_transport_copy	(snmp_transport *t);


/*  Free an snmp_transport.  */

void		     	snmp_transport_free	(snmp_transport *t);


/*  If the passed oid (in_oid, in_len) corresponds to a supported transport
    domain, return 1; if not return 0.  If out_oid is not NULL and out_len is
    not NULL, then the "internal" oid which should be used to identify this
    domain (e.g. in pdu->tDomain etc.) is written to *out_oid and its length
    to *out_len.  */

int			snmp_tdomain_support	(const oid *in_oid,
						 size_t in_len,
						 const oid **out_oid,
						 size_t *out_len);
						 
int			snmp_tdomain_register	(snmp_tdomain *domain);

int			snmp_tdomain_unregister	(snmp_tdomain *domain);

void			snmp_tdomain_init	(void);

snmp_transport	       *snmp_tdomain_transport	(const char *string, int local,
						 const char *default_domain);

snmp_transport	       *snmp_tdomain_transport_oid(const oid *dom, 
						   size_t dom_len,
						   const u_char *o,
						   size_t o_len, int local);

#ifdef __cplusplus
}
#endif

#endif/*_SNMP_TRANSPORT_H*/
