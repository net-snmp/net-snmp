#ifndef _SNMPUDPDOMAIN_H
#define _SNMPUDPDOMAIN_H

#include "snmp_transport.h"
#include "asn1.h"

snmp_transport	*snmp_udp_transport	(struct sockaddr_in *addr,
					 int local);


/*  Convert a "traditional" peername into a sockaddr_in structure which is
    written to *addr.  Returns 1 if the conversion was successful, or 0 if it
    failed.  */

int		 snmp_sockaddr_in	(struct sockaddr_in *addr,
					 const char *peername,
					 int remote_port);


/*  Register any configuration tokens specific to the agent.  */

void		snmp_udp_agent_config_tokens_register(void);

void		snmp_udp_parse_security	(const char *token, char *param);

int		snmp_udp_getSecName	(void *opaque, int olength,
					 const char *community,
					 int community_len, char **secname);


#endif/*_SNMPUDPDOMAIN_H*/
