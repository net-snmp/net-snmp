#ifndef _SNMPCALLBACKDOMAIN_H
#define _SNMPCALLBACKDOMAIN_H

#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include "snmp_transport.h"

typedef struct callback_pass_s {
   int return_transport_num;
   struct snmp_pdu *pdu;
   struct callback_pass_s *next;
} callback_pass;

typedef struct callback_info_s {
   int linkedto;
   void *parent_data;
   callback_pass *data;
   int callback_num;
   int pipefds[2];
} callback_info;

snmp_transport		*snmp_callback_transport (int);
int snmp_callback_hook_parse(struct snmp_session *sp,
                             struct snmp_pdu *pdu,
                             u_char *packetptr,
                             size_t len);
int snmp_callback_hook_build(struct snmp_session *sp,
                             struct snmp_pdu *pdu,
                             u_char *ptk, size_t *len);
int snmp_callback_check_packet(u_char *pkt, size_t len);
struct snmp_pdu *snmp_callback_create_pdu(snmp_transport *transport,
                                          void *opaque, size_t olength);
struct snmp_session *snmp_callback_open(int attach_to,
                                        int (*return_func)(int op, struct snmp_session *session,
                                                           int reqid, struct snmp_pdu *pdu,
                                                           void *magic),
                                        int (*fpre_parse) (struct snmp_session *,
                                                           struct _snmp_transport *,
                                                           void *, int),
                                        int (*fpost_parse)(struct snmp_session *,
                                                           struct snmp_pdu *, int));

#endif/*_SNMPCALLBACKDOMAIN_H*/
