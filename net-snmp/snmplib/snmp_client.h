/*
 * snmp_client.h
 */
/***********************************************************
	Copyright 1988, 1989 by Carnegie Mellon University

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of CMU not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.
******************************************************************/
 
#ifndef SNMP_CLIENT_H
#define SNMP_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif


struct snmp_pdu;
struct snmp_session;
struct variable_list;

struct synch_state {
    int	waiting;
    int status;
/* status codes */
#define STAT_SUCCESS	0
#define STAT_ERROR	1
#define STAT_TIMEOUT 2
    int reqid;
    struct snmp_pdu *pdu;
};

int snmp_set_var_value(struct variable_list *, u_char *, size_t);
int snmp_set_var_objid (struct variable_list *vp,
                    const oid *objid, size_t name_length);
struct variable_list* snmp_add_null_var (struct snmp_pdu *, oid *, size_t);
struct snmp_pdu	*snmp_pdu_create (int);
struct snmp_pdu *snmp_fix_pdu (struct snmp_pdu *, int);
struct snmp_pdu *snmp_clone_pdu (struct snmp_pdu *);
struct snmp_pdu *snmp_split_pdu (struct snmp_pdu *, int skipCount,
                                 int copyCount);

unsigned long snmp_varbind_len(struct snmp_pdu * pdu);
int snmp_clone_var(struct variable_list *, struct variable_list *);
struct variable_list *snmp_clone_varbind(struct variable_list *);
const char *snmp_errstring (int);
int snmp_synch_response (struct snmp_session *, struct snmp_pdu *, struct snmp_pdu **);
int snmp_synch_response_cb (struct snmp_session *, struct snmp_pdu *, struct snmp_pdu **, snmp_callback);
int snmp_clone_mem(void **, void *, unsigned);

/* single session API - see snmp_api.h for full details */
int snmp_sess_synch_response (void *, struct snmp_pdu *, struct snmp_pdu **);
 
#ifdef __cplusplus
}
#endif

#endif /* SNMP_CLIENT_H */
