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

extern struct synch_state snmp_synch_state;

struct variable_list* snmp_add_null_var __P((struct snmp_pdu *, oid *, int));
struct snmp_pdu	*snmp_pdu_create __P((int));
struct snmp_pdu *snmp_fix_pdu __P((struct snmp_pdu *, int));
struct snmp_pdu *snmp_clone_pdu __P((struct snmp_pdu *));
char *snmp_errstring __P((int));
void snmp_synch_setup __P((struct snmp_session *));
int snmp_synch_response __P((struct snmp_session *, struct snmp_pdu *, struct snmp_pdu **));
int ms_party_init __P((u_long, oid *, int *, oid *, int *, oid *, int *));
