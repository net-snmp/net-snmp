/*
 * snmp_client.c - a toolkit of common functions for an SNMP client.
 *
 */
/**********************************************************************
	Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

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
#include <config.h>

#include <stdio.h>
#include <errno.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#include <stdio.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "party.h"
#include "context.h"
#include "view.h"
#include "acl.h"
#include "mib.h"


#ifndef BSD4_3
#define BSD4_2
#endif

#ifndef FD_SET

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	memset((p), 0, sizeof(*(p)))
#endif

#define PARTY_MIB_BASE	".1.3.6.1.6.3.3.1.3.127.0.0.1.1"

_CRTIMP extern int errno;

int
snmp_synch_input __P((int, struct snmp_session *, int, struct snmp_pdu *, void *));

struct snmp_pdu *
snmp_pdu_create(command)
    int command;
{
    struct snmp_pdu *pdu;

    pdu = (struct snmp_pdu *)malloc(sizeof(struct snmp_pdu));
    memset(pdu, 0, sizeof(struct snmp_pdu));
    pdu->version = SNMP_DEFAULT_VERSION;
    pdu->srcPartyLen = 0;
    pdu->dstPartyLen = 0;
    pdu->community_len = 0;
    pdu->command = command;
    pdu->errstat = SNMP_DEFAULT_ERRSTAT;
    pdu->errindex = SNMP_DEFAULT_ERRINDEX;
    pdu->address.sin_addr.s_addr = SNMP_DEFAULT_ADDRESS;
    pdu->enterprise = NULL;
    pdu->enterprise_length = 0;
    pdu->variables = NULL;
    return pdu;
}

/*
 * Add a null variable with the requested name to the end of the list of
 * variables for this pdu.
 */
struct variable_list* snmp_add_null_var(pdu, name, name_length)
    struct snmp_pdu *pdu;
    oid *name;
    int name_length;
{
    struct variable_list *vars;

    if (pdu->variables == NULL){
	pdu->variables = vars = (struct variable_list *)malloc(sizeof(struct variable_list));
    } else {
	for(vars = pdu->variables; vars->next_variable; vars = vars->next_variable)
	    /*EXIT*/;
	vars->next_variable = (struct variable_list *)malloc(sizeof(struct variable_list));
	vars = vars->next_variable;
    }

    vars->next_variable = NULL;
    vars->name = (oid *)malloc(name_length * sizeof(oid));
    memmove(vars->name, name, name_length * sizeof(oid));
    vars->name_length = name_length;
    vars->type = ASN_NULL;
    vars->val.string = NULL;
    vars->val_len = 0;
    return vars;
}

int
snmp_synch_input(op, session, reqid, pdu, magic)
    int op;
    struct snmp_session *session;
    int reqid;
    struct snmp_pdu *pdu;
    void *magic;
{
    struct synch_state *state = (struct synch_state *)magic;

    if (reqid != state->reqid)
	return 0;
    state->waiting = 0;
    if (op == RECEIVED_MESSAGE && pdu->command == SNMP_MSG_RESPONSE){
	/* clone the pdu */
	state->pdu = snmp_clone_pdu(pdu);
	state->status = STAT_SUCCESS;
	snmp_errno = 0;  /* XX all OK when msg received ? */
	session->s_snmp_errno = 0;
    } else if (op == TIMED_OUT){
	state->pdu = NULL;
	state->status = STAT_TIMEOUT;
	snmp_errno = SNMPERR_TIMEOUT;
	session->s_snmp_errno = SNMPERR_TIMEOUT;
    }

    return 1;
}

/*
 * If there was an error in the input pdu, creates a clone of the pdu
 * that includes all the variables except the one marked by the errindex.
 * The command is set to the input command and the reqid, errstat, and
 * errindex are set to default values.
 * If the error status didn't indicate an error, the error index didn't
 * indicate a variable, the pdu wasn't a get response message, or there
 * would be no remaining variables, this function will return NULL.
 * If everything was successful, a pointer to the fixed cloned pdu will
 * be returned.
 */
struct snmp_pdu *
snmp_fix_pdu(pdu, command)
    struct snmp_pdu *pdu;
    int command;
{
    struct variable_list *var, *newvar;
    struct snmp_pdu *newpdu;
    int index, copied = 0;

    if (pdu->command != SNMP_MSG_RESPONSE || pdu->errstat == SNMP_ERR_NOERROR || pdu->errindex <= 0)
	return NULL;
    /* clone the pdu */
    newpdu = (struct snmp_pdu *)malloc(sizeof(struct snmp_pdu));
    memmove(newpdu, pdu, sizeof(struct snmp_pdu));
    newpdu->variables = 0;
    newpdu->command = command;
    newpdu->reqid = SNMP_DEFAULT_REQID;
    newpdu->errstat = SNMP_DEFAULT_ERRSTAT;
    newpdu->errindex = SNMP_DEFAULT_ERRINDEX;
    if (pdu->enterprise){
	newpdu->enterprise = (oid *)malloc(sizeof(oid)*pdu->enterprise_length);
	memmove(newpdu->enterprise, pdu->enterprise, sizeof(oid)*pdu->enterprise_length);
    }
    if (pdu->community){
	newpdu->community = (u_char *)malloc(pdu->community_len);
	memmove(newpdu->community, pdu->community, pdu->community_len);
    }
   if (pdu->srcParty){
	newpdu->srcParty = (oid *)malloc(sizeof(oid)*pdu->srcPartyLen);
	memmove(newpdu->srcParty, pdu->srcParty, sizeof(oid)*pdu->srcPartyLen);
    }
    if (pdu->dstParty){
	newpdu->dstParty = (oid *)malloc(sizeof(oid)*pdu->dstPartyLen);
	memmove(newpdu->dstParty, pdu->dstParty, sizeof(oid)*pdu->dstPartyLen);
    }
    if (pdu->context){
	newpdu->context = (oid *)malloc(sizeof(oid)*pdu->contextLen);
	memmove(newpdu->context, pdu->context, sizeof(oid)*pdu->contextLen);
    }
    var = pdu->variables;
    index = 1;
    if (pdu->errindex == index){	/* skip first variable */
      if (var == NULL)
        return NULL;
      var = var->next_variable;
      index++;
    }
    if (var != NULL){
	newpdu->variables = newvar = (struct variable_list *)malloc(sizeof(struct variable_list));
	memmove(newvar, var, sizeof(struct variable_list));
	if (var->name != NULL){
	    newvar->name = (oid *)malloc(var->name_length * sizeof(oid));
	    memmove(newvar->name, var->name, var->name_length * sizeof(oid));
	}
	if (var->val.string != NULL){
	    newvar->val.string = (u_char *)malloc(var->val_len);
	    memmove(newvar->val.string, var->val.string, var->val_len);
	}
	newvar->next_variable = 0;
	copied++;

	while(var->next_variable){
	    var = var->next_variable;
	    if (++index == pdu->errindex)
		continue;
	    newvar->next_variable = (struct variable_list *)malloc(sizeof(struct variable_list));
	    newvar = newvar->next_variable;
	    memmove(newvar, var, sizeof(struct variable_list));
	    if (var->name != NULL){
		newvar->name = (oid *)malloc(var->name_length * sizeof(oid));
		memmove(newvar->name, var->name, var->name_length * sizeof(oid));
	    }
	    if (var->val.string != NULL){
		newvar->val.string = (u_char *)malloc(var->val_len);
		memmove(newvar->val.string, var->val.string, var->val_len);
	    }
	    newvar->next_variable = 0;
	    copied++;
	}
    }
    if (index < pdu->errindex || copied == 0){
	snmp_free_pdu(newpdu);
	return NULL;
    }
    return newpdu;
}


/*
 * Creates (allocates and copies) a clone of the input PDU.
 */
struct snmp_pdu *
snmp_clone_pdu(pdu)
    struct snmp_pdu *pdu;
{
    struct variable_list *var, *newvar;
    struct snmp_pdu *newpdu;

    /* clone the pdu */
    newpdu = (struct snmp_pdu *)malloc(sizeof(struct snmp_pdu));
    memmove(newpdu, pdu, sizeof(struct snmp_pdu));
    newpdu->variables = 0;
    var = pdu->variables;
    if (var != NULL){
	newpdu->variables = newvar =
	    (struct variable_list *)malloc(sizeof(struct variable_list));
	memmove(newvar, var, sizeof(struct variable_list));
	if (var->name != NULL){
	    newvar->name = (oid *)malloc(var->name_length * sizeof(oid));
	    memmove(newvar->name, var->name, var->name_length * sizeof(oid));
	}
	if (var->val.string != NULL){
	    newvar->val.string = (u_char *)malloc(var->val_len);
	    memmove(newvar->val.string, var->val.string, var->val_len);
	}
	newvar->next_variable = 0;

	while(var->next_variable){
	    var = var->next_variable;
	    newvar->next_variable =
		(struct variable_list *)malloc(sizeof(struct variable_list));
	    newvar = newvar->next_variable;
	    memmove(newvar, var, sizeof(struct variable_list));
	    if (var->name != NULL){
		newvar->name = (oid *)malloc(var->name_length * sizeof(oid));
		memmove(newvar->name, var->name, var->name_length * sizeof(oid));
	    }
/* XX CISCO Catalyst 2900 returns NULL strings as data of length 0. */
	    if ((var->val.string != NULL) && (var->val_len)) {
		newvar->val.string = (u_char *)malloc(var->val_len);
		memmove(newvar->val.string, var->val.string, var->val_len);
	    }
	    newvar->next_variable = 0;
	}
    }
    if (pdu->enterprise){
	newpdu->enterprise = (oid *)malloc(sizeof(oid)*pdu->enterprise_length);
	memmove(newpdu->enterprise, pdu->enterprise, sizeof(oid)*pdu->enterprise_length);
    }
    if (pdu->community){
	newpdu->community = (u_char *)malloc(pdu->community_len);
	memmove(newpdu->community, pdu->community, pdu->community_len);
    }
    if (pdu->srcParty){
	newpdu->srcParty = (oid *)malloc(sizeof(oid)*pdu->srcPartyLen);
	memmove(newpdu->srcParty, pdu->srcParty, sizeof(oid)*pdu->srcPartyLen);
    }
    if (pdu->dstParty){
	newpdu->dstParty = (oid *)malloc(sizeof(oid)*pdu->dstPartyLen);
	memmove(newpdu->dstParty, pdu->dstParty, sizeof(oid)*pdu->dstPartyLen);
    }
    if (pdu->context){
	newpdu->context = (oid *)malloc(sizeof(oid)*pdu->contextLen);
	memmove(newpdu->context, pdu->context, sizeof(oid)*pdu->contextLen);
    }
    return newpdu;
}


int
snmp_synch_response(ss, pdu, response)
    struct snmp_session *ss;
    struct snmp_pdu *pdu;
    struct snmp_pdu **response;
{
    struct synch_state *state = ss->snmp_synch_state;
    int numfds, count;
    fd_set fdset;
    struct timeval timeout, *tvp;
    int block;

    if ((state->reqid = snmp_send(ss, pdu)) == 0){
	*response = NULL;
	snmp_free_pdu(pdu);
	return STAT_ERROR;
    }
    state->waiting = 1;

    while(state->waiting){
	numfds = 0;
	FD_ZERO(&fdset);
	block = SNMPBLOCK;
	tvp = &timeout;
	timerclear(tvp);
	snmp_select_info(&numfds, &fdset, tvp, &block);
	if (block == 1)
	    tvp = NULL;	/* block without timeout */
	count = select(numfds, &fdset, 0, 0, tvp);
	if (count > 0){
	    snmp_read(&fdset);
	} else switch(count){
	    case 0:
		snmp_timeout();
		break;
	    case -1:
		if (errno == EINTR){
		    continue;
		} else {
		    snmp_errno = SNMPERR_GENERR;
		/* CAUTION! if another thread closed the socket(s)
		   waited on here, the session structure was freed.
		   It would be nice, but we can't rely on the pointer.
		    ss->s_snmp_errno = SNMPERR_GENERR;
		    ss->s_errno = errno;
		 */
		    snmp_set_detail(strerror(errno));
		}
	    /* FALLTHRU */
	    default:
		snmp_free_pdu(pdu);
		*response = NULL;
		return STAT_ERROR;
	}
    }
    *response = state->pdu;
    return state->status;
}

int
snmp_sess_synch_response(sessp, pdu, response)
    void *sessp;
    struct snmp_pdu *pdu;
    struct snmp_pdu **response;
{
    struct snmp_session *ss;
    struct synch_state *state;
    int numfds, count;
    fd_set fdset;
    struct timeval timeout, *tvp;
    int block;

    ss = snmp_sess_session(sessp);
    state = ss->snmp_synch_state;

    if ((state->reqid = snmp_sess_send(sessp, pdu)) == 0){
	*response = NULL;
	snmp_free_pdu(pdu);
	return STAT_ERROR;
    }
    state->waiting = 1;

    while(state->waiting){
	numfds = 0;
	FD_ZERO(&fdset);
	block = SNMPBLOCK;
	tvp = &timeout;
	timerclear(tvp);
	snmp_sess_select_info(sessp, &numfds, &fdset, tvp, &block);
	if (block == 1)
	    tvp = NULL;	/* block without timeout */
	count = select(numfds, &fdset, 0, 0, tvp);
	if (count > 0){
	    snmp_sess_read(sessp);
	} else switch(count){
	    case 0:
		snmp_sess_timeout(sessp);
		break;
	    case -1:
		if (errno == EINTR){
		    continue;
		} else {
		    snmp_errno = SNMPERR_GENERR;
		/* CAUTION! if another thread closed the socket(s)
		   waited on here, the session structure was freed.
		   It would be nice, but we can't rely on the pointer.
		    ss->s_snmp_errno = SNMPERR_GENERR;
		    ss->s_errno = errno;
		 */
		    snmp_set_detail(strerror(errno));
		}
	    /* FALLTHRU */
	    default:
		snmp_free_pdu(pdu);
		*response = NULL;
		return STAT_ERROR;
	}
    }
    *response = state->pdu;
    return state->status;
}

void
snmp_synch_reset(session)
    struct snmp_session *session;
{
    if (session && session->snmp_synch_state)
       free(session->snmp_synch_state);
}

void
snmp_synch_setup(session)
    struct snmp_session *session;
{
    struct synch_state *rp = (struct synch_state *)malloc(sizeof(struct synch_state));
    rp->waiting = 0;
    rp->pdu = NULL;
    session->snmp_synch_state = rp;

    session->callback = snmp_synch_input;
    session->callback_magic = (void *)rp;
}

char	*error_string[19] = {
    "(noError) No Error",
    "(tooBig) Response message would have been too large.",
    "(noSuchName) There is no such variable name in this MIB.",
    "(badValue) The value given has the wrong type or length.",
    "(readOnly) The two parties used do not have access to use the specified SNMP PDU.",
    "(genError) A general failure occured",
    "noAccess",
    "wrongType",
    "wrongLength",
    "wrongEncoding",
    "wrongValue",
    "noCreation",
    "inconsistentValue",
    "resourceUnavailable",
    "commitFailed",
    "undoFailed",
    "authorizationError",
    "notWritable",
    "inconsistentName"
};

char *
snmp_errstring(errstat)
    int	errstat;
{
    if (errstat <= MAX_SNMP_ERR && errstat >= SNMP_ERR_NOERROR){
	return error_string[errstat];
    } else {
	return "Unknown Error";
    }
}

#ifdef USE_V2PARTY_PROTOCOL

/*
 * In: Dest IP address, src, dst parties and lengths and context and contextlen
 * Initializes a noAuth/noPriv party pair, a context, and 2 acl entries.
 * (Are two acl entries really needed?)
 * Out: returns 0 if OK, -1 if an error occurred.
 */
int
ms_party_init(destaddr, src, srclen, dst, dstlen, context, contextlen)
    in_addr_t destaddr;
    oid *src, *dst, *context;
    int *srclen, *dstlen, *contextlen;
{
    u_long addr;
    u_short port;
    unsigned char *adp;
    struct partyEntry *pp1, *pp2, *rp;
    struct contextEntry *cxp, *rxp;
    struct aclEntry *ap;
    int oneIndex, twoIndex, cxindex;

    if (!read_objid(PARTY_MIB_BASE, dst, dstlen)){
	snmp_errno = SNMPERR_BAD_PARTY;
	snmp_set_detail(PARTY_MIB_BASE);
	return -1;
    }
    adp = (unsigned char *)&destaddr;
    dst[9] =  adp[0];
    dst[10] = adp[1];
    dst[11] = adp[2];
    dst[12] = adp[3];
    dst[13] = 1;

    pp1 = party_getEntry(dst, *dstlen);
    if (!pp1){
	pp1 = party_createEntry(dst, *dstlen);

	rp = pp1->reserved;
	strcpy(pp1->partyName, "noAuthAgent");
	pp1->partyTDomain = rp->partyTDomain = DOMAINSNMPUDP;
	addr = htonl(destaddr);
	port = htons(161);
	memmove(pp1->partyTAddress, &addr, sizeof(addr));
	memmove(pp1->partyTAddress + 4, &port, sizeof(port));
	memmove(rp->partyTAddress, pp1->partyTAddress, 6);
	pp1->partyTAddressLen = rp->partyTAddressLen = 6;
	pp1->partyAuthProtocol = rp->partyAuthProtocol = NOAUTH;
	pp1->partyAuthClock = rp->partyAuthClock = 0;
	pp1->tv.tv_sec = pp1->partyAuthClock;
	pp1->partyAuthPublicLen = 0;
	pp1->partyAuthLifetime = rp->partyAuthLifetime = 0;
	pp1->partyPrivProtocol = rp->partyPrivProtocol = NOPRIV;
	pp1->partyPrivPublicLen = 0;
	pp1->partyMaxMessageSize = rp->partyMaxMessageSize = 1500;
	pp1->partyLocal = 2; /* FALSE */
	pp1->partyAuthPrivateLen = rp->partyAuthPrivateLen = 0;
	pp1->partyPrivPrivateLen = rp->partyPrivPrivateLen = 0;
	pp1->partyStorageType = 2; /* volatile */
	pp1->partyStatus = rp->partyStatus = SNMP_ROW_ACTIVE;
#define PARTYCOMPLETE_MASK              65535
	/* all collumns - from party_vars.c XXX */
	pp1->partyBitMask = rp->partyBitMask = PARTYCOMPLETE_MASK;
    }
    oneIndex = pp1->partyIndex;

    if (!read_objid(PARTY_MIB_BASE, src, srclen)){
	snmp_errno = SNMPERR_BAD_PARTY;
	snmp_set_detail(PARTY_MIB_BASE);
	return -1;
    }
    src[9] =  adp[0];
    src[10] = adp[1];
    src[11] = adp[2];
    src[12] = adp[3];
    src[13] = 2;
    pp2 = party_getEntry(src, *srclen);
    if (!pp2){
	pp2 = party_createEntry(src, *srclen);

	rp = pp2->reserved;
	strcpy(pp2->partyName, "noAuthMS");
	pp2->partyTDomain = rp->partyTDomain = DOMAINSNMPUDP;
	memset(pp2->partyTAddress, 0, 6);
	memmove(rp->partyTAddress, pp2->partyTAddress, 6);
	pp2->partyTAddressLen = rp->partyTAddressLen = 6;
	pp2->partyAuthProtocol = rp->partyAuthProtocol = NOAUTH;
	pp2->partyAuthClock = rp->partyAuthClock = 0;
	pp2->tv.tv_sec = pp2->partyAuthClock;
	pp2->partyAuthPublicLen = 0;
	pp2->partyAuthLifetime = rp->partyAuthLifetime = 0;
	pp2->partyPrivProtocol = rp->partyPrivProtocol = NOPRIV;
	pp2->partyPrivPublicLen = 0;
	pp2->partyMaxMessageSize = rp->partyMaxMessageSize = 484; /* ??? */
	pp2->partyLocal = 2; /* FALSE */
	pp2->partyAuthPrivateLen = rp->partyAuthPrivateLen = 0;
	pp2->partyPrivPrivateLen = rp->partyPrivPrivateLen = 0;
	pp2->partyStorageType = 2; /* volatile */
	pp2->partyStatus = rp->partyStatus = SNMP_ROW_ACTIVE;
#define PARTYCOMPLETE_MASK              65535
	/* all collumns - from party_vars.c XXX */
	pp2->partyBitMask = rp->partyBitMask = PARTYCOMPLETE_MASK;
    }
    twoIndex = pp2->partyIndex;

    if (!read_objid(PARTY_MIB_BASE, context, contextlen)){
	snmp_errno = SNMPERR_BAD_CONTEXT;
	snmp_set_detail(PARTY_MIB_BASE);
	return -1;
    }
    context[9] =  adp[0];
    context[10] = adp[1];
    context[11] = adp[2];
    context[12] = adp[3];
    context[13] = 1;
    cxp = context_getEntry(context, *contextlen);
    if (!cxp){
	cxp = context_createEntry(context, *contextlen);
	rxp = cxp->reserved;
	strcpy(cxp->contextName, "noAuthContext");
	cxp->contextLocal = 2; /* FALSE */
	cxp->contextViewIndex = -1; /* unknown */
	cxp->contextLocalEntityLen = 0;
	cxp->contextLocalTime = CURRENTTIME;
	cxp->contextProxyContextLen = 0;
	cxp->contextStorageType = 2;
	cxp->contextStatus = rxp->contextStatus = SNMP_ROW_ACTIVE;
#define CONTEXTCOMPLETE_MASK              0x03FF
	/* all collumns - from context_vars.c XXX */
	cxp->contextBitMask = rxp->contextBitMask = CONTEXTCOMPLETE_MASK;
    }
    cxindex = cxp->contextIndex;

    ap = acl_getEntry(oneIndex, twoIndex, cxindex);
    if (!ap){
	ap = acl_createEntry(oneIndex, twoIndex, cxindex);
	ap->aclPriveleges = 132;
	ap->aclStorageType = 2; /* volatile */
	ap->aclStatus = SNMP_ROW_ACTIVE;
#define ACLCOMPLETE_MASK              0x3F
	/* all collumns - from acl_vars.c XXX */
	ap->aclBitMask = ACLCOMPLETE_MASK;
	ap->reserved->aclBitMask = ap->aclBitMask;
    }
    return 0; /* SUCCESS */
}

#endif /* USE_V2PARTY_PROTOCOL */

