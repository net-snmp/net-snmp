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

#define PARTY_MIB_BASE	 ".1.3.6.1.6.3.3.1.3.127.0.0.1.1"
#define CONTEXT_MIB_BASE ".1.3.6.1.6.3.3.1.4.127.0.0.1.1"


int
snmp_synch_input (int, struct snmp_session *, int, struct snmp_pdu *, void *);


struct snmp_pdu *
snmp_pdu_create(int command)
{
    struct snmp_pdu *pdu;

    pdu = (struct snmp_pdu *)calloc(1,sizeof(struct snmp_pdu));
    if (pdu) {
    pdu->version		 = SNMP_DEFAULT_VERSION;
    pdu->command		 = command;
    pdu->errstat		 = SNMP_DEFAULT_ERRSTAT;
    pdu->errindex		 = SNMP_DEFAULT_ERRINDEX;
    pdu->address.sin_addr.s_addr = SNMP_DEFAULT_ADDRESS;
    pdu->securityNameLen	 = -1;
    pdu->contextNameLen		 = -1;
    }

    return pdu;

}  /* end snmp_pdu_create() */


/*
 * Add a null variable with the requested name to the end of the list of
 * variables for this pdu.
 */
struct variable_list* snmp_add_null_var(struct snmp_pdu * pdu, 
					oid *name, 
					int name_length)
{
    return snmp_pdu_add_variable(pdu, name, name_length, ASN_NULL, 0, 0);
}  /* end snmp_add_null_var() */



int
snmp_synch_input(int op,
		 struct snmp_session *session,
		 int reqid,
		 struct snmp_pdu *pdu,
		 void *magic)
{
    struct synch_state *state = (struct synch_state *)magic;
    int rpt_type;

    if (reqid != state->reqid && pdu->command != SNMP_MSG_REPORT)
	return 0;

    state->waiting = 0;
    if (op == RECEIVED_MESSAGE) {
      if (pdu->command == SNMP_MSG_REPORT) {
	rpt_type = snmpv3_get_report_type(pdu);
	if (SNMPV3_IGNORE_UNAUTH_REPORTS || 
	    rpt_type == SNMPERR_NOT_IN_TIME_WINDOW) 
	  state->waiting = 1;
	state->pdu = NULL;
	state->status = STAT_ERROR;
	snmp_errno = rpt_type;
	session->s_snmp_errno = rpt_type;
      } else if (pdu->command == SNMP_MSG_RESPONSE) {
	/* clone the pdu to return to snmp_synch_response */
	state->pdu = snmp_clone_pdu(pdu);
	state->status = STAT_SUCCESS;
	snmp_errno = 0;  /* XX all OK when msg received ? */
	session->s_snmp_errno = 0;
      }
    } else if (op == TIMED_OUT){
	state->pdu		 = NULL;
	state->status		 = STAT_TIMEOUT;
	snmp_errno		 = SNMPERR_TIMEOUT;
	session->s_snmp_errno	 = SNMPERR_TIMEOUT;
    }

    return 1;

}  /* end snmp_synch_input() */


/*
 * Clone an SNMP variable data structure.
 * Sets pointers to structure private storage, or
 * allocates larger object identifiers and values as needed.
 *
 * Caller must make list association for cloned variable.
 *
 * Returns 0 if successful.
 */
int
snmp_clone_var(struct variable_list *var, struct variable_list *newvar)
{
    if (!newvar || !var) return 1;

    memmove(newvar, var, sizeof(struct variable_list));
    newvar->next_variable = 0; newvar->name = 0; newvar->val.string = 0;

    /*
     * Clone the object identifier and the value.
     * Allocate memory iff original will not fit into local storage.
     */
    if (snmp_set_var_objid(newvar, var->name, var->name_length))
        return 1;

    /* need a pointer and a length to copy a string value. */
    if (var->val.string && var->val_len) {
      if (var->val.string != &var->buf[0]){
        if (var->val_len <= sizeof(var->buf))
            newvar->val.string = newvar->buf;
        else {
            newvar->val.string = (u_char *)malloc(var->val_len);
            if (!newvar->val.string) return 1;
        }
        memmove(newvar->val.string, var->val.string, var->val_len);
      }
      else { /* fix the pointer to new local store */
        newvar->val.string = newvar->buf;
      }
    }
    else {
        newvar->val.string = 0; newvar->val_len = 0;
    }

    return 0;
}


/*
 * Possibly make a copy of source memory buffer.
 * Will reset destination pointer if source pointer is NULL.
 * Returns 0 if successful, 1 if memory allocation fails.
 */
static int
snmp_clone_mem(void ** dstPtr, void * srcPtr, unsigned len)
{
    *dstPtr = 0;
    if (srcPtr){
        *dstPtr = malloc(len);
        if (! *dstPtr){
            return 1;
        }
        memmove(*dstPtr, srcPtr, len);
    }
    return 0;
}


/*
 * Creates (allocates and copies) a clone of the input PDU.
 * If drop_err is set, drop any variable associated with errindex.
 *
 * Returns cloned PDU if successful, or 0 if failure.
 */
static
struct snmp_pdu *
locl_clone_pdu(struct snmp_pdu *pdu, int drop_err)
{
    struct variable_list *var, *newvar, *oldvar;
    struct snmp_pdu *newpdu;
    int ii, copied;

    newpdu = (struct snmp_pdu *)malloc(sizeof(struct snmp_pdu));
    if (!newpdu) return 0;
    memmove(newpdu, pdu, sizeof(struct snmp_pdu));

    /* reset copied pointers if copy fails */
    newpdu->variables = 0; newpdu->enterprise = 0; newpdu->community = 0;
    newpdu->srcParty  = 0; newpdu->dstParty   = 0; newpdu->context   = 0;
    newpdu->securityEngineID = 0; newpdu->securityName = 0;
    newpdu->contextEngineID  = 0; newpdu->contextName  = 0;

    /* copy buffers individually. If any copy fails, all are freed. */
    if ( snmp_clone_mem((void **)&newpdu->enterprise, pdu->enterprise,
                                    sizeof(oid)*pdu->enterprise_length)
     ||  snmp_clone_mem((void **)&newpdu->community, pdu->community,
                                    pdu->community_len)
     ||  snmp_clone_mem((void **)&newpdu->contextEngineID, pdu->contextEngineID,
                                    pdu->contextEngineIDLen)
     ||  snmp_clone_mem((void **)&newpdu->securityEngineID, pdu->securityEngineID,
                                    pdu->securityEngineIDLen)
     ||  snmp_clone_mem((void **)&newpdu->contextName, pdu->contextName,
                                    pdu->contextNameLen)
     ||  snmp_clone_mem((void **)&newpdu->securityName, pdu->securityName,
                                    pdu->securityNameLen)
     ||  snmp_clone_mem((void **)&newpdu->srcParty, pdu->srcParty,
                                    sizeof(oid)*pdu->srcPartyLen)
     ||  snmp_clone_mem((void **)&newpdu->dstParty, pdu->dstParty,
                                    sizeof(oid)*pdu->dstPartyLen)
     ||  snmp_clone_mem((void **)&newpdu->context, pdu->context,
                                    sizeof(oid)*pdu->contextLen)
       )
    {
        snmp_free_pdu(newpdu); return 0;
    }

    var = pdu->variables;
    oldvar = 0; ii = 0; copied = 0;
    while (var) {
        /* errindex starts from 1. If drop_err, skip the errored variable */
        if (drop_err && (++ii == pdu->errindex)) {
            var = var->next_variable; continue;
        }

        /* clone the next variable. Cleanup if alloc fails */
        newvar = (struct variable_list *)malloc(sizeof(struct variable_list));
        if (snmp_clone_var(var, newvar)){
            if (newvar) free((char *)newvar);
            snmp_free_pdu(newpdu); return 0;
        }
        copied++;

        /* add cloned variable to new PDU */
        if (0 == newpdu->variables) newpdu->variables = newvar;
        if (oldvar) oldvar->next_variable = newvar;
        oldvar = newvar;

        var = var->next_variable;
    }
    if ((drop_err && (ii < pdu->errindex)) || copied == 0){
        snmp_free_pdu(newpdu); return 0;
    }
    return newpdu;
}

struct snmp_pdu *
snmp_clone_pdu(struct snmp_pdu *pdu)
{
    return locl_clone_pdu(pdu, 0); /* copies all variables */
}

/*
 * If there was an error in the input pdu, creates a clone of the pdu
 * that includes all the variables except the one marked by the errindex.
 * The command is set to the input command and the reqid, errstat, and
 * errindex are set to default values.
 * If the error status didn't indicate an error, the error index didn't
 * indicate a variable, the pdu wasn't a get response message, or there
 * would be no remaining variables, this function will return 0.
 * If everything was successful, a pointer to the fixed cloned pdu will
 * be returned.
 */
struct snmp_pdu *
snmp_fix_pdu(struct snmp_pdu *pdu, int command)
{
    struct snmp_pdu *newpdu;

    if ((pdu->command != SNMP_MSG_RESPONSE)
     || (pdu->errstat == SNMP_ERR_NOERROR)
     || (0 == pdu->variables)
     || (pdu->errindex <= 0))
    {
#if 0
        DEBUGP("Fix PDU ? command 0x%x errstat %d errindex %d vars %x \n",
                pdu->command, pdu->errstat, pdu->errindex, pdu->variables);
#endif
            return 0; /* pre-condition tests fail */
    }

    newpdu = locl_clone_pdu(pdu, 1); /* copies all except errored variable */
    if (!newpdu)
        return 0;
    if (!newpdu->variables) {
        snmp_free_pdu(newpdu);
        return 0; /* no variables. "should not happen" */
    }
    newpdu->command = command;
    newpdu->reqid = SNMP_DEFAULT_REQID;
    newpdu->errstat = SNMP_DEFAULT_ERRSTAT;
    newpdu->errindex = SNMP_DEFAULT_ERRINDEX;

    return newpdu;
}

/*
 * Add object identifier name to SNMP variable.
 * If the name is large, additional memory is allocated.
 * Returns 0 if successful.
 */

int
snmp_set_var_objid (struct variable_list *vp,
                    const oid *objid, int name_length)
{
    int len = sizeof(oid) * name_length;

    /* use built-in storage for smaller values */
    if (len <= sizeof(vp->name_loc)) {
        vp->name = vp->name_loc;
    }
    else {
        vp->name = (oid *)malloc(len);
        if (!vp->name) return 1;
    }
    memmove(vp->name, objid, len);
    vp->name_length = name_length;
    return 0;
}

/*
 * Add some value to SNMP variable.
 * If the value is large, additional memory is allocated.
 * Returns 0 if successful.
 */

int
snmp_set_var_value(struct variable_list *newvar,
                    char *val_str, int val_len)
{
    if (newvar->val.string &&
        newvar->val.string != newvar->buf)
    {
        free(newvar->val.string);
    }

    newvar->val.string = 0; newvar->val_len = 0;

    /* need a pointer and a length to copy a string value. */
    if (val_str && val_len)
    {
        if (val_len <= sizeof(newvar->buf))
            newvar->val.string = newvar->buf;
        else {
            newvar->val.string = (u_char *)malloc(val_len);
            if (!newvar->val.string) return 1;
        }
        memmove(newvar->val.string, val_str, val_len);
        newvar->val_len = val_len;
    }

    return 0;
}


int
snmp_synch_response(struct snmp_session *ss,
		    struct snmp_pdu *pdu,
		    struct snmp_pdu **response)
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
snmp_sess_synch_response(void *sessp,
			 struct snmp_pdu *pdu,
			 struct snmp_pdu **response)
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
	    snmp_sess_read(sessp, &fdset);
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

void snmp_synch_reset(struct snmp_session *session)
{
    if (session && session->snmp_synch_state)
       free((char*)session->snmp_synch_state);
}

void
snmp_synch_setup(struct snmp_session *session)
{
    struct synch_state *rp = (struct synch_state *)calloc(1,sizeof(struct synch_state));
    session->snmp_synch_state = rp;

    session->callback = snmp_synch_input;
    session->callback_magic = (void *)rp;
}

char	*error_string[19] = {
    (char*)"(noError) No Error",
    (char*)"(tooBig) Response message would have been too large.",
    (char*)"(noSuchName) There is no such variable name in this MIB.",
    (char*)"(badValue) The value given has the wrong type or length.",
    (char*)"(readOnly) The two parties used do not have access to use the specified SNMP PDU.",
    (char*)"(genError) A general failure occured",
    (char*)"noAccess",
    (char*)"wrongType",
    (char*)"wrongLength",
    (char*)"wrongEncoding",
    (char*)"wrongValue",
    (char*)"noCreation",
    (char*)"inconsistentValue",
    (char*)"resourceUnavailable",
    (char*)"commitFailed",
    (char*)"undoFailed",
    (char*)"authorizationError",
    (char*)"notWritable",
    (char*)"inconsistentName"
};

char *
snmp_errstring(int errstat)
{
    if (errstat <= MAX_SNMP_ERR && errstat >= SNMP_ERR_NOERROR){
	return error_string[errstat];
    } else {
	return "Unknown Error";
    }
}


#ifdef USE_V2PARTY_PROTOCOL
/*******************************************************************-o-******
 * ms_party_init
 *
 * Parameters:
 *	 destaddr
 *	*src
 *	*srclen
 *	*dst
 *	*dstlen
 *	*context
 *	*contextllen
 *      
 * Returns:
 *	0		Success.
 *	-1		Otherwise.
 *
 * Initializes a noAuth/noPriv party pair, a context, and 2 acl entries.
 *
 * XXX  Are two acl entries really needed?
 */
int
ms_party_init(	in_addr_t	 destaddr,
		oid		*src,		int	*srclen,
		oid		*dst,		int	*dstlen,
		oid		*context,	int	*contextlen)
{
#define PARTYCOMPLETE_MASK	65535
#define PARTYCOMPLETE_MASK	65535
#define CONTEXTCOMPLETE_MASK	0x03FF
#define ACLCOMPLETE_MASK	0x3F

    u_short		 port;
    int			 oneIndex, twoIndex, cxindex;
    u_long		 addr;

    unsigned char	*adp;

    struct partyEntry	*pp1, *pp2, *rp;
    struct contextEntry	*cxp, *rxp;
    struct aclEntry	*ap;


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

	pp1->partyTAddressLen	 = rp->partyTAddressLen		= 6;
	pp1->partyAuthProtocol	 = rp->partyAuthProtocol	= NOAUTH;
	pp1->partyAuthClock	 = rp->partyAuthClock		= 0;
	pp1->tv.tv_sec		 = pp1->partyAuthClock;
	pp1->partyAuthPublicLen	 = 0;
	pp1->partyAuthLifetime	 = rp->partyAuthLifetime	= 0;
	pp1->partyPrivProtocol	 = rp->partyPrivProtocol	= NOPRIV;
	pp1->partyPrivPublicLen	 = 0;
	pp1->partyMaxMessageSize = rp->partyMaxMessageSize	= 1500;
	pp1->partyLocal		 = 2; /* FALSE */
	pp1->partyAuthPrivateLen = rp->partyAuthPrivateLen	= 0;
	pp1->partyPrivPrivateLen = rp->partyPrivPrivateLen	= 0;
	pp1->partyStorageType	 = 2; /* volatile */
	pp1->partyStatus	 = rp->partyStatus	= SNMP_ROW_ACTIVE;

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

	pp2->partyTAddressLen	 = rp->partyTAddressLen		= 6;
	pp2->partyAuthProtocol	 = rp->partyAuthProtocol	= NOAUTH;
	pp2->partyAuthClock	 = rp->partyAuthClock		= 0;
	pp2->tv.tv_sec		 = pp2->partyAuthClock;
	pp2->partyAuthPublicLen	 = 0;
	pp2->partyAuthLifetime	 = rp->partyAuthLifetime	= 0;
	pp2->partyPrivProtocol	 = rp->partyPrivProtocol	= NOPRIV;
	pp2->partyPrivPublicLen	 = 0;
	pp2->partyMaxMessageSize = rp->partyMaxMessageSize	= 484; /* ??? */
	pp2->partyLocal		 = 2; /* FALSE */
	pp2->partyAuthPrivateLen = rp->partyAuthPrivateLen	= 0;
	pp2->partyPrivPrivateLen = rp->partyPrivPrivateLen	= 0;
	pp2->partyStorageType	 = 2; /* volatile */
	pp2->partyStatus	 = rp->partyStatus	= SNMP_ROW_ACTIVE;

	/* all collumns - from party_vars.c XXX */
	pp2->partyBitMask = rp->partyBitMask = PARTYCOMPLETE_MASK;
    }
    twoIndex = pp2->partyIndex;

    if (!read_objid(CONTEXT_MIB_BASE, context, contextlen)){
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

	cxp->contextLocal		= 2;	/* FALSE */
	cxp->contextViewIndex		= -1;	/* unknown */
	cxp->contextLocalEntityLen	= 0;
	cxp->contextLocalTime		= CURRENTTIME;
	cxp->contextProxyContextLen	= 0;
	cxp->contextStorageType		= 2;
	cxp->contextStatus		= rxp->contextStatus = SNMP_ROW_ACTIVE;

	/* all collumns - from context_vars.c XXX
	 */
	cxp->contextBitMask = rxp->contextBitMask = CONTEXTCOMPLETE_MASK;
    }
    cxindex = cxp->contextIndex;

    ap = acl_getEntry(oneIndex, twoIndex, cxindex);
    if (!ap){
	ap		   	 = acl_createEntry(oneIndex, twoIndex, cxindex);
	ap->aclPriveleges  	 = 132;
	ap->aclStorageType 	 = 2; /* volatile */
	ap->aclStatus	   	 = SNMP_ROW_ACTIVE;
	/* all collumns - from acl_vars.c XXX
	 */
	ap->aclBitMask	   	 = ACLCOMPLETE_MASK;
	ap->reserved->aclBitMask = ap->aclBitMask;
    }


    return 0; /* SUCCESS */
}

#endif /* USE_V2PARTY_PROTOCOL */
