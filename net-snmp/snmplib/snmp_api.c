/******************************************************************
	Copyright 1989, 1991, 1992 by Carnegie Mellon University

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
/*
 * snmp_api.c - API for access to snmp.
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netdb.h>
#include "asn1.h"
#include "snmp.h"
#include "snmp_impl.h"
#include "snmp_api.h"

#define PACKET_LENGTH	8000

#ifndef BSD4_3
#define BSD4_2
#endif

#ifndef FD_SET

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif

oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1};
/* enterprises.cmu.systems.cmuSNMP */

#define DEFAULT_COMMUNITY   "public"
#define DEFAULT_RETRIES	    5
#define DEFAULT_TIMEOUT	    1000000L
#define DEFAULT_REMPORT	    SNMP_PORT
#define DEFAULT_ENTERPRISE  default_enterprise
#define DEFAULT_TIME	    0

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    int	    sd;		/* socket descriptor for this connection */
    ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
    struct request_list *requestsEnd; /* ptr to end of list */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    long  request_id;	/* request id */
    int	    retries;	/* Number of retries */
    u_long timeout;	/* length to wait for timeout */
    struct timeval time; /* Time this request was made */
    struct timeval expire;  /* time this request is due to expire */
    struct snmp_pdu *pdu;   /* The pdu for this request
			       (saved so it can be retransmitted */
};

struct internal_variable_list {
    struct variable_list *next_variable;    /* NULL for last variable */
    oid     *name;  /* Object identifier of variable */
    int     name_length;    /* number of subid's in name */
    u_char  type;   /* ASN type of variable */
    union { /* value of variable */
        long    *integer;
        u_char  *string;
        oid     *objid;
        u_char  *bitstring;
        struct counter64 *counter64;
    } val;
    int     val_len;
    oid name_loc[MAX_NAME_LEN];
    u_char buf[32];
    int usedBuf;
};

struct internal_snmp_pdu {
    int     version;

    ipaddr  address;    /* Address of peer */
    oid     *srcParty;
    int     srcPartyLen;
    oid     *dstParty;
    int     dstPartyLen;
    oid     *context;
    int     contextLen;

    u_char  *community; /* community for outgoing requests. */
    int     community_len;  /* Length of community name. */

    int     command;    /* Type of this PDU */

    long  reqid;        /* Request id */
    long  errstat;      /* Error status (non_repeaters in GetBulk) */
    long  errindex;     /* Error index (max_repetitions in GetBulk) */

    /* Trap information */
    oid     *enterprise;/* System OID */
    int     enterprise_length;
    ipaddr  agent_addr; /* address of object generating trap */
    int     trap_type;  /* trap type */
    int     specific_type;  /* specific type */
    u_long  time;       /* Uptime */

    struct variable_list *variables;
    oid srcPartyBuf[MAX_NAME_LEN];
    oid dstPartyBuf[MAX_NAME_LEN];
    oid contextBuf[MAX_NAME_LEN];
    /* XXX do community later */
    
};

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

struct session_list *Sessions = NULL;

long Reqid = 0;
int snmp_errno = 0;

char *api_errors[4] = {
    "Unknown session",
    "Unknown host",
    "Invalid local port",
    "Unknown Error"
};

struct timeval Now;
struct snmp_pdu *SavedPdu = NULL;
struct internal_variable_list *SavedVars = NULL;

static char *
api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    if (snmp_errnumber <= SNMPERR_BAD_SESSION
	&& snmp_errnumber >= SNMPERR_GENERR){
	return api_errors[snmp_errnumber + 4];
    } else {
	return "Unknown Error";
    }
}


/*
 * Gets initial request ID for all transactions.
 */
static
init_snmp(){
    struct timeval tv;

    gettimeofday(&tv, (struct timezone *)0);
    Now = tv;
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
}

/*
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *
snmp_open(session)
    struct snmp_session *session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    u_char *cp;
    oid *op;
    int sd;
    u_long addr;
    struct sockaddr_in	me;
    struct hostent *hp;
    struct servent *servp;


    if (Reqid == 0)
	init_snmp();

    /* Copy session structure and link into list */
    slp = (struct session_list *)malloc(sizeof(struct session_list));
    slp->internal = isp = (struct snmp_internal_session *)malloc(sizeof(struct snmp_internal_session));
    bzero((char *)isp, sizeof(struct snmp_internal_session));
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)malloc(sizeof(struct snmp_session));
    bcopy((char *)session, (char *)slp->session, sizeof(struct snmp_session));
    session = slp->session;
    /* now link it in. */
    slp->next = Sessions;
    Sessions = slp;
    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)malloc((unsigned)strlen(session->peername) + 1);
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	cp = (u_char *)malloc((unsigned)session->community_len);
	bcopy((char *)session->community, (char *)cp, session->community_len);
    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)malloc((unsigned)session->community_len);
	bcopy((char *)DEFAULT_COMMUNITY, (char *)cp, session->community_len);
    }
    session->community = cp;	/* replace pointer with pointer to new data */

    if (session->srcPartyLen > 0){
	op = (oid *)malloc((unsigned)session->srcPartyLen * sizeof(oid));
	bcopy((char *)session->srcParty, (char *)op,
	      session->srcPartyLen * sizeof(oid));
	session->srcParty = op;
    } else {
	session->srcParty = 0;
    }

    if (session->dstPartyLen > 0){
	op = (oid *)malloc((unsigned)session->dstPartyLen * sizeof(oid));
	bcopy((char *)session->dstParty, (char *)op,
	      session->dstPartyLen * sizeof(oid));
	session->dstParty = op;
    } else {
	session->dstParty = 0;
    }

    if (session->contextLen > 0){
	op = (oid *)malloc((unsigned)session->contextLen * sizeof(oid));
	bcopy((char *)session->context, (char *)op,
	      session->contextLen * sizeof(oid));
	session->context = op;
    } else {
	session->context = 0;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = DEFAULT_TIMEOUT;
    isp->requests = isp->requestsEnd = NULL;

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	perror("socket");
	snmp_errno = SNMPERR_GENERR;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n",
		    api_errstring(snmp_errno));
	    exit(1);
	}
	return 0;
    }
    isp->sd = sd;
    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((addr = inet_addr(session->peername)) != -1){
	    bcopy((char *)&addr, (char *)&isp->addr.sin_addr,
		  sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		fprintf(stderr, "unknown host: %s\n", session->peername);
		snmp_errno = SNMPERR_BAD_ADDRESS;
		if (!snmp_close(session)){
		    fprintf(stderr, "Couldn't abort session: %s. Exiting\n",
			    api_errstring(snmp_errno));
		    exit(2);
		}
		return 0;
	    } else {
		bcopy((char *)hp->h_addr, (char *)&isp->addr.sin_addr,
		      hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
	    servp = getservbyname("snmp", "udp");
	    if (servp != NULL){
		isp->addr.sin_port = servp->s_port;
	    } else {
		isp->addr.sin_port = htons(SNMP_PORT);
	    }
	} else {
	    isp->addr.sin_port = htons(session->remote_port);
	}
    } else {
	isp->addr.sin_addr.s_addr = SNMP_DEFAULT_ADDRESS;
    }

    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	perror("bind");
	snmp_errno = SNMPERR_BAD_LOCPORT;
	if (!snmp_close(session)){
	    fprintf(stderr, "Couldn't abort session: %s. Exiting\n",
		    api_errstring(snmp_errno));
	    exit(3);
	}
	return 0;
    }
    return session;
}


/*
 * Free each element in the input request list.
 */
static
free_request_list(rp)
    struct request_list *rp;
{
    struct request_list *orp;

    while(rp){
	orp = rp;
	rp = rp->next_request;
	if (orp->pdu != NULL)
	    snmp_free_pdu(orp->pdu);
	free((char *)orp);
    }
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    if (Sessions->session == session){	/* If first entry */
	slp = Sessions;
	Sessions = slp->next;
    } else {
	for(slp = Sessions; slp; slp = slp->next){
	    if (slp->session == session){
		if (oslp)   /* if we found entry that points here */
		    oslp->next = slp->next;	/* link around this entry */
		break;
	    }
	    oslp = slp;
	}
    }
    /* If we found the session, free all data associated with it */
    if (slp){
	if (slp->session->community != NULL)
	    free((char *)slp->session->community);
	if(slp->session->peername != NULL)
	    free((char *)slp->session->peername);
	if (slp->session->srcParty != NULL)
	    free((char *)slp->session->srcParty);
	if (slp->session->dstParty != NULL)
	    free((char *)slp->session->dstParty);
	if (slp->session->context != NULL)
	    free((char *)slp->session->context);
	free((char *)slp->session);
	if (slp->internal->sd != -1)
	    close(slp->internal->sd);
	free_request_list(slp->internal->requests);
	free((char *)slp->internal);
	free((char *)slp);
    } else {
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return 1;
}

shift_array(begin, length, shift_amount)
    u_char          *begin;
    register int    length;
    int             shift_amount;
{
    register u_char     *old, *new;

    if (shift_amount >= 0){
        old = begin + length - 1;
        new = old + shift_amount;

        while(length--)
            *new-- = *old--;
    } else {
        old = begin;
        new = begin + shift_amount;

        while(length--)
            *new++ = *old++;
    }
}

/*
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
static int
snmp_build(session, pdu, packet, out_length)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    register u_char	*packet;
    int			*out_length;
{
    u_char  *authEnd, *h1, *h1e, *h2;
    register u_char  *cp;
    struct variable_list *vp;
    struct  packet_info pkt, *pi = &pkt;
    int length, packet_length, header_length;

    if (session->version == SNMP_VERSION_1){
        cp = snmp_auth_build(packet, out_length, pdu->community,
                         &pdu->community_len, &pdu->version,
                         0);
        if (cp == NULL)
            return -1;
    } else if (session->version == SNMP_VERSION_2){
        pi->version = session->version;
        pi->srcp = NULL;
        pi->dstp = NULL;
        cp = snmp_secauth_build(packet, out_length, pi, 0,
                             pdu->srcParty, pdu->srcPartyLen,
                             pdu->dstParty, pdu->dstPartyLen,
                             pdu->context, pdu->contextLen,
                             0, FIRST_PASS);
        if (cp == NULL)
            return -1;
    } else {
	return -1;
    }
    authEnd = cp;

    h1 = cp;
    if (session->version == SNMP_VERSION_1)
	cp = asn_build_header(cp, out_length, (u_char)pdu->command, 0);
    else
	cp = asn_build_sequence(cp, out_length, (u_char)pdu->command, 0);
    if (cp == NULL)
        return -1;
    h1e = cp;
    
    if (pdu->command != TRP_REQ_MSG){
        /* request id */
        cp = asn_build_int(cp, out_length,
            (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &pdu->reqid, sizeof(pdu->reqid));
        if (cp == NULL)
            return -1;
        /* error status */
        cp = asn_build_int(cp, out_length,
                (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                &pdu->errstat, sizeof(pdu->errstat));
        if (cp == NULL)
            return -1;
        /* error index */
        cp = asn_build_int(cp, out_length,
                (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                &pdu->errindex, sizeof(pdu->errindex));
        if (cp == NULL)
            return -1;
    } else {    /* this is a trap message */
        /* enterprise */
        cp = asn_build_objid(cp, out_length,
            (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            (oid *)pdu->enterprise, pdu->enterprise_length);
        if (cp == NULL)
            return -1;
        /* agent-addr */
        cp = asn_build_string(cp, out_length,
                (u_char)(IPADDRESS | ASN_PRIMITIVE),
                (u_char *)&pdu->agent_addr.sin_addr.s_addr,
                              sizeof(pdu->agent_addr.sin_addr.s_addr));
        if (cp == NULL)
            return -1;
        /* generic trap */
        cp = asn_build_int(cp, out_length,
                (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                (long *)&pdu->trap_type, sizeof(pdu->trap_type));
        if (cp == NULL)
            return -1;
        /* specific trap */
        cp = asn_build_int(cp, out_length,
                (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                (long *)&pdu->specific_type, sizeof(pdu->specific_type));
        if (cp == NULL)
            return -1;
        /* timestamp  */
        cp = asn_build_unsigned_int(cp, out_length,
                (u_char)(TIMETICKS | ASN_PRIMITIVE),
                &pdu->time, sizeof(pdu->time));
        if (cp == NULL)
            return -1;
    }

    h2 = cp;
    cp = asn_build_sequence(cp, out_length,
                          (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                          0);
    if (cp == NULL)
        return -1;

    for(vp = pdu->variables; vp; vp = vp->next_variable){
        cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type,
                               vp->val_len, (u_char *)vp->val.string,
			       out_length);
        if (cp == NULL)
            return -1;
    }

    length = PACKET_LENGTH;
    asn_build_sequence(h2, &length,
		       (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                          (cp - h2) - 4);
    if (session->version == SNMP_VERSION_1){
	if ((cp - h1e) < 0x80)
	    header_length = 2;
	else if ((cp - h1e) <= 0xFF)
	    header_length = 3;
	else
	    header_length = 4;
	shift_array(h1e, cp - h1e, header_length + h1 - h1e);
	asn_build_header(h1, &length, (u_char)pdu->command, cp - h1e);
	cp += header_length + h1 - h1e;
    } else {
	asn_build_sequence(h1, &length, (u_char)pdu->command, (cp - h1) - 4);
    }
    
    if (session->version == SNMP_VERSION_1){
        snmp_auth_build(packet, &length, pdu->community,
                         &pdu->community_len, &pdu->version,
                         cp - authEnd);
    } else if (session->version == SNMP_VERSION_2){
        snmp_secauth_build(packet, &length, pi, cp - authEnd,
                             pdu->srcParty, pdu->srcPartyLen,
                             pdu->dstParty, pdu->dstPartyLen,
                             pdu->context, pdu->contextLen,
                             &packet_length, LAST_PASS);
	cp = packet + packet_length;
	/* DES encryption might bump length of packet */
    }
    *out_length = cp - packet;
    return 0;
}

/*
 * Parses the packet recieved on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct internal_snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  msg_type;
    u_char  type;
    struct packet_info pkt, *pi = &pkt;
    u_char  *var_val;
    long    version;
    int	    len, four;
    u_char community[128];
    int community_length = 128;
    struct internal_variable_list *vp;
    oid	    objid[MAX_NAME_LEN], *op;

    len = length;
    (void)asn_parse_header(data, &len, &type);

    if (type == (ASN_SEQUENCE | ASN_CONSTRUCTOR)){
	if (session->version != SNMP_VERSION_1)
	    return -1;
	/* authenticates message and returns length if valid */
	data = snmp_auth_parse(data, &length, community, &community_length,
			       &version);
	if (data == NULL)
	    return -1;
	pdu->community_len = community_length;
	pdu->community = (u_char *)malloc(community_length);
	bcopy(community, pdu->community, community_length);
	if (session->authenticator){
	    data = session->authenticator(data, &length,
					  community, community_length);
	    if (data == NULL)
		return 0;
	}

    } else if (type == (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)){
	if (session->version != SNMP_VERSION_2)
	    return -1;
	pdu->srcParty = pdu->srcPartyBuf;
	pdu->dstParty = pdu->dstPartyBuf;
	pdu->context  = pdu->contextBuf;
        pdu->srcPartyLen = MAX_NAME_LEN;
        pdu->dstPartyLen = MAX_NAME_LEN;
        pdu->contextLen  = MAX_NAME_LEN;

	/* authenticates message and returns length if valid */
	data = snmp_secauth_parse(data, &length, pi,
				  pdu->srcParty, &pdu->srcPartyLen,
				  pdu->dstParty, &pdu->dstPartyLen,
				  pdu->context, &pdu->contextLen,
				  FIRST_PASS | LAST_PASS);
	if (data == NULL)
	    return -1;
	version = pi->version;
    } else {
        ERROR("unknown auth header type");
        return NULL;
    }
    pdu->version = version;

    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;

    /* the calling sequence for has_access is wrong - fix it or nuke it XXX */
    /* should the following be for version 2?  If so make it so, if not,
     * nuke it.
     */
    if (version == SNMP_SECURITY_1
	&& !has_access(msg_type, pdu->srcParty, pdu->srcPartyLen,
		       pdu->dstParty, pdu->dstPartyLen))
	return -1;
    pdu->command = msg_type;
    if (pdu->command != TRP_REQ_MSG){
	data = asn_parse_int(data, &length, &type, &pdu->reqid,
			     sizeof(pdu->reqid));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, &pdu->errstat,
			     sizeof(pdu->errstat));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, &pdu->errindex,
			     sizeof(pdu->errindex));
	if (data == NULL)
	    return -1;
    } else {
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid,
			       &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)malloc(pdu->enterprise_length * sizeof(oid));
	bcopy((char *)objid, (char *)pdu->enterprise,
	      pdu->enterprise_length * sizeof(oid));

	four = 4;
	data = asn_parse_string(data, &length, &type,
				(u_char *)&pdu->agent_addr.sin_addr.s_addr,
				&four);
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type,
			     sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type,
			     sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;
	data = asn_parse_unsigned_int(data, &length, &type, &pdu->time,
				      sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;
    while((int)length > 0){
	if (pdu->variables == NULL){
	    if (SavedVars){
		pdu->variables = (struct variable_list *)SavedVars;
		vp = SavedVars;
		SavedVars =
		    (struct internal_variable_list *)SavedVars->next_variable;
	    } else {
		vp = (struct internal_variable_list *)
		    malloc(sizeof(struct internal_variable_list));
		pdu->variables = (struct variable_list *)vp;
	    }
	} else {
	    if (SavedVars){
		vp->next_variable = (struct variable_list *)SavedVars;
		SavedVars =
		    (struct internal_variable_list *)SavedVars->next_variable;
		vp = (struct internal_variable_list *)vp->next_variable;
	    } else {
		vp->next_variable =
		    (struct variable_list *)malloc(sizeof(struct internal_variable_list));
		vp = (struct internal_variable_list *)vp->next_variable;
	    }
	}
	vp->next_variable = NULL;
	vp->val.string = NULL;
	vp->name = NULL;
	vp->name_length = MAX_NAME_LEN;
	vp->name = vp->name_loc;
	vp->usedBuf = FALSE;
	data = snmp_parse_var_op(data, vp->name, &vp->name_length, &vp->type,
				 &vp->val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return -1;

	len = PACKET_LENGTH;
	switch((short)vp->type){
	    case ASN_INTEGER:
		vp->val.integer = (long *)vp->buf;
		vp->usedBuf = TRUE;
		vp->val_len = sizeof(long);
		asn_parse_int(var_val, &len, &vp->type,
			      (long *)vp->val.integer,
			      sizeof(vp->val.integer));
		break;
	    case COUNTER:
	    case GAUGE:
	    case TIMETICKS:
	    case UINTEGER:
		vp->val.integer = (long *)vp->buf;
		vp->usedBuf = TRUE;
		vp->val_len = sizeof(u_long);
		asn_parse_unsigned_int(var_val, &len, &vp->type,
				       (u_long *)vp->val.integer,
				       sizeof(vp->val.integer));
		break;
	    case COUNTER64:
		vp->val.counter64 = (struct counter64 *)vp->buf;
		vp->usedBuf = TRUE;
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
	    case ASN_OCTET_STR:
	    case IPADDRESS:
	    case OPAQUE:
	    case NSAP:
		if (vp->val_len < 32){
		    vp->val.string = (u_char *)vp->buf;
		    vp->usedBuf = TRUE;
		} else {
		    vp->val.string = (u_char *)malloc((unsigned)vp->val_len);
		}
		asn_parse_string(var_val, &len, &vp->type, vp->val.string,
				 &vp->val_len);
		break;
	    case ASN_OBJECT_ID:
		vp->val_len = MAX_NAME_LEN;
		asn_parse_objid(var_val, &len, &vp->type, objid, &vp->val_len);
		vp->val_len *= sizeof(oid);
		vp->val.objid = (oid *)malloc((unsigned)vp->val_len);
		bcopy((char *)objid, (char *)vp->val.objid, vp->val_len);
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
		break;
	    case ASN_BIT_STR:
		vp->val.bitstring = (u_char *)malloc(vp->val_len);
		asn_parse_bitstring(var_val, &len, &vp->type,
				    vp->val.bitstring, &vp->val_len);
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", vp->type);
		break;
	}
    }
    return 0;
}

/*
 * Sends the input pdu on the session after calling snmp_build to create
 * a serialized packet.  If necessary, set some of the pdu data from the
 * session defaults.  Add a request corresponding to this pdu to the list
 * of outstanding requests on this session, then send the pdu.
 * Returns the request id of the generated packet if applicable, otherwise 1.
 * On any error, 0 is returned.
 * The pdu is freed by snmp_send() unless a failure occured.
 */
int
snmp_send(session, pdu)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
{
    struct session_list *slp;
    struct snmp_internal_session *isp = NULL;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    isp = slp->internal;
	    break;
	}
    }
    if (isp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == GET_RSP_MSG || pdu->command == SET_REQ_MSG){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else if (pdu->command == INFORM_REQ_MSG || pdu->command == TRP2_REQ_MSG){
	if (session->version != SNMP_VERSION_2){
	    fprintf(stderr, "Cant send SNMP PDU's in SNMPv2 message.\n");
	    snmp_errno = SNMPERR_GENERR;/* Fix this XXXXX */
	    return 0;
	}
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
    } else if (pdu->command == BULK_REQ_MSG){
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	    pdu->reqid = ++Reqid;
	if (pdu->max_repetitions < 0 || pdu->non_repeaters < 0){
	    fprintf(stderr, "Invalid parameters for max_repetitions or non_repeaters\n");
	    snmp_errno = SNMPERR_GENERR;	/* Fix this XXXXX */
	    return 0;
	}
	    
    } else {
	if (session->version == SNMP_VERSION_2){
	    fprintf(stderr, "Cant send old Trap PDU in SNMPv2 message.\n");
	    snmp_errno = SNMPERR_GENERR;/* Fix this XXXXX */
	    return 0;
	}
	/* fill in trap defaults */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)malloc(sizeof(DEFAULT_ENTERPRISE));
	    bcopy((char *)DEFAULT_ENTERPRISE, (char *)pdu->enterprise,
		  sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
    }
    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    bcopy((char *)&isp->addr, (char *)&pdu->address,
		  sizeof(pdu->address));
	} else {
	    fprintf(stderr, "No remote IP address specified\n");
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    return 0;
	}
    }
	
    /* !!!!!!!!!!!!!!!!!!!!!! MAJOR PROBLEM  !!!!!!!!!!!!!!!!!!!!!!!
     *
     * This stuff needs to be cleanly added to the api.
     * currently some applications are passing non-malloc'd data.
     * we can't free this stuff because they would get hosed.
     * Therefore this is a core leak.
     * !!!!!!!!!!!!!!!!!!!!!! MAJOR PROBLEM  !!!!!!!!!!!!!!!!!!!!!!!
     */
    if (pdu->version == SNMP_DEFAULT_VERSION){
	pdu->version = session->version;
    }
    if (pdu->version == SNMP_DEFAULT_VERSION){
	fprintf(stderr, "No version specified\n");
	snmp_errno = SNMPERR_BAD_ADDRESS;
	return 0;
    }
    if (pdu->version == SNMP_VERSION_2){
	if (pdu->srcPartyLen == 0){
	    if (session->srcPartyLen == 0){
		fprintf(stderr, "No source party specified\n");
		snmp_errno = SNMPERR_BAD_ADDRESS;
		return 0;
	    }
	    pdu->srcParty = (oid *)malloc(session->srcPartyLen * sizeof(oid));
	    bcopy((char *)session->srcParty, (char *)pdu->srcParty,
		  session->srcPartyLen * sizeof(oid));
	    pdu->srcPartyLen = session->srcPartyLen;
	}
	if (pdu->dstPartyLen == 0){
	    if (session->dstPartyLen == 0){
		fprintf(stderr, "No destination party specified\n");
		snmp_errno = SNMPERR_BAD_ADDRESS;
		return 0;
	    }
	    pdu->dstParty = (oid *)malloc(session->dstPartyLen * sizeof(oid));
	    bcopy((char *)session->dstParty, (char *)pdu->dstParty,
		  session->dstPartyLen * sizeof(oid));
	    pdu->dstPartyLen = session->dstPartyLen;
	}
	if (pdu->contextLen == 0){
	    if (session->contextLen == 0){
		fprintf(stderr, "No context specified\n");
		snmp_errno = SNMPERR_BAD_ADDRESS;
		return 0;
	    }
	    pdu->context = (oid *)malloc(session->contextLen * sizeof(oid));
	    bcopy((char *)session->context, (char *)pdu->context,
		  session->contextLen * sizeof(oid));
	    pdu->contextLen = session->contextLen;
	}
    } else if (pdu->version == SNMP_VERSION_1){
	if (pdu->community_len == 0){
	    if (session->community_len == 0){
		fprintf(stderr, "No community name specified\n");
		snmp_errno = SNMPERR_BAD_ADDRESS;
		return 0;
	    }
	    pdu->community = (u_char *)malloc(session->community_len);
	    bcopy((char *)session->community, (char *)pdu->community,
		  session->community_len);
	    pdu->community_len = session->community_len;
	}
    }

    if (snmp_build(session, pdu, packet, &length) < 0){
	fprintf(stderr, "Error building packet\n");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
    if (snmp_dump_packet){
	printf("sending %d bytes to %s:\n", length,
	       inet_ntoa(pdu->address.sin_addr));
	xdump(packet, length, "");
        printf("\n\n");
    }


    if (sendto(isp->sd, (char *)packet, length, 0,
	       (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	perror("sendto");
	snmp_errno = SNMPERR_GENERR;
	return 0;
    }
/*    gettimeofday(&tv, (struct timezone *)0); */
    tv = Now;
    if (pdu->command == GET_REQ_MSG || pdu->command == GETNEXT_REQ_MSG
	|| pdu->command == SET_REQ_MSG || pdu->command == BULK_REQ_MSG
	|| pdu->command == INFORM_REQ_MSG){
	/* set up to expect a response */
	rp = (struct request_list *)malloc(sizeof(struct request_list));
	if (isp->requestsEnd){
	    rp->next_request = isp->requestsEnd->next_request;
	    isp->requestsEnd->next_request = rp;
	    isp->requestsEnd = rp;
	} else {
	    rp->next_request = isp->requests;
	    isp->requests = rp;
	    isp->requestsEnd = rp;
	}
	rp->pdu = pdu;
	rp->request_id = pdu->reqid;

	rp->retries = 1;
	rp->timeout = session->timeout;
	rp->time = tv;
	tv.tv_usec += rp->timeout;
	tv.tv_sec += tv.tv_usec / 1000000L;
	tv.tv_usec %= 1000000L;
	rp->expire = tv;
    }
    return pdu->reqid;
}

/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_pdu(pdu)
    struct snmp_pdu *pdu;
{
    struct variable_list *vp, *ovp;

    vp = pdu->variables;
    while(vp){
	if (vp->name)
	    free((char *)vp->name);
	if (vp->val.string)
	    free((char *)vp->val.string);
	ovp = vp;
	vp = vp->next_variable;
	free((char *)ovp);
    }
    if (pdu->enterprise)
	free((char *)pdu->enterprise);
    free((char *)pdu);
}


/*
 * Frees the pdu and any malloc'd data associated with it.
 */
void
snmp_free_internal_pdu(pdu)
    struct snmp_pdu *pdu;
{
    struct internal_variable_list *vp, *ovp;

    vp = (struct internal_variable_list *)pdu->variables;
    while(vp){
	if (vp->val.string && !vp->usedBuf)
	    free((char *)vp->val.string);
	ovp = vp;
	vp = (struct internal_variable_list *)vp->next_variable;
	ovp->next_variable = (struct variable_list *)SavedVars;
	SavedVars = ovp;
    }
    if (pdu->enterprise)
	free((char *)pdu->enterprise);
    if (!SavedPdu)
	SavedPdu = pdu;
    else
	free((char *)pdu);
    
}


/*
 * Checks to see if any of the fd's set in the fdset belong to
 * snmp.  Each socket with it's fd set has a packet read from it
 * and snmp_parse is called on the packet received.  The resulting pdu
 * is passed to the callback routine for that session.  If the callback
 * routine returns successfully, the pdu and it's request are deleted.
 */
void
snmp_read(fdset)
    fd_set  *fdset;
{
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    int length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp, *orp;

    for(slp = Sessions; slp; slp = slp->next){
	if (FD_ISSET(slp->internal->sd, fdset)){
	    sp = slp->session;
	    isp = slp->internal;
	    fromlength = sizeof from;
	    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0,
			      (struct sockaddr *)&from, &fromlength);
	    if (length == -1)
		perror("recvfrom");
	    if (snmp_dump_packet){
		printf("received %d bytes from %s:\n", length,
		       inet_ntoa(from.sin_addr));
		xdump(packet, length, "");
                printf("\n\n");
	    }

	    if (SavedPdu){
		pdu = SavedPdu;
		SavedPdu = NULL;
	    } else {
		pdu = (struct snmp_pdu *)malloc(sizeof(struct internal_snmp_pdu));
	    }
	    pdu->address = from;
	    pdu->reqid = 0;
	    pdu->variables = NULL;
	    pdu->enterprise = NULL;
	    pdu->enterprise_length = 0;
	    if (snmp_parse(sp, pdu, packet, length) != SNMP_ERR_NOERROR){
		fprintf(stderr, "Unrecognizable or unauthentic packet received\n");
		snmp_free_internal_pdu(pdu);
		return;
	    }

	    if (pdu->command == GET_RSP_MSG){
		for(rp = isp->requests; rp; rp = rp->next_request){
		    if (rp->request_id == pdu->reqid){
			if (sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid,
					 pdu, sp->callback_magic) == 1){
			    /* successful, so delete request */
			    orp = rp;
			    if (isp->requests == orp){
				/* first in list */
				isp->requests = orp->next_request;
				if (isp->requestsEnd == orp)
				    isp->requestsEnd = NULL;
			    } else {
				for(rp = isp->requests; rp;
				    rp = rp->next_request){
				    if (rp->next_request == orp){
					if (isp->requestsEnd == orp)
					    isp->requestsEnd = rp;
					/* check logic ^^^: is this the
					   new "end"? XXX */
					/* link around it */
					rp->next_request = orp->next_request;
					break;
				    }
				}
			    }
			    snmp_free_pdu(orp->pdu);
			    free((char *)orp);
			    /* there shouldn't be any more requests with the
			       same reqid */
			    break;
			}
		    }
		}
	    } else if (pdu->command == GET_REQ_MSG
		       || pdu->command == GETNEXT_REQ_MSG
		       || pdu->command == TRP_REQ_MSG
		       || pdu->command == SET_REQ_MSG
		       || pdu->command == BULK_REQ_MSG
		       || pdu->command == INFORM_REQ_MSG
		       || pdu->command == TRP2_REQ_MSG){
		sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu,
			     sp->callback_magic);
	    }
	    snmp_free_internal_pdu(pdu);
	}
    }
}

/*
 * Returns info about what snmp requires from a select statement.
 * numfds is the number of fds in the list that are significant.
 * All file descriptors opened for SNMP are OR'd into the fdset.
 * If activity occurs on any of these file descriptors, snmp_read
 * should be called with that file descriptor set
 *
 * The timeout is the latest time that SNMP can wait for a timeout.  The
 * select should be done with the minimum time between timeout and any other
 * timeouts necessary.  This should be checked upon each invocation of select.
 * If a timeout is received, snmp_timeout should be called to check if the
 * timeout was for SNMP.  (snmp_timeout is idempotent)
 *
 * Block is 1 if the select is requested to block indefinitely, rather than
 * time out.
 * If block is input as 1, the timeout value will be treated as undefined,
 * but it must be available for setting in snmp_select_info.  On return, if
 * block is true, the value of timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The number of
 * sessions open)
 */
int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* should the select block until input arrives
		       (i.e. no input) */
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    struct request_list *rp;
    struct timeval now, earliest;
    int active = 0, requests = 0;

    timerclear(&earliest);
    /*
     * For each request outstanding, add it's socket to the fdset,
     * and if it is the earliest timeout to expire, mark it as lowest.
     */
    for(slp = Sessions; slp; slp = slp->next){
	active++;
	isp = slp->internal;
	if ((isp->sd + 1) > *numfds)
	    *numfds = (isp->sd + 1);
	FD_SET(isp->sd, fdset);
	if (isp->requests){
	    /* found another session with outstanding requests */
	    requests++;
	    for(rp = isp->requests; rp; rp = rp->next_request){
		if (!timerisset(&earliest)
		    || timercmp(&rp->expire, &earliest, <))
		    earliest = rp->expire;
	    }
	}
    }
    if (requests == 0)	/* if none are active, skip arithmetic */
	return active;

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now, (struct timezone *)0);
    Now = now;
    earliest.tv_sec--;	/* adjust time to make arithmetic easier */
    earliest.tv_usec += 1000000L;
    earliest.tv_sec -= now.tv_sec;
    earliest.tv_usec -= now.tv_usec;
    while (earliest.tv_usec >= 1000000L){
	earliest.tv_usec -= 1000000L;
	earliest.tv_sec += 1;
    }
    if (earliest.tv_sec < 0){
	earliest.tv_sec = 0;
	earliest.tv_usec = 0;
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block == 1 || timercmp(&earliest, timeout, <)){
	*timeout = earliest;
	*block = 0;
    }
    return active;
}

/*
 * snmp_timeout should be called whenever the timeout from snmp_select_info
 * expires, but it is idempotent, so snmp_timeout can be polled (probably a
 * cpu expensive proposition).  snmp_timeout checks to see if any of the
 * sessions have an outstanding request that has timed out.  If it finds one
 * (or more), and that pdu has more retries available, a new packet is formed
 * from the pdu and is resent.  If there are no more retries available, the
 *  callback for the session is used to alert the user of the timeout.
 */
void
snmp_timeout(){
    struct session_list *slp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    struct request_list *rp, *orp, *freeme = NULL;
    struct timeval now;

    gettimeofday(&now, (struct timezone *)0);
    /*
     * For each request outstanding, check to see if it has expired.
     */
    for(slp = Sessions; slp; slp = slp->next){
	sp = slp->session;
	isp = slp->internal;
	orp = NULL;
	for(rp = isp->requests; rp; rp = rp->next_request){
	    if (freeme != NULL){
		/* frees rp's after the for loop goes on to the next_request */
		free((char *)freeme);
		freeme = NULL;
	    }
	    if (timercmp(&rp->expire, &now, <)){
		/* this timer has expired */
		if (rp->retries >= sp->retries){
		    /* No more chances, delete this entry */
		    sp->callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu,
				 sp->callback_magic);
		    if (orp == NULL){
			isp->requests = rp->next_request;
			if (isp->requestsEnd == rp)
			    isp->requestsEnd = NULL;
		    } else {
			orp->next_request = rp->next_request;
			if (isp->requestsEnd == rp)
			    isp->requestsEnd = rp->next_request;
			/* check logic ^^^: is this the new "end"? XXX */
		    }
		    snmp_free_pdu(rp->pdu);
		    freeme = rp;
		    continue;	/* don't update orp below */
		} else {
		    u_char  packet[PACKET_LENGTH];
		    int length = PACKET_LENGTH;
		    struct timeval tv;

		    /* retransmit this pdu */
		    rp->retries++;
		    if (rp->retries > 3)
			rp->timeout <<= 1;
		    if (rp->timeout > 30000000L)
			rp->timeout = 30000000L;
		    if (snmp_build(sp, rp->pdu, packet, &length) < 0){
			fprintf(stderr, "Error building packet\n");
		    }
		    if (snmp_dump_packet){
			printf("sending %d bytes to %s:\n", length,
			       inet_ntoa(rp->pdu->address.sin_addr));
			xdump(packet, length, "");
			printf("\n\n");
		    }
		    if (sendto(isp->sd, (char *)packet, length, 0,
			       (struct sockaddr *)&rp->pdu->address,
			       sizeof(rp->pdu->address)) < 0){
			perror("sendto");
		    }
		    tv = now;
		    rp->time = tv;
		    tv.tv_usec += rp->timeout;
		    tv.tv_sec += tv.tv_usec / 1000000L;
		    tv.tv_usec %= 1000000L;
		    rp->expire = tv;
		}
	    }
	    orp = rp;
	}
	if (freeme != NULL){
	    free((char *)freeme);
	    freeme = NULL;
	}
    }
}
