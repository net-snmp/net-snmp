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
#include <config.h>

#include <stdio.h>
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
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
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
#else
#include <sys/socket.h>
#include <netdb.h>
#endif
#include <errno.h>
#ifdef STDC_HEADERS
#include <stdarg.h>
#else
#include <varargs.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "party.h"
#include "context.h"
#include "system.h"

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
#define FD_ZERO(p)	memset((p), 0, sizeof(*(p)))
#endif

static oid default_enterprise[] = {1, 3, 6, 1, 4, 1, 3, 1, 1};
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
    snmp_ipaddr  addr;	/* address of connected peer */
    struct request_list *requests;/* Info about outstanding requests */
    struct request_list *requestsEnd; /* ptr to end of list */
};

/*
 * A list of all the outstanding requests for a particular session.
 */
struct request_list {
    struct request_list *next_request;
    long  request_id;	/* request id */
    snmp_callback callback; /* user callback per request (NULL if unused) */
    void   *cb_data;   /* user callback data per request (NULL if unused) */
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
#ifdef OPAQUE_SPECIAL_TYPES
	float   *floatVal;
	double  *doubleVal;
#endif /* OPAQUE_SPECIAL_TYPES */
    } val;
    int     val_len;
    oid name_loc[MAX_NAME_LEN];
    u_char buf[32];
    int usedBuf;
};

struct internal_snmp_pdu {
    int     version;

    snmp_ipaddr  address;    /* Address of peer */
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
    snmp_ipaddr  agent_addr; /* address of object generating trap */
    long     trap_type;  /* trap type */
    long     specific_type;  /* specific type */
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

static char *api_errors[-SNMPERR_MAX+1] = {
    "No error",
    "Generic error",
    "Invalid local port",
    "Unknown host",
    "Unknown session",
    "Too long",
    "No socket",
    "Cannot send V2 PDU on V1 session",
    "Cannot send V1 PDU on V2 session",
    "Bad value for non-repeaters",
    "Bad value for max-repetitions",
    "Error building ASN.1 representation",
    "Failure in sendto",
    "Bad parse of ASN.1 type",
    "Bad version specified",
    "Bad source party specified",
    "Bad destination party specified",
    "Bad context specified",
    "Bad community specified",
    "Cannot send noAuth/desPriv",
    "Bad ACL definition",
    "Bad Party definition",
    "Session abort failure",
    "Unknown PDU type",
    "Timeout",
    "Failure in recvfrom",
};

/*
 * Multiple threads may changes these variables.
 * Suggest using the Single API, which does not use Sessions.
 *
 * Reqid may need to be protected. Time will tell...
 *
 */
/*MTCRITICAL_RESOURCE*/
struct session_list *Sessions = NULL;
long Reqid = 0;
/*END MTCRITICAL_RESOURCE*/

/*struct timeval Now;*/
static struct servent *servp = NULL;
int snmp_errno = 0;
char *snmp_detail = NULL;

static int snmp_dump_packet = 0;

static void free_request_list __P((struct request_list *));
void shift_array __P((u_char *, int, int));
static int snmp_build __P((struct snmp_session *, struct snmp_pdu *, u_char *, int *));
static int snmp_parse __P((struct snmp_session *, struct internal_snmp_pdu *, u_char *, int));
static void snmp_free_internal_pdu __P((struct snmp_pdu *));

static void * snmp_sess_pointer __P((struct snmp_session *));

#ifndef HAVE_STRERROR
char *strerror(err)
int err;
{
  extern char *sys_errlist[];
  extern int sys_nerr;

  if (err < 0 || err >= sys_nerr) return "Unknown error";
  return sys_errlist[err];
}
#endif

void snmp_set_dump_packet(val)
    int val;
{
    snmp_dump_packet = val;
}

int snmp_get_dump_packet __P((void))
{
    return snmp_dump_packet;
}

int snmp_get_errno __P((void))
{
    return snmp_errno;
}

void
snmp_perror(prog_string)
  char *prog_string;
{
  fprintf(stderr,"%s: %s\n",prog_string, snmp_api_errstring(snmp_errno));
}

void
snmp_set_detail(detail_string)
  char *detail_string;
{
  if (snmp_detail != NULL) {
    free(snmp_detail);
    snmp_detail = NULL;
  }
  if (detail_string != NULL)
    snmp_detail = (char *)strdup(detail_string);
}

char *
snmp_api_errstring(snmp_errnumber)
    int	snmp_errnumber;
{
    char *msg;
    static char msg_buf [256];
    if (snmp_errnumber >= SNMPERR_MAX && snmp_errnumber <= SNMPERR_GENERR){
	msg = api_errors[-snmp_errnumber];
    } else {
	msg = "Unknown Error";
    }
    if (snmp_detail) {
	sprintf (msg_buf, "%s (%s)", msg, snmp_detail);
        free(snmp_detail);
        snmp_detail = NULL;  /* only return the detail once */
	return msg_buf;
    }
    else return msg;
}

/*
 * snmp_error - return error data
 * Inputs :  address of errno, address of snmp_errno, address of string
 * Caller must free the string returned after use.
 */
void
snmp_error(psess, p_errno, p_snmp_errno, p_str)
    struct snmp_session *psess;
    int * p_errno;
    int * p_snmp_errno;
    char ** p_str;
{
    char buf[512];
    int snmp_errnumber;

    if (p_errno) *p_errno = psess->s_errno;
    if (p_snmp_errno) *p_snmp_errno = psess->s_snmp_errno;
    if (p_str == NULL) return;

    snmp_errnumber = psess->s_snmp_errno;
    if (snmp_errnumber >= SNMPERR_MAX && snmp_errnumber <= SNMPERR_GENERR){
	strcpy(buf, api_errors[-snmp_errnumber]);
    } else {
	sprintf(buf, "Unknown Error %d", snmp_errnumber);
    }

    /* append a useful system errno interpretation. */
    if (psess->s_errno)
        sprintf (&buf[strlen(buf)], " (%s)", strerror(psess->s_errno));
    *p_str = (char *)strdup(buf);
}

/*
 * snmp_sess_error - same as snmp_error for single session API use.
 */
void
snmp_sess_error(sessp, p_errno, p_snmp_errno, p_str)
    void * sessp;
    int * p_errno;
    int * p_snmp_errno;
    char ** p_str;
{
    struct session_list *slp = (struct session_list*)sessp;

    if ((slp) && (slp->session))
	snmp_error(slp->session, p_errno, p_snmp_errno, p_str);
}


/*
 * Gets initial request ID for all transactions.
 * and finds which port SNMP over UDP uses.
 */
static void
init_snmp __P((void))
{
    struct timeval tv;

    if (Reqid) return;
    Reqid = 1;

    if (! servp)
      servp = getservbyname("snmp", "udp");

    gettimeofday(&tv,(struct timezone *)0);
    /*Now = tv;*/

#ifdef SVR4
    srand48(tv.tv_sec ^ tv.tv_usec);
    Reqid = lrand48();
#else
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
#endif
}

void
snmp_sess_init(session)
    struct snmp_session * session;
{
extern int init_mib_internals();

    init_snmp();
    init_mib_internals();

    /* initialize session to default values */
 
    memset(session, 0, sizeof(struct snmp_session));
    session->remote_port = SNMP_DEFAULT_REMPORT;
    session->timeout = SNMP_DEFAULT_TIMEOUT;
    session->retries = SNMP_DEFAULT_RETRIES;
    session->version = SNMP_VERSION_1;
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
    slp = (struct session_list *)snmp_sess_open(session);
    if (slp)
    { /*MTCRITICAL_RESOURCE*/
	slp->next = Sessions;
	Sessions = slp;
    }
    return (slp->session);
}

/* The "spin-free" version of snmp_open */
void *
snmp_sess_open(in_session)
    struct snmp_session *in_session;
{
    struct session_list *slp;
    struct snmp_internal_session *isp;
    struct snmp_session *session;
    u_char *cp;
    oid *op;
    int sd;
    in_addr_t addr;
    struct sockaddr_in	me;
    struct hostent *hp;

    if (Reqid == 0)
      init_snmp();

    /* Copy session structure and link into list */
    slp = (struct session_list *)malloc(sizeof(struct session_list));
    if (slp == NULL) { 
      snmp_errno = SNMPERR_GENERR;
      in_session->s_snmp_errno = SNMPERR_GENERR;
      return(NULL);
    }
    memset(slp, 0, sizeof(struct session_list));

    isp = (struct snmp_internal_session *)malloc(sizeof(struct snmp_internal_session));
    if (isp == NULL) { 
      snmp_errno = SNMPERR_GENERR;
      in_session->s_snmp_errno = SNMPERR_GENERR;
      snmp_sess_close(slp);
      return(NULL);
    }
    memset(isp, 0, sizeof(struct snmp_internal_session));

    slp->internal = isp;
    slp->internal->sd = -1; /* mark it not set */
    slp->session = (struct snmp_session *)malloc(sizeof(struct snmp_session));
    if (slp->session == NULL) { 
      snmp_errno = SNMPERR_GENERR;
      in_session->s_snmp_errno = SNMPERR_GENERR;
      snmp_sess_close(slp);
      return(NULL);
    }
    memmove(slp->session, in_session, sizeof(struct snmp_session));
    session = slp->session;

    /*
     * session now points to the new structure that still contains pointers to
     * data allocated elsewhere.  Some of this data is copied to space malloc'd
     * here, and the pointer replaced with the new one.
     */

    if (session->peername != NULL){
	cp = (u_char *)malloc((unsigned)strlen(session->peername) + 1);
	if (cp == NULL) {
          snmp_errno = SNMPERR_GENERR;
          in_session->s_snmp_errno = SNMPERR_GENERR;
          snmp_sess_close(slp);
          return(NULL);
        }
	strcpy((char *)cp, session->peername);
	session->peername = (char *)cp;
    }

    /* Fill in defaults if necessary */
    if (session->community_len != SNMP_DEFAULT_COMMUNITY_LEN){
	cp = (u_char *)malloc((unsigned)session->community_len);
	if (cp)
	memmove(cp, session->community, session->community_len);
    } else {
	session->community_len = strlen(DEFAULT_COMMUNITY);
	cp = (u_char *)malloc((unsigned)session->community_len);
	if (cp)
	memmove(cp, DEFAULT_COMMUNITY, session->community_len);
    }
    if (cp == NULL) {
      snmp_errno = SNMPERR_GENERR;
      in_session->s_snmp_errno = SNMPERR_GENERR;
      snmp_sess_close(slp);
      return(NULL);
    }

    session->community = cp;	/* replace pointer with pointer to new data */

    if (session->srcPartyLen > 0){
	op = (oid *)malloc((unsigned)session->srcPartyLen * sizeof(oid));
	if (op == NULL) {
	    snmp_errno = SNMPERR_GENERR;
	    in_session->s_snmp_errno = SNMPERR_GENERR;
	    snmp_sess_close(slp);
	    return(NULL);
	}
	memmove(op, session->srcParty, session->srcPartyLen * sizeof(oid));
	session->srcParty = op;
    } else {
	session->srcParty = 0;
    }

    if (session->dstPartyLen > 0){
	op = (oid *)malloc((unsigned)session->dstPartyLen * sizeof(oid));
	if (op == NULL) {
	    snmp_errno = SNMPERR_GENERR;
	    in_session->s_snmp_errno = SNMPERR_GENERR;
	    snmp_sess_close(slp);
	    return(NULL);
	}
	memmove(op, session->dstParty, session->dstPartyLen * sizeof(oid));
	session->dstParty = op;
    } else {
	session->dstParty = 0;
    }

    if (session->contextLen > 0){
	op = (oid *)malloc((unsigned)session->contextLen * sizeof(oid));
	if (op == NULL) {
	    snmp_errno = SNMPERR_GENERR;
	    in_session->s_snmp_errno = SNMPERR_GENERR;
	    snmp_sess_close(slp);
	    return(NULL);
	}
	memmove(op, session->context, session->contextLen * sizeof(oid));
	session->context = op;
    } else {
	session->context = 0;
    }

    if (session->retries == SNMP_DEFAULT_RETRIES)
	session->retries = DEFAULT_RETRIES;
    if (session->timeout == SNMP_DEFAULT_TIMEOUT)
	session->timeout = DEFAULT_TIMEOUT;

    /* Set up connections */
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sd < 0){
	snmp_errno = SNMPERR_NO_SOCKET;
	in_session->s_snmp_errno = SNMPERR_NO_SOCKET;
	in_session->s_errno = errno;
	snmp_set_detail(strerror(errno));
	snmp_sess_close(slp);
	return 0;
    }

#ifdef SO_BSDCOMPAT
    /* Patch for Linux.  Without this, UDP packets that fail get an ICMP
     * response.  Linux turns the failed ICMP response into an error message
     * and return value, unlike all other OS's.
     */
    {
	int one=1;
	setsockopt(sd, SOL_SOCKET, SO_BSDCOMPAT, &one, sizeof(one));
    }
#endif /* SO_BSDCOMPAT */

    isp->sd = sd;
    if (session->peername != SNMP_DEFAULT_PEERNAME){
	if ((int)(addr = inet_addr(session->peername)) != -1){
	    memmove(&isp->addr.sin_addr, &addr, sizeof(isp->addr.sin_addr));
	} else {
	    hp = gethostbyname(session->peername);
	    if (hp == NULL){
		snmp_errno = SNMPERR_BAD_ADDRESS;
		in_session->s_snmp_errno = SNMPERR_BAD_ADDRESS;
		in_session->s_errno = errno;
		snmp_set_detail(session->peername);
		snmp_sess_close(slp);
		return 0;
	    } else {
		memmove(&isp->addr.sin_addr, hp->h_addr, hp->h_length);
	    }
	}
	isp->addr.sin_family = AF_INET;
	if (session->remote_port == SNMP_DEFAULT_REMPORT){
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

    memset(&me, '\0', sizeof(me));
    me.sin_family = AF_INET;
    me.sin_addr.s_addr = INADDR_ANY;
    me.sin_port = htons(session->local_port);
    if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	snmp_errno = SNMPERR_BAD_LOCPORT;
	in_session->s_snmp_errno = SNMPERR_BAD_LOCPORT;
	in_session->s_errno = errno;
	snmp_set_detail(strerror(errno));
	snmp_sess_close(slp);
	return 0;
    }
    return (void *)slp;
}


/*
 * Free each element in the input request list.
 */
static void
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

static void
_snmp_free(cp)
    char * cp;
{
    if (cp)
	free(cp);
}

/*
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int
snmp_sess_close(sessp)
    void *sessp;
{
    struct session_list *slp = (struct session_list *)sessp;

    if (slp == NULL)
	return 0;

    if (slp->internal) {
	if (slp->internal->sd != -1)
	{
#ifndef HAVE_CLOSESOCKET
	close(slp->internal->sd);
#else
	closesocket(slp->internal->sd);
#endif
	}
	free_request_list(slp->internal->requests);
    }

    _snmp_free((char *)slp->session->context);
    _snmp_free((char *)slp->session->dstParty);
    _snmp_free((char *)slp->session->srcParty);
    _snmp_free((char *)slp->session->peername);
    _snmp_free((char *)slp->session->community);
    _snmp_free((char *)slp->session);
    _snmp_free((char *)slp->internal);
    _snmp_free((char *)slp);

    return 1;
}

int 
snmp_close(session)
    struct snmp_session *session;
{
    struct session_list *slp = NULL, *oslp = NULL;

    { /*MTCRITICAL_RESOURCE*/
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
    } /*END MTCRITICAL_RESOURCE*/

    if (slp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return 0;
    }
    return snmp_sess_close((void *)slp);
}

#ifdef notused
void
shift_array(begin, length, shift_amount)
    u_char          *begin;
    register int    length;
    int             shift_amount;
{
    register u_char     *old, *newer;

    if (shift_amount >= 0){
        old = begin + length - 1;
        newer = old + shift_amount;

        while(length--)
            *newer-- = *old--;
    } else {
        old = begin;
        newer = begin + shift_amount;

        while(length--)
            *newer++ = *old++;
    }
}
#endif

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
    u_char *h0, *h0e=NULL, *h1, *h1e, *h2, *h2e;
    register u_char  *cp;
    struct variable_list *vp;
    struct  packet_info pkt, *pi = &pkt;
    int length;
#ifdef USE_V2PARTY_PROTOCOL
    int packet_length;
#endif /* USE_V2PARTY_PROTOCOL */
    long version;

    snmp_errno = SNMPERR_BAD_ASN1_BUILD;
    session->s_snmp_errno = SNMPERR_BAD_ASN1_BUILD;

    /* save length */
    length = *out_length;

    /* build the message wrapper and all the administrative fields
       upto the PDU sequence
       (note that actual length of message will be inserted later) */
    h0 = packet;
    switch (pdu->version) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
        /* Save current location and build SEQUENCE tag and length
           placeholder for SNMP message sequence
          (actual length will be inserted later) */        
        cp = asn_build_sequence(packet, out_length,
                                (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                                0);
        if (cp == NULL)
            return -1;
        h0e = cp;

        /* store the version field */
        version = pdu->version;
        cp = asn_build_int(cp, out_length,
                    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                    (long *) &version, sizeof(version));
        if (cp == NULL)
            return -1;                

        /* store the community string */
        cp = asn_build_string(cp, out_length,
                    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
                    pdu->community, pdu->community_len);
        if (cp == NULL)
            return -1;
        break;

    case SNMP_VERSION_2p:
#ifdef USE_V2PARTY_PROTOCOL
        pi->version = session->version;
        pi->srcp = NULL;
        pi->dstp = NULL;
        cp = snmp_party_build(packet, out_length, pi, 0,
                              pdu->srcParty, pdu->srcPartyLen,
                              pdu->dstParty, pdu->dstPartyLen,
                              pdu->context, pdu->contextLen,
                              0, FIRST_PASS);
        if (cp == NULL)
            return -1;
        break;
#endif /* USE_V2PARTY_PROTOCOL */

    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    case SNMP_VERSION_3:
    default:
	return -1;
    }

    /* Save current location and build PDU tag and length placeholder
       (actual length will be inserted later) */        
    h1 = cp;
    cp = asn_build_sequence(cp, out_length, (u_char)pdu->command, 0);
    if (cp == NULL)
        return -1;
    h1e = cp;
    
    /* store fields in the PDU preceeding the variable-bindings sequence */    
    if (pdu->command != SNMP_MSG_TRAP){
        /* PDU is not an SNMPv1 trap */

        /* request id */
        cp = asn_build_int(cp, out_length,
            (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &pdu->reqid, sizeof(pdu->reqid));
        if (cp == NULL)
            return -1;

        /* error status (getbulk non-repeaters) */
        cp = asn_build_int(cp, out_length,
                (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                &pdu->errstat, sizeof(pdu->errstat));
        if (cp == NULL)
            return -1;

        /* error index (getbulk max-repetitions) */
        cp = asn_build_int(cp, out_length,
                (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
                &pdu->errindex, sizeof(pdu->errindex));
        if (cp == NULL)
            return -1;
    } else {
        /* an SNMPv1 trap PDU */

        /* enterprise */
        cp = asn_build_objid(cp, out_length,
            (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
            (oid *)pdu->enterprise, pdu->enterprise_length);
        if (cp == NULL)
            return -1;

        /* agent-addr */
        cp = asn_build_string(cp, out_length,
                (u_char)(ASN_IPADDRESS | ASN_PRIMITIVE),
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
                (u_char)(ASN_TIMETICKS | ASN_PRIMITIVE),
                &pdu->time, sizeof(pdu->time));
        if (cp == NULL)
            return -1;
    }

    /* Save current location and build SEQUENCE tag and length placeholder
       for variable-bindings sequence
       (actual length will be inserted later) */
    h2 = cp;
    cp = asn_build_sequence(cp, out_length,
                          (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                          0);
    if (cp == NULL)
        return -1;
    h2e = cp;

    /* Store variable-bindings */
    for(vp = pdu->variables; vp; vp = vp->next_variable){
        cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type,
                               vp->val_len, (u_char *)vp->val.string,
			       out_length);
        if (cp == NULL)
            return -1;
    }

    /* insert actual length of variable-bindings sequence */
    asn_build_sequence(h2, &length,
		       (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                       cp - h2e);

    /* insert actual length of PDU sequence */
    asn_build_sequence(h1, &length,
		       (u_char)pdu->command,
                       cp - h1e);

    /* insert the actual length of the message sequence */        
    switch (pdu->version) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
        asn_build_sequence(packet, &length,
		       (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                       cp - h0e);
        break;

    case SNMP_VERSION_2p:
#ifdef USE_V2PARTY_PROTOCOL
        /* add potentially encryption and digest calculation */
/*?? cleanup length parameters in call */
        snmp_party_build(packet, &length, pi, cp - h1,
                         pdu->srcParty, pdu->srcPartyLen,
                         pdu->dstParty, pdu->dstPartyLen,
                         pdu->context, pdu->contextLen,
                         &packet_length, LAST_PASS);
	/* encryption might bump length of packet */
	cp = packet + packet_length;
	break;
#endif /* USE_V2PARTY_PROTOCOL */

    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    case SNMP_VERSION_3:
    default:
	return -1;
    }
    *out_length = cp - packet;
    snmp_errno = 0;
    session->s_snmp_errno = 0;
    return 0;
}

/*
 * Parses the packet received on the input session, and places the data into
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
    int     version, badtype;
    int	    len, four;
    u_char community[COMMUNITY_MAX_LEN];
    int community_length = COMMUNITY_MAX_LEN;
    struct internal_variable_list *vp = NULL;
    oid objid[MAX_NAME_LEN];
    char err[256];

    badtype = 0;
    snmp_errno = SNMPERR_BAD_PARSE;
    session->s_snmp_errno = SNMPERR_BAD_PARSE;

    /* get the message tag */
    len = length;
    (void)asn_parse_header(data, &len, &type);

    /* parse the message wrapper and all the administrative fields
       upto the PDU sequence */
    if (session->version != SNMP_DEFAULT_VERSION)
	version = session->version;
    else if (type == (ASN_SEQUENCE | ASN_CONSTRUCTOR))
	version = SNMP_VERSION_1;
#ifdef USE_V2PARTY_PROTOCOL
    else
	version = SNMP_VERSION_2p;
#endif /* USE_V2PARTY_PROTOCOL */
    switch (version) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
        /* message tag is a sequence */
        if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR))
            return -1;

	/* authenticates message and returns length if valid */
	data = snmp_comstr_parse(data, &length,
                                 community, &community_length,
			         &version);
	if (data == NULL)
	    return -1;
        if (version != session->version && session->version != SNMP_DEFAULT_VERSION)
            return -1;
	pdu->community_len = community_length;
	pdu->community = (u_char *)malloc(community_length);
	memmove(pdu->community, community, community_length);
	if (session->authenticator){
	    data = session->authenticator(data, &length,
					  (char *)community,
                                          community_length);
	    if (data == NULL)
		return 0; /* COMMENT OR CHANGE YYXX not an error ? */
	}
        break;

    case SNMP_VERSION_2p:
#ifdef USE_V2PARTY_PROTOCOL
        /* message tag is a tagged context specific sequence
           that is,  "[1] IMPLICIT SEQUENCE" */
        if (type != (ASN_CONTEXT | ASN_CONSTRUCTOR | 1))
	    return -1;

        /* authenticate the message and possibly decrypt it */
	pdu->srcParty = pdu->srcPartyBuf;
	pdu->dstParty = pdu->dstPartyBuf;
	pdu->context  = pdu->contextBuf;
        pdu->srcPartyLen = MAX_NAME_LEN;
        pdu->dstPartyLen = MAX_NAME_LEN;
        pdu->contextLen  = MAX_NAME_LEN;

	/* authenticates message and returns length if valid */
	data = snmp_party_parse(data, &length, pi,
			        pdu->srcParty, &pdu->srcPartyLen,
			        pdu->dstParty, &pdu->dstPartyLen,
				pdu->context, &pdu->contextLen,
				FIRST_PASS | LAST_PASS);
	if (data == NULL)
	    return -1;
	version = pi->version;
        break;
#endif /* USE_V2PARTY_PROTOCOL */

    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    case SNMP_VERSION_3:
    default:
        ERROR_MSG("unsupported/unknown message header type");
	return -1;
    }
    pdu->version = version;

    /* Get the PDU type */
    data = asn_parse_header(data, &length, &msg_type);
    if (data == NULL)
	return -1;
    pdu->command = msg_type;

    /* get the fields in the PDU preceeding the variable-bindings sequence */
    if (pdu->command != SNMP_MSG_TRAP){
        /* PDU is not an SNMPv1 TRAP */

        /* request id */
	data = asn_parse_int(data, &length, &type, &pdu->reqid,
			     sizeof(pdu->reqid));
	if (data == NULL) {
	    ERROR_MSG(strcat(strcpy(err, "parsing request-id: "), snmp_detail));
	    return -1;
	}

        /* error status (getbulk non-repeaters) */
	data = asn_parse_int(data, &length, &type, &pdu->errstat,
			     sizeof(pdu->errstat));
	if (data == NULL) {
	    ERROR_MSG(strcat(strcpy(err, "parsing error status: "), snmp_detail));
	    return -1;
	}

        /* error index (getbulk max-repetitions) */
	data = asn_parse_int(data, &length, &type, &pdu->errindex,
			     sizeof(pdu->errindex));
	if (data == NULL) {
	    ERROR_MSG(strcat(strcpy(err, "parsing error index: "), snmp_detail));
	    return -1;
	}
    } else {
        /* an SNMPv1 trap PDU */

        /* enterprise */
	pdu->enterprise_length = MAX_NAME_LEN;
	data = asn_parse_objid(data, &length, &type, objid,
			       &pdu->enterprise_length);
	if (data == NULL)
	    return -1;
	pdu->enterprise = (oid *)malloc(pdu->enterprise_length * sizeof(oid));
	memmove(pdu->enterprise, objid, pdu->enterprise_length * sizeof(oid));

        /* agent-addr */
	four = 4;
	data = asn_parse_string(data, &length, &type,
				(u_char *)&pdu->agent_addr.sin_addr.s_addr,
				&four);
	if (data == NULL)
	    return -1;

        /* generic trap */
	data = asn_parse_int(data, &length, &type, (long *)&pdu->trap_type,
			     sizeof(pdu->trap_type));
	if (data == NULL)
	    return -1;

        /* specific trap */
	data = asn_parse_int(data, &length, &type, (long *)&pdu->specific_type,
			     sizeof(pdu->specific_type));
	if (data == NULL)
	    return -1;

        /* timestamp  */
	data = asn_parse_unsigned_int(data, &length, &type, &pdu->time,
				      sizeof(pdu->time));
	if (data == NULL)
	    return -1;
    }

    /* get header for variable-bindings sequence */
    data = asn_parse_header(data, &length, &type);
    if (data == NULL)
	return -1;
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
	return -1;

    /* get each varBind sequence */
    while((int)length > 0){
	if (vp == NULL){
	    vp = (struct internal_variable_list *)malloc(sizeof(struct internal_variable_list));
	    pdu->variables = (struct variable_list *)vp;
	} else {
	    vp->next_variable = (struct variable_list *)malloc(sizeof(struct internal_variable_list));
	    vp = (struct internal_variable_list *)vp->next_variable;
	}

	vp->next_variable = NULL;
	vp->val.string = NULL;
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
	    case ASN_COUNTER:
	    case ASN_GAUGE:
	    case ASN_TIMETICKS:
	    case ASN_UINTEGER:
		vp->val.integer = (long *)vp->buf;
		vp->usedBuf = TRUE;
		vp->val_len = sizeof(u_long);
		asn_parse_unsigned_int(var_val, &len, &vp->type,
				       (u_long *)vp->val.integer,
				       sizeof(vp->val.integer));
		break;
#ifdef OPAQUE_SPECIAL_TYPES
            case ASN_OPAQUE_COUNTER64:
            case ASN_OPAQUE_U64:
#endif /* OPAQUE_SPECIAL_TYPES */
	    case ASN_COUNTER64:
		vp->val.counter64 = (struct counter64 *)vp->buf;
		vp->usedBuf = TRUE;
		vp->val_len = sizeof(struct counter64);
		asn_parse_unsigned_int64(var_val, &len, &vp->type,
					 (struct counter64 *)vp->val.counter64,
					 sizeof(*vp->val.counter64));
		break;
#ifdef OPAQUE_SPECIAL_TYPES
	    case ASN_OPAQUE_FLOAT:
		vp->val.floatVal = (float *)vp->buf;
		vp->usedBuf = TRUE;
		vp->val_len = sizeof(float);
		asn_parse_float(var_val, &len, &vp->type,
		                         vp->val.floatVal,
					 vp->val_len);
		break;
	    case ASN_OPAQUE_DOUBLE:
		vp->val.doubleVal = (double *)vp->buf;
		vp->usedBuf = TRUE;
		vp->val_len = sizeof(double);
		asn_parse_double(var_val, &len, &vp->type,
		                         vp->val.doubleVal,
					 vp->val_len);
		break;
	    case ASN_OPAQUE_I64:
		vp->val.counter64 = (struct counter64 *)vp->buf;
		vp->usedBuf = TRUE;
		vp->val_len = sizeof(struct counter64);
		asn_parse_signed_int64(var_val, &len, &vp->type,
			             (struct counter64 *)vp->val.counter64,
				      sizeof(*vp->val.counter64));

		break;
#endif /* OPAQUE_SPECIAL_TYPES */
	    case ASN_OCTET_STR:
	    case ASN_IPADDRESS:
	    case ASN_OPAQUE:
	    case ASN_NSAP:
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
		memmove(vp->val.objid, objid, vp->val_len);
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
		fprintf(stderr,"bad type returned (%x)\n", vp->type);
		badtype = 1;
		break;
	}
    }
    if (badtype == 0) {
	snmp_errno = 0;
	session->s_snmp_errno = 0;
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
  return snmp_async_send(session, pdu, NULL, NULL);
}

int
snmp_sess_send(sessp, pdu)
    void	        *sessp;
    struct snmp_pdu	*pdu;
{
  return snmp_sess_async_send(sessp, pdu, NULL, NULL);
}

/*
 * int snmp_async_send(session, pdu, callback, cb_data)
 *     struct snmp_session *session;
 *     struct snmp_pdu	*pdu;
 *     snmp_callback callback;
 *     void   *cb_data;
 * 
 * Sends the input pdu on the session after calling snmp_build to create
 * a serialized packet.  If necessary, set some of the pdu data from the
 * session defaults.  Add a request corresponding to this pdu to the list
 * of outstanding requests on this session and store callback and data, 
 * then send the pdu.
 * Returns the request id of the generated packet if applicable, otherwise 1.
 * On any error, 0 is returned.
 * The pdu is freed by snmp_send() unless a failure occured.
 */
int
snmp_async_send(session, pdu, callback, cb_data)
    struct snmp_session *session;
    struct snmp_pdu	*pdu;
    snmp_callback	callback;
    void	        *cb_data;
{
    void *sessp = snmp_sess_pointer(session);

    if (sessp == NULL) return 0;

    return snmp_sess_async_send(sessp, pdu, callback, cb_data);
}

int
snmp_sess_async_send(sessp, pdu, callback, cb_data)
    void	        *sessp;
    struct snmp_pdu	*pdu;
    snmp_callback	callback;
    void	        *cb_data;
{
    struct session_list *slp = (struct session_list *)sessp;
    struct snmp_session *session;
    struct snmp_internal_session *isp;
    u_char  packet[PACKET_LENGTH];
    int length = PACKET_LENGTH;
    struct request_list *rp;
    struct timeval tv;
    int expect_response = 1;

    session = slp->session; isp = slp->internal;
    session->s_snmp_errno = 0;
    session->s_errno = 0;

    /* check/setup the version */
    if (pdu->version == SNMP_DEFAULT_VERSION) {
        if (session->version == SNMP_DEFAULT_VERSION) {
	    snmp_errno = SNMPERR_BAD_VERSION;
	    session->s_snmp_errno = SNMPERR_BAD_VERSION;
	    return 0;
        }
        pdu->version = session->version;
    } else if (session->version == SNMP_DEFAULT_VERSION) {
	/* It's OK */
    } else if (pdu->version != session->version) {
        snmp_errno = SNMPERR_BAD_VERSION;
        session->s_snmp_errno = SNMPERR_BAD_VERSION;
        return 0;
    }

    /* do validations for PDU types */
    if ((pdu->command == SNMP_MSG_GET) ||
            (pdu->command == SNMP_MSG_RESPONSE) ||
            (pdu->command == SNMP_MSG_GETNEXT) ||
            (pdu->command == SNMP_MSG_SET)) {
        /* all versions support these PDU types */
        /* initialize defaulted PDU fields */
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	{ /*MTCRITICAL_RESOURCE*/
	    pdu->reqid = ++Reqid;
	}
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
        if (pdu->command == SNMP_MSG_RESPONSE)
            /* don't expect a response */
            expect_response = 0;
    } else if ((pdu->command == SNMP_MSG_INFORM) ||
               (pdu->command == SNMP_MSG_TRAP2)) {
        /* not supported in SNMPv1 and SNMPsec */
	if ((pdu->version == SNMP_VERSION_1) ||
                (pdu->version == SNMP_VERSION_sec)) {
	    snmp_errno = SNMPERR_V2_IN_V1;
	    session->s_snmp_errno = SNMPERR_V2_IN_V1;
	    return 0;
	}
        /* initialize defaulted PDU fields */
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	{ /*MTCRITICAL_RESOURCE*/
	    pdu->reqid = ++Reqid;
	}
	if (pdu->errstat == SNMP_DEFAULT_ERRSTAT)
	    pdu->errstat = 0;
	if (pdu->errindex == SNMP_DEFAULT_ERRINDEX)
	    pdu->errindex = 0;
        if (pdu->command == SNMP_MSG_TRAP2)
            expect_response = 0;
    } else if (pdu->command == SNMP_MSG_GETBULK) {
        /* not supported in SNMPv1 and SNMPsec */
	if ((pdu->version == SNMP_VERSION_1) ||
                (pdu->version == SNMP_VERSION_sec)) {
	    snmp_errno = SNMPERR_V1_IN_V2;
	    session->s_snmp_errno = SNMPERR_V1_IN_V2;
	    return 0;
	}
        /* initialize defaulted PDU fields */
	if (pdu->reqid == SNMP_DEFAULT_REQID)
	{ /*MTCRITICAL_RESOURCE*/
	    pdu->reqid = ++Reqid;
	}
	if ((pdu->max_repetitions < 0) || (pdu->non_repeaters < 0)){
	    snmp_errno = SNMPERR_BAD_REPETITIONS;
	    session->s_snmp_errno = SNMPERR_BAD_REPETITIONS;
	    return 0;
	}
	    
    } else if (pdu->command == SNMP_MSG_TRAP) {
        if ((pdu->version != SNMP_VERSION_1) &&
            (pdu->version != SNMP_VERSION_sec)) {
          snmp_errno = SNMPERR_V2_IN_V1;
          session->s_snmp_errno = SNMPERR_V2_IN_V1;
          return 0;
        }
        /* initialize defaulted Trap PDU fields */
	pdu->reqid = 1;	/* give a bogus non-error reqid for traps */
	if (pdu->enterprise_length == SNMP_DEFAULT_ENTERPRISE_LENGTH){
	    pdu->enterprise = (oid *)malloc(sizeof(DEFAULT_ENTERPRISE));
	    memmove(pdu->enterprise, DEFAULT_ENTERPRISE,
		    sizeof(DEFAULT_ENTERPRISE));
	    pdu->enterprise_length = sizeof(DEFAULT_ENTERPRISE)/sizeof(oid);
	}
	if (pdu->time == SNMP_DEFAULT_TIME)
	    pdu->time = DEFAULT_TIME;
        /* don't expect a response */
        expect_response = 0;
    } else {
        /* some unknown PDU type */
        snmp_errno = SNMPERR_UNKNOWN_PDU; 
        session->s_snmp_errno = SNMPERR_UNKNOWN_PDU;
        return 0;
    }

    if (pdu->address.sin_addr.s_addr == SNMP_DEFAULT_ADDRESS){
	if (isp->addr.sin_addr.s_addr != SNMP_DEFAULT_ADDRESS){
	    memmove(&pdu->address, &isp->addr, sizeof(pdu->address));
	} else {
	    snmp_errno = SNMPERR_BAD_ADDRESS;
	    session->s_snmp_errno = SNMPERR_BAD_ADDRESS;
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

    /* setup administrative fields based on version */
    switch (pdu->version) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
	if (pdu->community_len == 0){
	    if (session->community_len == 0){
		snmp_errno = SNMPERR_BAD_ADDRESS;
		session->s_snmp_errno = SNMPERR_BAD_ADDRESS;
		return 0;
	    }
	    pdu->community = (u_char *)malloc(session->community_len);
	    memmove(pdu->community, session->community,
                        session->community_len);
	    pdu->community_len = session->community_len;
	}
        break;

    case SNMP_VERSION_2p:
#ifdef USE_V2PARTY_PROTOCOL
	if (pdu->srcPartyLen == 0){
	    if (session->srcPartyLen == 0){
		snmp_errno = SNMPERR_BAD_SRC_PARTY;
		session->s_snmp_errno = SNMPERR_BAD_SRC_PARTY;
		return 0;
	    }
	    pdu->srcParty = (oid *)malloc(session->srcPartyLen * sizeof(oid));
	    memmove(pdu->srcParty, session->srcParty,
		    session->srcPartyLen * sizeof(oid));
	    pdu->srcPartyLen = session->srcPartyLen;
	}
	if (pdu->dstPartyLen == 0){
	    if (session->dstPartyLen == 0){
		snmp_errno = SNMPERR_BAD_DST_PARTY;
		session->s_snmp_errno = SNMPERR_BAD_DST_PARTY;
		return 0;
	    }
	    pdu->dstParty = (oid *)malloc(session->dstPartyLen * sizeof(oid));
	    memmove(pdu->dstParty, session->dstParty,
		    session->dstPartyLen * sizeof(oid));
	    pdu->dstPartyLen = session->dstPartyLen;
	}
	if (pdu->contextLen == 0){
	    if (session->contextLen == 0){
		snmp_errno = SNMPERR_BAD_CONTEXT;
		session->s_snmp_errno = SNMPERR_BAD_CONTEXT;
		return 0;
	    }
	    pdu->context = (oid *)malloc(session->contextLen * sizeof(oid));
	    memmove(pdu->context, session->context,
		    session->contextLen * sizeof(oid));
	    pdu->contextLen = session->contextLen;
	}
        break;
#endif /* USE_V2PARTY_PROTOCOL */

    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    case SNMP_VERSION_3:
    default:
        snmp_errno = SNMPERR_BAD_VERSION;
        session->s_snmp_errno = SNMPERR_BAD_VERSION;
	return -1;
    }

    /* build the message to send */
    if (snmp_build(session, pdu, packet, &length) < 0){
	return 0;
    }
    if (snmp_dump_packet){
	printf("\nsending %d bytes to %s:%hu:\n", length,
	       inet_ntoa(pdu->address.sin_addr), ntohs(pdu->address.sin_port));
	xdump(packet, length, "");
        printf("\n");
    }

    /* send the message */
    if (sendto(isp->sd, (char *)packet, length, 0,
	       (struct sockaddr *)&pdu->address, sizeof(pdu->address)) < 0){
	snmp_errno = SNMPERR_BAD_SENDTO;
	session->s_snmp_errno = SNMPERR_BAD_SENDTO;
	session->s_errno = errno;
	return 0;
    }

    /* check if should get a response */
    if (expect_response != 0) {
        gettimeofday(&tv, (struct timezone *)0);

	/* set up to expect a response */
	rp = (struct request_list *)malloc(sizeof(struct request_list));
	if (rp == NULL) {
	    snmp_errno = SNMPERR_GENERR;
	    session->s_snmp_errno = SNMPERR_GENERR;
	    return 0;
	}
	memset(rp, 0, sizeof(struct request_list));
	/* XX isp needs lock iff multiple threads can handle this session */
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
        rp->callback = callback;
        rp->cb_data = cb_data;
	rp->retries = 0;
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
 * Frees the variable and any malloc'd data associated with it.
 */
void
snmp_free_var(var)
    struct variable_list *var;
{
    if (var->name) free((char *)var->name);
    if (var->val.string) free((char *)var->val.string);
    free((char *)var);
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
    if (pdu->enterprise) free((char *)pdu->enterprise);
    if (pdu->community) free((char *) pdu->community);
    if (pdu->srcParty) free((char *)pdu->srcParty);
    if (pdu->dstParty) free((char *)pdu->dstParty);
    if (pdu->context) free((char *)pdu->context);
    free((char *)pdu);
}


/*
 * Frees the pdu and any malloc'd data associated with it.
 */
static void
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
	free(ovp);
    }
    if (pdu->enterprise) free(pdu->enterprise);
    if (pdu->community) free(pdu->community);
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

    for(slp = Sessions; slp; slp = slp->next){
        if (FD_ISSET(slp->internal->sd, fdset))
	    snmp_sess_read((void *)slp);
    }
}

/* Same as snmp_read, but works just one session. */
void
snmp_sess_read(sessp)
    void *sessp;
{
    struct session_list *slp = (struct session_list*)sessp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    u_char packet[PACKET_LENGTH];
    struct sockaddr_in	from;
    int length, fromlength;
    struct snmp_pdu *pdu;
    struct request_list *rp, *orp = NULL;
    snmp_callback callback;
    void *magic;

    sp = slp->session; isp = slp->internal;
    sp->s_snmp_errno = 0;
    sp->s_errno = 0;
    callback = sp->callback;
    magic = sp->callback_magic;
    fromlength = sizeof from;
    length = recvfrom(isp->sd, (char *)packet, PACKET_LENGTH, 0,
		      (struct sockaddr *)&from, &fromlength);
    if (length == -1) {
	snmp_errno = SNMPERR_BAD_RECVFROM;
	sp->s_snmp_errno = SNMPERR_BAD_RECVFROM;
	sp->s_errno = errno;
	snmp_set_detail(strerror(errno));
	return;
    }
    if (snmp_dump_packet){
	printf("\nreceived %d bytes from %s:%hu:\n", length,
	       inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	xdump(packet, length, "");
                printf("\n");
    }

    pdu = (struct snmp_pdu *)malloc(sizeof(struct internal_snmp_pdu));
    memset (pdu, 0, sizeof(*pdu));
    pdu->address = from;
    if (snmp_parse(sp, (struct internal_snmp_pdu *)pdu, packet, length) != SNMP_ERR_NOERROR){
	snmp_free_internal_pdu(pdu);
	return;
    }

    if (pdu->command == SNMP_MSG_RESPONSE){
	for(rp = isp->requests; rp; rp = rp->next_request){
	    if (rp->request_id == pdu->reqid){
		callback = sp->callback;
		magic = sp->callback_magic;
		if (rp->callback) callback = rp->callback;
		if (rp->cb_data) magic = rp->cb_data;
	        if (callback == NULL || callback(RECEIVED_MESSAGE, sp, pdu->reqid,
				 pdu, magic) == 1){
		    /* successful, so delete request */
		    if (isp->requests == rp){
			/* first in list */
			isp->requests = rp->next_request;
			if (isp->requestsEnd == rp)
			    isp->requestsEnd = NULL;
		    } else {
			orp->next_request = rp->next_request;
			if (isp->requestsEnd == rp)
			    isp->requestsEnd = orp;
		    }
		    snmp_free_pdu(rp->pdu);
		    free((char *)rp);
		    /* there shouldn't be any more requests with the
		       same reqid */
		    break;
		}
	    }
	    orp = rp;
	}
    } else if (pdu->command == SNMP_MSG_GET
	       || pdu->command == SNMP_MSG_GETNEXT
	       || pdu->command == SNMP_MSG_TRAP
	       || pdu->command == SNMP_MSG_SET
	       || pdu->command == SNMP_MSG_GETBULK
	       || pdu->command == SNMP_MSG_INFORM
	       || pdu->command == SNMP_MSG_TRAP2){
	if (sp->callback)
	    sp->callback(RECEIVED_MESSAGE, sp, pdu->reqid, pdu,
		     sp->callback_magic);
    }
    snmp_free_internal_pdu(pdu);
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
 * The value of block indicates how the timeout value is interpreted.
 * If block is true on input, the timeout value will be treated as undefined,
 * but it must be available for setting in snmp_select_info.  On return, 
 * block is set to true if the value returned for timeout is undefined; 
 * when block is set to false, timeout may be used as a parmeter to 'select'.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The number of
 * sessions open)
 */

int
snmp_select_info(numfds, fdset, timeout, block)
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block; /* input:  set to 1 if input timeout value is undefined  */
                    /*         set to 0 if input timeout value is defined    */
                    /* output: set to 1 if output timeout value is undefined */
                    /*         set to 0 if output rimeout vlaue id defined   */
{
    return snmp_sess_select_info((void *)0, numfds, fdset, timeout, block);
}

/* Same as snmp_select_info, but works just one session. */
int
snmp_sess_select_info(sessp, numfds, fdset, timeout, block)
    void    *sessp;
    int	    *numfds;
    fd_set  *fdset;
    struct timeval *timeout;
    int	    *block;
{
    struct session_list *slptest = (struct session_list *)sessp;
    struct session_list *slp;
    struct snmp_internal_session *isp;
    struct request_list *rp;
    struct timeval now, earliest;
    int active = 0, requests = 0;

    timerclear(&earliest);
    /*
     * For each request outstanding, add it's socket to the fdset,
     * and if it is the earliest timeout to expire, mark it as lowest.
     * If a single session is specified, do just for that session.
     */
    if (slptest) slp = slptest; else slp = Sessions;
    for(; slp; slp = slp->next){
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
	if (slp == slptest) break;
    }
    if (requests == 0) { /* if none are active, skip arithmetic */
       *block = 1; /* can block - timeout value is undefined if no requests*/
	return active;
    }

    /*
     * Now find out how much time until the earliest timeout.  This
     * transforms earliest from an absolute time into a delta time, the
     * time left until the select should timeout.
     */
    gettimeofday(&now,(struct timezone *)0);
    /*Now = now;*/

    if (earliest.tv_sec < now.tv_sec) {
       earliest.tv_sec  = 0;
       earliest.tv_usec = 100;
    }
    else if (earliest.tv_sec == now.tv_sec) {
       earliest.tv_sec  = 0;
       earliest.tv_usec = (earliest.tv_usec - now.tv_usec);
       if (earliest.tv_usec < 0) {
          earliest.tv_usec = 100;
       }
    }
    else {
       earliest.tv_sec  = (earliest.tv_sec  - now.tv_sec);
       earliest.tv_usec = (earliest.tv_usec - now.tv_usec);
       if (earliest.tv_usec < 0) {
          earliest.tv_sec --;
          earliest.tv_usec = (1000000L + earliest.tv_usec);
       }
    }

    /* if it was blocking before or our delta time is less, reset timeout */
    if (*block || timercmp(&earliest, timeout, <)){
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
snmp_timeout __P((void))
{
    struct session_list *slp;

    for(slp = Sessions; slp; slp = slp->next){
	snmp_sess_timeout((void *)slp);
    }
}

void
snmp_sess_timeout(sessp)
    void       *sessp;
{
    struct session_list *slp = (struct session_list*)sessp;
    struct snmp_session *sp;
    struct snmp_internal_session *isp;
    struct request_list *rp, *orp = NULL, *freeme = NULL;
    struct timeval now;
    snmp_callback callback;
    void *magic;

    sp = slp->session; isp = slp->internal;

    gettimeofday(&now,(struct timezone *)0);

    /*
     * For each request outstanding, check to see if it has expired.
     */
    for(rp = isp->requests; rp; rp = rp->next_request){
        if (freeme != NULL){
    	/* frees rp's after the for loop goes on to the next_request */
    	free((char *)freeme);
    	freeme = NULL;
        }
        if (timercmp(&rp->expire, &now, <)){
    	/* this timer has expired */
    	if (rp->retries >= sp->retries){
    	    callback = (rp->callback ? rp->callback : sp->callback);
    	    magic = (rp->cb_data ? rp->cb_data : sp->callback_magic);
    	    /* No more chances, delete this entry */
    	    if (callback)
		callback(TIMED_OUT, sp, rp->pdu->reqid, rp->pdu, magic);
    	    if (orp == NULL){
    		isp->requests = rp->next_request;
    		if (isp->requestsEnd == rp)
    		    isp->requestsEnd = NULL;
    	    } else {
    		orp->next_request = rp->next_request;
    		if (isp->requestsEnd == rp)
    		    isp->requestsEnd = orp;
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
    	    if (snmp_build(sp, rp->pdu, packet, &length) < 0){
    		/* this should never happen */
    		break;
    	    }
    	    if (snmp_dump_packet){
    		printf("\nsending %d bytes to %s:%hu:\n", length,
    		       inet_ntoa(rp->pdu->address.sin_addr), ntohs(rp->pdu->address.sin_port));
    		xdump(packet, length, "");
    		printf("\n");
    	    }

    	    if (sendto(isp->sd, (char *)packet, length, 0,
    		       (struct sockaddr *)&rp->pdu->address,
    		       sizeof(rp->pdu->address)) < 0){
		snmp_errno = SNMPERR_BAD_SENDTO;
		sp->s_snmp_errno = SNMPERR_BAD_SENDTO;
		sp->s_errno = errno;
    		snmp_set_detail(strerror(errno));
    		break;
    	    }
    	    else {
		gettimeofday(&now, (struct timezone *)0);
		tv = now;
		rp->time = tv;
		tv.tv_usec += rp->timeout;
		tv.tv_sec += tv.tv_usec / 1000000L;
		tv.tv_usec %= 1000000L;
		rp->expire = tv;
    	    }
    	}
        }
        orp = rp;
    }
    if (freeme != NULL){
        free((char *)freeme);
        freeme = NULL;
    }
}


static int dodebug = DODEBUG;

void
#ifdef STDC_HEADERS
DEBUGP(const char *first, ...)
#else
DEBUGP(va_alist)
  va_dcl
#endif
{
  va_list args;
#ifndef STDC_HEADERS
  const char *first;
  va_start(args);
  first = va_arg(args, const char *);
#else
  va_start(args,first);
#endif

  if (dodebug)
    vfprintf(stderr,first,args);
}

void
snmp_set_do_debugging(val)
  int val;
{
  dodebug = val;
}

int
snmp_get_do_debugging __P((void))
{
  return dodebug;
}


/*
 * returns NULL or internal pointer to session
 * use this pointer for the other snmp_sess* routines,
 * which guarantee action will occur ONLY for this given session.
 */
void *
snmp_sess_pointer(session)
    struct snmp_session *session;
{
    struct session_list *slp;

    for(slp = Sessions; slp; slp = slp->next){
	if (slp->session == session){
	    break;
	}
    }
    if (slp == NULL){
	snmp_errno = SNMPERR_BAD_SESSION;
	return(NULL);
    }
    return((void *)slp);
}

/*
 * Input : an opaque pointer, returned by snmp_sess_open.
 * returns NULL or pointer to session.
 */
struct snmp_session *
snmp_sess_session(sessp)
    void *sessp;
{
    struct session_list *slp = (struct session_list *)sessp;
    if (slp == NULL) return(NULL);
    return (slp->session);
}

