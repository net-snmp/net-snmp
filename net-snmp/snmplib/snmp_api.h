 
#ifndef SNMP_API_H
#define SNMP_API_H

/***********************************************************
	Copyright 1989 by Carnegie Mellon University

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
 * snmp_api.h - API for access to snmp.
 *
 * Caution: when using this library in a multi-threaded application,
 * the values of global variables "snmp_errno" and "snmp_detail"
 * cannot be reliably determined.  Suggest using snmp_error()
 * to obtain the library error codes.
 */

struct variable_list;
struct timeval;
struct synch_state;

typedef struct sockaddr_in  snmp_ipaddr;

struct snmp_pdu {
    int	    version;

    snmp_ipaddr  address;	/* Address of peer */
    u_char  *contextEngineID;	/* authoritative snmpEngineID */
    int	    contextEngineIDLen;  /* Length of contextEngineID */
    u_char  *contextName;	/* authoritative contextName */
    int	    contextNameLen;  /* Length of contextName */
    u_char  *securityName;	/* on behalf of this principal */
    int	    securityNameLen;  /* Length of securityName. */
    int	    securityModel; 
    int	    securityLevel;  /* noAuthNoPriv, authNoPriv, authPriv */
    oid	    *srcParty;
    int	    srcPartyLen;
    oid	    *dstParty;
    int	    dstPartyLen;
    oid	    *context;
    int     contextLen;

    u_char  *community;	/* community for outgoing requests. */
    int	    community_len;  /* Length of community name. */

    int	    command;	/* Type of this PDU */

    long  reqid;	/* Request id */
    long  errstat;	/* Error status (non_repeaters in GetBulk) */
    long  errindex;	/* Error index (max_repetitions in GetBulk) */

    /* Trap information */
    oid	    *enterprise;/* System OID */
    int	    enterprise_length;
    snmp_ipaddr  agent_addr;	/* address of object generating trap */
    long    trap_type;	/* trap type */
    long    specific_type;  /* specific type */
    u_long  time;	/* Uptime */

    void * secStateRef;

    struct variable_list *variables;
};

struct snmp_session {
    u_char  *community;	/* community for outgoing requests. */
    int	    community_len;  /* Length of community name. */
    u_char  *contextEngineID;	/* authoritative snmpEngineID */
    int	    contextEngineIDLen;  /* Length of contextEngineID */
    u_char  *contextName;	/* authoritative contextName */
    int	    contextNameLen;  /* Length of contextName */
    u_char  *securityName;	/* on behalf of this principal */
    int	    securityNameLen;  /* Length of securityName. */
    int	    securityModel; 
    int	    securityLevel;  /* noAuthNoPriv, authNoPriv, authPriv */
    int	    retries;	/* Number of retries before timeout. */
    long    timeout;    /* Number of uS until first timeout, then exponential backoff */
    char    *peername;	/* Domain name or dotted IP address of default peer */
    u_short remote_port;/* UDP port number of peer. */
    u_short local_port; /* My UDP port number, 0 for default, picked randomly */
    /* Authentication function or NULL if null authentication is used */
    u_char    *(*authenticator) __P((u_char *, int *, char *, int));
    int	    (*callback) __P((int, struct snmp_session *, int, struct snmp_pdu *, void *));
   	/* Function to interpret incoming data */
    /* Pointer to data that the callback function may consider important */
    void    *callback_magic;
    int	    version;
    oid	    *srcParty;
    int	    srcPartyLen;
    oid	    *dstParty;
    int	    dstPartyLen;
    oid	    *context;
    int	    contextLen;
    struct synch_state * snmp_synch_state;
    int     s_errno;        /* copy of system errno */
    int     s_snmp_errno;   /* copy of library errno */
};

typedef int (*snmp_callback) __P((int, struct snmp_session *, int, struct snmp_pdu *, void *));

/*
 * Set fields in session and pdu to the following to get a default or unconfigured value.
 */
#define SNMP_DEFAULT_COMMUNITY_LEN  0	/* to get a default community name */
#define SNMP_DEFAULT_RETRIES	    -1
#define SNMP_DEFAULT_TIMEOUT	    -1
#define SNMP_DEFAULT_REMPORT	    0
#define SNMP_DEFAULT_REQID	    0
#define SNMP_DEFAULT_ERRSTAT	    -1
#define SNMP_DEFAULT_ERRINDEX	    -1
#define SNMP_DEFAULT_ADDRESS	    0
#define SNMP_DEFAULT_PEERNAME	    NULL
#define SNMP_DEFAULT_ENTERPRISE_LENGTH	0
#define SNMP_DEFAULT_TIME	    0
#define SNMP_DEFAULT_VERSION	    -1
#define SNMP_MAX_MSG_SIZE           1200 /* this is provisional */
#define SNMP_MAX_ENG_SIZE     256
#define SNMP_MAX_SEC_NAME_SIZE     256
#define SNMP_MAX_SEC_NAME_SIZE     256
#define SNMP_MAX_CONTEXT_SIZE     256
#define SNMP_SEC_PARAM_BUF_SIZE     256

extern char *snmp_api_errstring __P((int));
extern void snmp_perror __P((char *));
extern void snmp_set_detail __P((char *));
#define SNMP_DETAIL_SIZE        512

/* 
 * Error return values.
 *
 * XXX	These should be merged with SNMP_ERR_* defines and confined
 *	to values < 0.  ???
 */
#define SNMPERR_SUCCESS			(0)  /* XXX  Non-PDU "success" code. */
#define SNMPERR_GENERR			(-1)
#define SNMPERR_BAD_LOCPORT		(-2)
#define SNMPERR_BAD_ADDRESS		(-3)
#define SNMPERR_BAD_SESSION		(-4)
#define SNMPERR_TOO_LONG		(-5)
#define SNMPERR_NO_SOCKET		(-6)
#define SNMPERR_V2_IN_V1		(-7)
#define SNMPERR_V1_IN_V2		(-8)
#define SNMPERR_BAD_REPEATERS		(-9)
#define SNMPERR_BAD_REPETITIONS		(-10)
#define SNMPERR_BAD_ASN1_BUILD		(-11)
#define SNMPERR_BAD_SENDTO		(-12)
#define SNMPERR_BAD_PARSE		(-13)
#define SNMPERR_BAD_VERSION		(-14)
#define SNMPERR_BAD_SRC_PARTY		(-15)
#define SNMPERR_BAD_DST_PARTY		(-16)
#define SNMPERR_BAD_CONTEXT		(-17)
#define SNMPERR_BAD_COMMUNITY		(-18)
#define SNMPERR_NOAUTH_DESPRIV		(-19)
#define SNMPERR_BAD_ACL			(-20)
#define SNMPERR_BAD_PARTY		(-21)
#define SNMPERR_ABORT			(-22)
#define SNMPERR_UNKNOWN_PDU		(-23)
#define SNMPERR_TIMEOUT 		(-24)
#define SNMPERR_BAD_RECVFROM 		(-25)
#define SNMPERR_BAD_ENG_ID 		(-26)
#define SNMPERR_BAD_SEC_NAME 		(-27)
#define SNMPERR_BAD_SEC_LEVEL 		(-28)
#define SNMPERR_SC_GENERAL_FAILURE	(-29)	
#define SNMPERR_SC_NOT_CONFIGURED	(-30)

#define SNMPERR_MAX			(-30)

#define non_repeaters	errstat
#define max_repetitions errindex


struct variable_list {
    struct variable_list *next_variable;    /* NULL for last variable */
    oid	    *name;  /* Object identifier of variable */
    int	    name_length;    /* number of subid's in name */
    u_char  type;   /* ASN type of variable */
    union { /* value of variable */
	long	*integer;
	u_char	*string;
	oid	*objid;
	u_char  *bitstring;
	struct counter64 *counter64;
#ifdef OPAQUE_SPECIAL_TYPES
	float   *floatVal;
	double	*doubleVal;
/*	t_union *unionVal; */
#endif /* OPAQUE_SPECIAL_TYPES */
    } val;
    int	    val_len;
};

/*
 * struct snmp_session *snmp_open(session)
 *	struct snmp_session *session;
 * 
 * Sets up the session with the snmp_session information provided
 * by the user.  Then opens and binds the necessary UDP port.
 * A handle to the created session is returned (this is different than
 * the pointer passed to snmp_open()).  On any error, NULL is returned
 * and snmp_errno is set to the appropriate error code.
 */
struct snmp_session *snmp_open __P((struct snmp_session *));

/*
 * int snmp_close(session)
 *     struct snmp_session *session;
 * 
 * Close the input session.  Frees all data allocated for the session,
 * dequeues any pending requests, and closes any sockets allocated for
 * the session.  Returns 0 on error, 1 otherwise.
 */
int snmp_close __P((struct snmp_session *));


/*
 * int snmp_send(session, pdu)
 *     struct snmp_session *session;
 *     struct snmp_pdu	*pdu;
 * 
 * Sends the input pdu on the session after calling snmp_build to create
 * a serialized packet.  If necessary, set some of the pdu data from the
 * session defaults.  Add a request corresponding to this pdu to the list
 * of outstanding requests on this session, then send the pdu.
 * Returns the request id of the generated packet if applicable, otherwise 1.
 * On any error, 0 is returned.
 * The pdu is freed by snmp_send() unless a failure occured.
 */
int snmp_send __P((struct snmp_session *, struct snmp_pdu *));

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
int snmp_async_send __P((struct snmp_session *, struct snmp_pdu *, 
                         snmp_callback, void *));

/*
 * void snmp_read(fdset)
 *     fd_set  *fdset;
 * 
 * Checks to see if any of the fd's set in the fdset belong to
 * snmp.  Each socket with it's fd set has a packet read from it
 * and snmp_parse is called on the packet received.  The resulting pdu
 * is passed to the callback routine for that session.  If the callback
 * routine returns successfully, the pdu and it's request are deleted.
 */
void snmp_read __P((fd_set *));


/*
 * void
 * snmp_free_pdu(pdu)
 *     struct snmp_pdu *pdu;
 * 
 * Frees the pdu and any malloc'd data associated with it.
 */
void snmp_free_pdu __P((struct snmp_pdu *));

void snmp_free_var __P((struct variable_list *));
void snmp_free_varbind(struct variable_list *var);

/*
 * int snmp_select_info(numfds, fdset, timeout, block)
 * int *numfds;
 * fd_set   *fdset;
 * struct timeval *timeout;
 * int *block;
 *
 * Returns info about what snmp requires from a select statement.
 * numfds is the number of fds in the list that are significant.
 * All file descriptors opened for SNMP are OR'd into the fdset.
 * If activity occurs on any of these file descriptors, snmp_read
 * should be called with that file descriptor set.
 *
 * The timeout is the latest time that SNMP can wait for a timeout.  The
 * select should be done with the minimum time between timeout and any other
 * timeouts necessary.  This should be checked upon each invocation of select.
 * If a timeout is received, snmp_timeout should be called to check if the
 * timeout was for SNMP.  (snmp_timeout is idempotent)
 *
 * Block is 1 if the select is requested to block indefinitely, rather than time out.
 * If block is input as 1, the timeout value will be treated as undefined, but it must
 * be available for setting in snmp_select_info.  On return, if block is true, the value
 * of timeout will be undefined.
 *
 * snmp_select_info returns the number of open sockets.  (i.e. The number of sessions open)
 */
int snmp_select_info __P((int *, fd_set *, struct timeval *, int *));

/*
 * void snmp_timeout();
 * 
 * snmp_timeout should be called whenever the timeout from snmp_select_info expires,
 * but it is idempotent, so snmp_timeout can be polled (probably a cpu expensive
 * proposition).  snmp_timeout checks to see if any of the sessions have an
 * outstanding request that has timed out.  If it finds one (or more), and that
 * pdu has more retries available, a new packet is formed from the pdu and is
 * resent.  If there are no more retries available, the callback for the session
 * is used to alert the user of the timeout.
 */
void snmp_timeout __P((void));


/*
 * This routine must be supplied by the application:
 *
 * u_char *authenticator(pdu, length, community, community_len)
 * u_char *pdu;		The rest of the PDU to be authenticated
 * int *length;		The length of the PDU (updated by the authenticator)
 * u_char *community;	The community name to authenticate under.
 * int	community_len	The length of the community name.
 *
 * Returns the authenticated pdu, or NULL if authentication failed.
 * If null authentication is used, the authenticator in snmp_session can be
 * set to NULL(0).
 */

/*
 * This routine must be supplied by the application:
 *
 * int callback(operation, session, reqid, pdu, magic)
 * int operation;
 * struct snmp_session *session;    The session authenticated under.
 * int reqid;			    The request id of this pdu (0 for TRAP)
 * struct snmp_pdu *pdu;	    The pdu information.
 * void *magic			    A link to the data for this routine.
 *
 * Returns 1 if request was successful, 0 if it should be kept pending.
 * Any data in the pdu must be copied because it will be freed elsewhere.
 * Operations are defined below:
 */
#define RECEIVED_MESSAGE   1
#define TIMED_OUT	   2


void snmp_set_dump_packet __P((int));
int snmp_get_dump_packet __P((void));
void snmp_set_quick_print __P((int));
int snmp_get_quick_print __P((void));
void snmp_set_full_objid __P((int));
int snmp_get_full_objid __P((void));
void snmp_set_suffix_only __P((int));
int snmp_get_suffix_only __P((void));
int snmp_get_errno __P((void));
void snmp_set_do_debugging __P((int));
int snmp_get_do_debugging __P((void));
int compare __P((oid *, int, oid *, int));
void init_snmp __P((char *));
u_char * snmp_pdu_build __P((struct snmp_pdu *, u_char *, int *));
int snmpv3_parse(struct snmp_pdu *, u_char *, int *, u_char  **);
int snmpv3_packet_build(struct snmp_pdu *pdu, u_char *packet, int *out_length, u_char *pdu_data, int pdu_data_len);
void snmp_pdu_add_variable __P((struct snmp_pdu *, oid *, int, u_char, u_char *, int));
int hex_to_binary __P((u_char *, u_char *));
int ascii_to_binary __P((u_char *, u_char *));
int snmp_add_var __P((struct snmp_pdu *, oid*, int, char, char *));
oid  *snmp_duplicate_objid(oid *objToCopy, int);
u_int snmp_increment_statistic(int which);
u_int snmp_get_statistic(int which);
void  snmp_init_statistics(void);
  
#ifdef __STDC__
void DEBUGP __P((const char *, ...));
#else
void DEBUGP __P((va_alist));
#endif
void DEBUGPOID __P((oid *, int));

#ifdef CMU_COMPATIBLE
extern int snmp_dump_packet;
extern int quick_print;
#endif

/*
 * snmp_error - return error data
 * Inputs :  address of errno, address of snmp_errno, address of string
 * Caller must free the string returned after use.
 */
void snmp_error __P((struct snmp_session *, int *, int *, char **));

/*
 * single session API.
 *
 * These functions perform similar actions as snmp_XX functions,
 * but operate on a single session only.
 *
 * Synopsis:

	void * sessp;
	struct snmp_session session, *ss;
	struct snmp_pdu *pdu, *response;

	snmp_sess_init(&session);
	session.retries = ...
	session.remote_port = ...
	snmp_synch_setup(&session);
	sessp = snmp_sess_open(&session);
	ss = snmp_sess_session(sessp);
	if (ss == NULL)
		exit(1);
	...
	if (ss->community) free(ss->community);
	ss->community = strdup(gateway);
	ss->community_len = strlen(gateway);
	...
	snmp_sess_synch_response(sessp, pdu, &response);
	...
	snmp_synch_reset(&session);
	snmp_sess_close(sessp);

 * See also:
 * snmp_sess_synch_response, in snmp_client.h.

 * Notes:
 *  1. Invoke snmp_sess_session after snmp_sess_open.
 *  2. snmp_sess_session return value is an opaque pointer.
 *  3. Do NOT free memory returned by snmp_sess_session.
 *  4. Replace snmp_send(ss,pdu) with snmp_sess_send(sessp,pdu)
 */

void   snmp_sess_init       __P((struct snmp_session *));
void * snmp_sess_open       __P((struct snmp_session *));
struct snmp_session * snmp_sess_session    __P((void *));

/* use return value from snmp_sess_open as void * parameter */

int    snmp_sess_send       __P((void *, struct snmp_pdu *));
int    snmp_sess_async_send __P((void *, struct snmp_pdu *,
                                         snmp_callback, void *));
int    snmp_sess_select_info __P((void *, int *, fd_set *,
                                         struct timeval *, int *));
void   snmp_sess_read       __P((void *));
void   snmp_sess_timeout    __P((void *));
int    snmp_sess_close      __P((void *));

void   snmp_sess_error      __P((void *, int *, int *, char **));

/* end single session API */
 
#endif /* SNMP_API_H */

/* generic statistic counters */

/* snmpv3 statistics */

/* mpd stats */
#define   STAT_SNMPUNKNOWNSECURITYMODELS     0
#define   STAT_SNMPINVALIDMSGS               1
#define   STAT_SNMPUNKNOWNPDUHANDLERS        2
#define   STAT_MPD_STATS_START               STAT_SNMPUNKNOWNSECURITYMODELS
#define   STAT_MPD_STATS_END                 STAT_SNMPUNKNOWNPDUHANDLERS

/* usm stats */
#define   STAT_USMSTATSUNSUPPORTEDSECLEVELS  3
#define   STAT_USMSTATSNOTINTIMEWINDOWS      4
#define   STAT_USMSTATSUNKNOWNUSERNAMES      5
#define   STAT_USMSTATSUNKNOWNENGINEIDS      6
#define   STAT_USMSTATSWRONGDIGESTS          7
#define   STAT_USMSTATSDECRYPTIONERRORS      8
#define   STAT_USM_STATS_START               STAT_USMSTATSUNSUPPORTEDSECLEVELS
#define   STAT_USM_STATS_END                 STAT_USMSTATSDECRYPTIONERRORS

#define MAX_STATS                            8
