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
#include <ctype.h>
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

#ifdef HAVE_KMT_H
#	include <kmt.h>
#endif
#ifdef HAVE_KMT_ALGS_H
#	include <kmt_algs.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "snmp_impl.h"
#include "party.h"
#include "mib.h"
#include "context.h"
#include "system.h"
#include "int64.h"
#include "snmpv3.h"
#include "read_config.h"
#include "snmpusm.h"
#include "tools.h"
#include "keytools.h"
#include "debug.h"

#include "transform_oids.h"

/*
 * Globals.
 */
#define PACKET_LENGTH	(8 * 1024)

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

/*
 * The list of active/open sessions.
 */
struct session_list {
    struct session_list *next;
    struct snmp_session *session;
    struct snmp_internal_session *internal;
};

static char *api_errors[-SNMPERR_MAX+1] = {
    "No error",					/* SNMPERR_SUCCESS */
    "Generic error",				/* SNMPERR_GENERR */
    "Invalid local port",			/* SNMPERR_BAD_LOCPORT */
    "Unknown host",				/* SNMPERR_BAD_ADDRESS */
    "Unknown session",				/* SNMPERR_BAD_SESSION */
    "Too long",					/* SNMPERR_TOO_LONG */
    "No socket",				/* SNMPERR_NO_SOCKET */
    "Cannot send V2 PDU on V1 session",		/* SNMPERR_V2_IN_V1 */
    "Cannot send V1 PDU on V2 session",		/* SNMPERR_V1_IN_V2 */
    "Bad value for non-repeaters",		/* SNMPERR_BAD_REPEATERS */
    "Bad value for max-repetitions",		/* SNMPERR_BAD_REPETITIONS */
    "Error building ASN.1 representation",	/* SNMPERR_BAD_ASN1_BUILD */
    "Failure in sendto",			/* SNMPERR_BAD_SENDTO */
    "Bad parse of ASN.1 type",			/* SNMPERR_BAD_PARSE */
    "Bad version specified",			/* SNMPERR_BAD_VERSION */
    "Bad source party specified",		/* SNMPERR_BAD_SRC_PARTY */
    "Bad destination party specified",		/* SNMPERR_BAD_DST_PARTY */
    "Bad context specified",			/* SNMPERR_BAD_CONTEXT */
    "Bad community specified",			/* SNMPERR_BAD_COMMUNITY */
    "Cannot send noAuth/desPriv",		/* SNMPERR_NOAUTH_DESPRIV */
    "Bad ACL definition",			/* SNMPERR_BAD_ACL */
    "Bad Party definition",			/* SNMPERR_BAD_PARTY */
    "Session abort failure",			/* SNMPERR_ABORT */
    "Unknown PDU type",				/* SNMPERR_UNKNOWN_PDU */
    "Timeout",					/* SNMPERR_TIMEOUT */
    "Failure in recvfrom",			/* SNMPERR_BAD_RECVFROM */
    "Unable to determine contextEngineID",	/* SNMPERR_BAD_ENG_ID */
    "Unable to determine securityName",		/* SNMPERR_BAD_SEC_NAME */
    "Unable to determine securityLevel",	/* SNMPERR_BAD_SEC_LEVEL  */
    "ASN.1 parse error in message",             /* SNMPERR_ASN_PARSE_ERR */
    "Unknown security model in message",        /* SNMPERR_UNKNOWN_SEC_MODEL */
    "Invalid message (e.g. msgFlags)",          /* SNMPERR_INVALID_MSG */
    "Unknown engine ID",                        /* SNMPERR_UNKNOWN_ENG_ID */
    "Unknown user name",                        /* SNMPERR_UNKNOWN_USER_NAME */
    "Unsupported security level",           /* SNMPERR_UNSUPPORTED_SEC_LEVEL */
    "Authentication failure",               /* SNMPERR_AUTHENTICATION_FAILURE */
    "Not in time window",                       /* SNMPERR_NOT_IN_TIME_WINDOW */
    "Decryptiion error",                        /* SNMPERR_DECRYPTION_ERR */
    "SCAPI general failure",			/* SNMPERR_SC_GENERAL_FAILURE */
    "SCAPI sub-system not configured",		/* SNMPERR_SC_NOT_CONFIGURED */
    "Key tools not available",			/* SNMPERR_KT_NOT_AVAILABLE */
    "Unknown Report message",	                /* SNMPERR_UNKNOWN_REPORT */
    "USM generic error",	      /* SNMPERR_USM_GENERICERROR */
    "USM unknown security name",      /* SNMPERR_USM_UNKNOWNSECURITYNAME */
    "USM unsupported security level", /* SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL */
    "USM encryption error",	      /* SNMPERR_USM_ENCRYPTIONERROR */
    "USM authentication failure",     /* SNMPERR_USM_AUTHENTICATIONFAILURE */
    "USM parse error",		      /* SNMPERR_USM_PARSEERROR */
    "USM unknown engineID",	      /* SNMPERR_USM_UNKNOWNENGINEID */
    "USM not in time window",	      /* SNMPERR_USM_NOTINTIMEWINDOW */
    "USM decryption error",	      /* SNMPERR_USM_DECRYPTIONERROR */
};

static char * usmSecLevelName[] =
	{
		"BAD_SEC_LEVEL",
		"noAuthNoPriv",
		"authNoPriv",
		"authPriv"
	};

static int dodebug = DODEBUG;



/*
 * Multiple threads may changes these variables.
 * Suggest using the Single API, which does not use Sessions.
 *
 * Reqid may need to be protected. Time will tell...
 *
 */
/*MTCRITICAL_RESOURCE*/
struct session_list	*Sessions	 = NULL;
long			 Reqid		 = 0;
/*END MTCRITICAL_RESOURCE*/

/*struct timeval Now;*/
static unsigned short default_s_port = 0;	/* default SNMP service port */
int snmp_errno = 0;
char *snmp_detail = NULL;

static int snmp_dump_packet = 0;

/*
 * Prototypes.
 */
static void free_request_list __P((struct request_list *));
void shift_array __P((u_char *, int, int));
static void snmpv3_calc_msg_flags __P((int, int, u_char *));
static int snmpv3_build_probe_pdu __P((struct snmp_pdu **));
static int snmpv3_build __P((struct snmp_session *, struct snmp_pdu *, 
			     u_char *, int *));
static int snmp_build __P((struct snmp_session *, struct snmp_pdu *, 
			   u_char *, int *));
static int snmp_parse __P((struct snmp_session *, struct snmp_pdu *, 
			   u_char *, int));
static int snmp_parse_version __P((u_char *, int));
static void * snmp_sess_pointer __P((struct snmp_session *));
static int snmp_resend_request (struct session_list *slp, 
				struct request_list *rp, 
				int incr_retries);



#ifndef HAVE_STRERROR
char *
strerror(err)
int err;
{
  extern char *sys_errlist[];
  extern int sys_nerr;

  if (err < 0 || err >= sys_nerr) return "Unknown error";
  return sys_errlist[err];
}
#endif

void
snmp_set_dump_packet(val)
    int val;
{
    snmp_dump_packet = val;
}

int snmp_get_dump_packet __P((void))
{
    return snmp_dump_packet;
}

int 
snmp_get_errno __P((void))
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
 * Gets initial request ID for all transactions,
 * and finds which port SNMP over UDP uses.
 * SNMP over AppleTalk or IPX is not currently supported.
 */
static void
init_snmp_session __P((void))
{
    struct servent *servp;
    struct timeval tv;

    if (Reqid) return;
    Reqid = 1;

    gettimeofday(&tv,(struct timezone *)0);
    /*Now = tv;*/

#ifdef SVR4
    srand48(tv.tv_sec ^ tv.tv_usec);
    Reqid = lrand48();
#else
    srandom(tv.tv_sec ^ tv.tv_usec);
    Reqid = random();
#endif

    default_s_port = htons(SNMP_PORT);
    servp = getservbyname("snmp", "udp");
    if (servp)
      default_s_port = servp->s_port;
}

/*
 * Initializes the session structure.
 * May perform one time minimal library initialization.
 * No MIB file processing is done via this call.
 */
void
snmp_sess_init(session)
    struct snmp_session * session;
{
extern int init_mib_internals();

    init_snmp_session();
    init_mib_internals();

    /* initialize session to default values */

    memset(session, 0, sizeof(struct snmp_session));
    session->remote_port = SNMP_DEFAULT_REMPORT;
    session->timeout = SNMP_DEFAULT_TIMEOUT;
    session->retries = SNMP_DEFAULT_RETRIES;
    session->version = SNMP_VERSION_1;
}




/*******************************************************************-o-******
 * init_snmp
 *
 * Parameters:
 *      *type   Label for the config file "type" used by calling entity.
 *
 * Call appropriately the functions to do config file loading and
 * mib module parsing in the correct order.
 */
void
init_snmp(char *type)
{
  static int	done_init = 0;	/* To prevent double init's. */
  char          file[512];

  if (done_init) {
    return;
  }
  done_init = 1;

  snmp_init_statistics();
  register_mib_handlers();
  init_snmpv3(type);

  read_premib_configs();
  init_mib();

  read_configs();

  init_usm_post_config();
  init_snmpv3_post_config();
  init_snmp_session();

}  /* end init_snmp() */

/* snmp_shutdown(char *type):

   Parameters:
        *type   Label for the config file "type" used by calling entity.

   Does the appropriate shutdown calls for the library, saving
   persistent data, clean up, etc...
*/
void
snmp_shutdown(char *type) {
  snmp_clean_persistent(type);
  shutdown_snmpv3(type);
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
    if (!slp) return NULL;

    { /*MTCRITICAL_RESOURCE*/
	slp->next = Sessions;
	Sessions = slp;
    }
    return (slp->session);
}



/*******************************************************************-o-******
 * snmp_sess_open
 *
 * Parameters:
 *	*in_session
 *
 * Returns:
 *      Pointer to a session in the session list   -OR-		FIX -- right?
 *	NULL on failure.
 *
 * The "spin-free" version of snmp_open.
 */
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
    struct snmp_pdu *pdu, *response;
    int status, i;

    if (Reqid == 0)
      init_snmp_session();

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

    if (session->securityLevel <= 0)
      session->securityLevel = get_default_secLevel();

    if (session->securityAuthProtoLen > 0) {
      cp = (u_char*)malloc((unsigned)session->securityAuthProtoLen *
			   sizeof(oid));
      if (cp == NULL) {
	snmp_errno = SNMPERR_GENERR;
	in_session->s_snmp_errno = SNMPERR_GENERR;
	snmp_sess_close(slp);
	return(NULL);
      }
      memmove(cp, session->securityAuthProto,
	      session->securityAuthProtoLen * sizeof(oid));
      session->securityAuthProto = (oid*)cp;
    } else if (get_default_authtype(&i) != NULL) {
        session->securityAuthProto =
          snmp_duplicate_objid(get_default_authtype(NULL), i);
        session->securityAuthProtoLen = i;
    }

    if (session->securityPrivProtoLen > 0) {
      cp = (u_char*)malloc((unsigned)session->securityPrivProtoLen *
			   sizeof(oid));
      if (cp == NULL) {
	snmp_errno = SNMPERR_GENERR;
	in_session->s_snmp_errno = SNMPERR_GENERR;
	snmp_sess_close(slp);
	return(NULL);
      }
      memmove(cp, session->securityPrivProto,
	      session->securityPrivProtoLen * sizeof(oid));
      session->securityPrivProto = (oid*)cp;
    } else if (get_default_privtype(&i) != NULL) {
        session->securityPrivProto =
          snmp_duplicate_objid(get_default_privtype(NULL), i);
        session->securityPrivProtoLen = i;
    }

    if (session->contextEngineIDLen > 0) {
      cp = (u_char*)malloc((unsigned)session->contextEngineIDLen *
			   sizeof(u_char));
      if (cp == NULL) {
	snmp_errno = SNMPERR_GENERR;
	in_session->s_snmp_errno = SNMPERR_GENERR;
	snmp_sess_close(slp);
	return(NULL);
      }
      memmove(cp, session->contextEngineID,
	      session->contextEngineIDLen * sizeof(u_char));
      session->contextEngineID = cp;

    }

    if (session->contextName) {
      session->contextName = strdup(session->contextName);
      if (cp == NULL) {
	snmp_errno = SNMPERR_GENERR;
	in_session->s_snmp_errno = SNMPERR_GENERR;
	snmp_sess_close(slp);
	return(NULL);
      }
    } else if ((cp = get_default_context()) != NULL) {
      cp = strdup(cp);
      if (cp == NULL) {
	snmp_errno = SNMPERR_GENERR;
	in_session->s_snmp_errno = SNMPERR_GENERR;
	snmp_sess_close(slp);
	return(NULL);
      }
      session->contextName = cp;
      session->contextNameLen = strlen(cp);
    }

    if (session->securityName) {
      session->securityName = strdup(session->securityName);
      if (session->securityName == NULL) {
	snmp_errno = SNMPERR_GENERR;
	in_session->s_snmp_errno = SNMPERR_GENERR;
	snmp_sess_close(slp);
	return(NULL);
      }
    } else if ((cp = get_default_secName()) != NULL) {
      cp = strdup(cp);
      if (cp == NULL) {
	snmp_errno = SNMPERR_GENERR;
	in_session->s_snmp_errno = SNMPERR_GENERR;
	snmp_sess_close(slp);
	return(NULL);
      }
      session->securityName = cp;
      session->securityNameLen = strlen(cp);
    }

    if (in_session->securityAuthKeyLen > 0) {
      session->securityAuthKeyLen = in_session->securityAuthKeyLen;
      memcpy(session->securityAuthKey, in_session->securityAuthKey,
             session->securityAuthKeyLen);
    } else if (get_default_authpass()) {
      session->securityAuthKeyLen = USM_AUTH_KU_LEN;
      if (generate_Ku(session->securityAuthProto,
                      session->securityAuthProtoLen,
                      get_default_authpass(), strlen(get_default_authpass()),
                      session->securityAuthKey,
                      &session->securityAuthKeyLen) != SNMPERR_SUCCESS) {
        snmp_set_detail("Error generating Ku from authentication pass phrase.");
	snmp_errno = SNMPERR_GENERR;
	in_session->s_snmp_errno = SNMPERR_GENERR;
	snmp_sess_close(slp);
        return NULL;
      }
    }

    if (in_session->securityPrivKeyLen > 0) {
      session->securityPrivKeyLen = in_session->securityPrivKeyLen;
      memcpy(session->securityPrivKey, in_session->securityPrivKey,
             session->securityPrivKeyLen);
    } else if (get_default_privpass()) {
      session->securityPrivKeyLen = USM_PRIV_KU_LEN;
      if (generate_Ku(session->securityAuthProto,
                      session->securityAuthProtoLen,
                      get_default_privpass(), strlen(get_default_privpass()),
                      session->securityPrivKey,
                      &session->securityPrivKeyLen) != SNMPERR_SUCCESS) {
        snmp_set_detail("Error generating Ku from privacy pass phrase.");
	snmp_errno = SNMPERR_GENERR;
	in_session->s_snmp_errno = SNMPERR_GENERR;
	snmp_sess_close(slp);
        return NULL;
      }
    }

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
	    isp->addr.sin_port = default_s_port;
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

    /* if we are opening a V3 session and we don't know engineID
       we must probe it - this must be done after the session is
       created and inserted in the list so that the response can
       handled correctly */
    if (session->version == SNMP_VERSION_3) {
      if (session->contextEngineIDLen == 0) {
	snmpv3_build_probe_pdu(&pdu);
	DEBUGP("probing for engineID...\n");
	status = snmp_sess_synch_response(slp, pdu, &response);

	if ((response == NULL) && (status == STAT_SUCCESS)) status = STAT_ERROR;

	switch (status) {
	case STAT_SUCCESS:
	  DEBUGP("error: expected Report as response to probe: %s (%d)\n",
		 snmp_errstring(response->errstat), response->errstat);
	  break;
	case STAT_ERROR: /* this is what we expected -> Report == STAT_ERROR */
	  break; 
	case STAT_TIMEOUT:
	default:
	  DEBUGP("unable to connect with remote engine: %s (%d)\n",
		 snmp_api_errstring(snmp_get_errno()),
		 snmp_get_errno());
	  break;
	}
	if (slp->session->contextEngineIDLen == 0) {
	  DEBUGP("unable to determine remote engine ID\n");
	  return NULL;
	}
	if (snmp_get_do_debugging()) {
	  DEBUGP("  probe found engineID:  ");
	  for(i = 0; i < slp->session->contextEngineIDLen; i++)
	    DEBUGP("%x", slp->session->contextEngineID[i]);
	  DEBUGP("\n");
	}
      }
      /* if boot/time supplied set it for this engineID */
      if (session->engineBoots || session->engineTime) {
	set_enginetime(session->contextEngineID, session->contextEngineIDLen,
		       session->engineBoots, session->engineTime, TRUE);
      }
      if (create_user_from_session(slp->session) != SNMPERR_SUCCESS)
	DEBUGP("snmp_sess_open(): failed(2) to create a new user from session\n");
    }


    return (void *)slp;

}  /* end snmp_sess_open() */



/* create_user_from_session(struct snmp_session *session):

   creates a user in the usm table from the information in a session

   Parameters:
        session -- IN: pointer to the session to use when creating the user.

   Returns:
        SNMPERR_SUCCESS
        SNMPERR_GENERR
*/
int
create_user_from_session(struct snmp_session *session)
{
  struct usmUser *user;

EM(-1);

  /* now that we have the engineID, create an entry in the USM list
     for this user using the information in the session */
  user = usm_get_user_from_list(session->contextEngineID,
                                session->contextEngineIDLen,
                                session->securityName,
                                usm_get_userList(), 0);
  if (user == NULL) {
    DEBUGP("Building user %s...\n",session->securityName);
    /* user doesn't exist so we create and add it */
    user = (struct usmUser *) SNMP_MALLOC(sizeof(struct usmUser));
    if (user == NULL)
      return SNMPERR_GENERR;

    /* copy in the securityName */
    if (session->securityName) {
      user->name = strdup(session->securityName);
      user->secName = strdup(session->securityName);
      if (user->name == NULL || user->secName == NULL) {
        usm_free_user(user);
        return SNMPERR_GENERR;
      }
    }

    /* copy in the engineID */
    if (memdup(&user->engineID, session->contextEngineID,
               session->contextEngineIDLen) != SNMPERR_SUCCESS) {
      usm_free_user(user);
      return SNMPERR_GENERR;
    }
    user->engineIDLen = session->contextEngineIDLen;

    /* copy the auth protocol */
    if (session->securityAuthProto != NULL) {
      user->authProtocol =
        snmp_duplicate_objid(session->securityAuthProto,
                             session->securityAuthProtoLen);
      if (user->authProtocol == NULL) {
        usm_free_user(user);
        return SNMPERR_GENERR;
      }
      user->authProtocolLen = session->securityAuthProtoLen;
    }

    /* copy the priv protocol */
    if (session->securityPrivProto != NULL) {
      user->privProtocol =
        snmp_duplicate_objid(session->securityPrivProto,
                             session->securityPrivProtoLen);
      if (user->privProtocol == NULL) {
        usm_free_user(user);
        return SNMPERR_GENERR;
      }
      user->privProtocolLen = session->securityPrivProtoLen;
    }

    /* copy in the authentication Key, and convert to the localized version */
    if (session->securityAuthKey != NULL && session->securityAuthKeyLen != 0) {
      user->authKey = malloc (USM_LENGTH_KU_HASHBLOCK);
      user->authKeyLen = USM_LENGTH_KU_HASHBLOCK;
      if (generate_kul( user->authProtocol, user->authProtocolLen,
                        session->contextEngineID, session->contextEngineIDLen,
                        session->securityAuthKey, session->securityAuthKeyLen,
                        user->authKey, &user->authKeyLen ) != SNMPERR_SUCCESS) {
        usm_free_user(user);
        return SNMPERR_GENERR;
      }
    }

    /* copy in the privacy Key, and convert to the localized version */
    if (session->securityPrivKey != NULL && session->securityPrivKeyLen != 0) {
      user->privKey = malloc (USM_LENGTH_KU_HASHBLOCK);
      user->privKeyLen = USM_LENGTH_KU_HASHBLOCK;
      if (generate_kul( user->authProtocol, user->authProtocolLen,
                        session->contextEngineID, session->contextEngineIDLen,
                        session->securityPrivKey, session->securityPrivKeyLen,
                        user->privKey, &user->privKeyLen ) != SNMPERR_SUCCESS) {
        usm_free_user(user);
        return SNMPERR_GENERR;
      }
    }

    /* add the user into the database */
    usm_add_user(user);
  }

  return  SNMPERR_SUCCESS;


}  /* end create_user_from_session() */

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

    _snmp_free((char *)slp->session->contextEngineID);
    _snmp_free((char *)slp->session->contextName);
    _snmp_free((char *)slp->session->securityName);
    _snmp_free((char *)slp->session->securityAuthProto);
    _snmp_free((char *)slp->session->securityPrivProto);
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

#ifdef notused	/* XXX */
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

static int
snmpv3_build_probe_pdu (pdu)
     struct snmp_pdu **pdu;
{
  struct usmUser *user;

  /* create the pdu */
  if (!pdu) return -1;
  *pdu = snmp_pdu_create(SNMP_MSG_GET);
  (*pdu)->version = SNMP_VERSION_3;
  (*pdu)->securityName = strdup("initial");
  (*pdu)->securityNameLen = strlen((*pdu)->securityName);
  (*pdu)->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
  (*pdu)->securityModel = SNMP_SEC_MODEL_USM;

  /* create the empty user */
  user = usm_get_user(NULL, 0, (*pdu)->securityName);
  if (user == NULL) {
    user = (struct usmUser *) SNMP_MALLOC(sizeof(struct usmUser));
    user->name = strdup((*pdu)->securityName);
    user->secName = strdup((*pdu)->securityName);
    user->authProtocolLen = sizeof(usmNoAuthProtocol)/sizeof(oid);
    user->authProtocol =
      snmp_duplicate_objid(usmNoAuthProtocol, user->authProtocolLen);
    user->privProtocolLen = sizeof(usmNoPrivProtocol)/sizeof(oid);
    user->privProtocol =
      snmp_duplicate_objid(usmNoPrivProtocol, user->privProtocolLen);
    usm_add_user(user);
  }
  return 0;
}

static void
snmpv3_calc_msg_flags (sec_level, msg_command, flags)
     int sec_level;
     int msg_command;
     u_char *flags;
{
  *flags = 0;
  if (sec_level == SNMP_SEC_LEVEL_AUTHNOPRIV)
    *flags = SNMP_MSG_FLAG_AUTH_BIT;
  else if (sec_level == SNMP_SEC_LEVEL_AUTHPRIV)
    *flags = SNMP_MSG_FLAG_AUTH_BIT | SNMP_MSG_FLAG_PRIV_BIT;

  if (msg_command == SNMP_MSG_GET || msg_command == SNMP_MSG_GETNEXT ||
      msg_command == SNMP_MSG_SET || msg_command == SNMP_MSG_GETBULK ||
      msg_command == SNMP_MSG_INFORM)
    *flags |= SNMP_MSG_FLAG_RPRT_BIT;

  return;
}

/* SNMPv3
 * Takes a session and a pdu and serializes the ASN PDU into the area
 * pointed to by packet.  out_length is the size of the data area available.
 * Returns the length of the completed packet in out_length.  If any errors
 * occur, -1 is returned.  If all goes well, 0 is returned.
 */
static int
snmpv3_build(session, pdu, packet, out_length)
    struct snmp_session	*session;
    struct snmp_pdu	*pdu;
    register u_char	*packet;
    int			*out_length;
{
  int ret;
  ret = snmpv3_packet_build(pdu, packet, out_length, NULL, 0);
  session->s_snmp_errno = snmp_errno;
  return ret;

}  /* end snmpv3_build() */



u_char *
snmpv3_header_build(struct snmp_pdu *pdu, register u_char *packet,
                    int *out_length, int length, u_char **msg_hdr_e)

{
    u_char			*global_hdr, *global_hdr_e;
    register u_char 		*cp;
    struct variable_list	*vp;
    u_char			 msg_flags;
    long			 max_size, sec_model;
    u_char			 pdu_buf[SNMP_MAX_MSG_SIZE];
    u_char			 msg_buf[SNMP_MAX_MSG_SIZE];
    u_char			 sec_param_buf[SNMP_SEC_PARAM_BUF_SIZE];
    int				 pdu_buf_len, msg_buf_len, sec_param_buf_len;
    u_char			*scopedPdu, *pb, *pb0e;

EM(-1);


    /* Save current location and build SEQUENCE tag and length placeholder
     * for SNMP message sequence (actual length inserted later)
     */
    cp = asn_build_sequence(packet, out_length,
			    (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), length);
    if (cp == NULL) return NULL;
    if (msg_hdr_e != NULL)
      *msg_hdr_e = cp;
    pb0e = cp;


    /* store the version field - msgVersion
     */
    cp = asn_build_int(cp, out_length,
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       (long *) &pdu->version, sizeof(pdu->version));
    if (cp == NULL) return NULL;

    global_hdr = cp;
    /* msgGlobalData HeaderData */
    cp = asn_build_sequence(cp, out_length,
			    (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (cp == NULL) return NULL;
    global_hdr_e = cp;


    /* request id being used as msgID in this case
     */
    cp = asn_build_int(cp, out_length,
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &pdu->reqid, sizeof(pdu->reqid));
    if (cp == NULL) return NULL;

    							/* msgMaxSize */
    max_size = SNMP_MAX_MSG_SIZE;
    cp = asn_build_int(cp, out_length,
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &max_size, sizeof(max_size));
    if (cp == NULL) return NULL;

    							/* msgFlags */
    snmpv3_calc_msg_flags(pdu->securityLevel, pdu->command, &msg_flags);
    cp = asn_build_string(cp, out_length,
			  (u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
			  &msg_flags, sizeof(msg_flags));
    if (cp == NULL) return NULL;

    							/* msgSecurityModel */
    sec_model = SNMP_SEC_MODEL_USM;
    cp = asn_build_int(cp, out_length,
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &sec_model, sizeof(sec_model));
    if (cp == NULL) return NULL;


    /* insert actual length of globalData
     */
    pb = asn_build_sequence(global_hdr, out_length,
                            (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                            cp - global_hdr_e);
    if (pb == NULL) return NULL;


    /* insert the actual length of the entire packet
     */
    pb = asn_build_sequence(packet, out_length,
			    (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                            length + (cp - pb0e));
    if (pb == NULL) return NULL;

    return cp;

}  /* end snmpv3_header_build() */



u_char *
snmpv3_scopedPDU_header_build(struct snmp_pdu *pdu,
                              register u_char *packet, int *out_length,
                              register u_char **spdu_e)

{
  u_char	 msg_buf[SNMP_MAX_MSG_SIZE];
  u_char	 spdu_buf[SNMP_MAX_MSG_SIZE];
  int		 spdu_buf_len, msg_buf_len, init_length;
  u_char	*scopedPdu, *pb, *pb0e;

EM(-1);

  init_length = *out_length;

  pb = scopedPdu = packet;
  pb = asn_build_sequence(pb, out_length,
                          (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
  if (pb == NULL) return NULL;
  if (spdu_e)
    *spdu_e = pb;

  pb = asn_build_string(pb, out_length,
                        (u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
                        pdu->contextEngineID, pdu->contextEngineIDLen);
  if (pb == NULL) return NULL;

  pb = asn_build_string(pb, out_length,
                        (u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
                        pdu->contextName, pdu->contextNameLen);
  if (pb == NULL) return NULL;

  return pb;

}  /* end snmpv3_scopedPDU_header_build() */



int
snmpv3_packet_build(struct snmp_pdu *pdu, u_char *packet, int *out_length,
		    u_char *pdu_data, int pdu_data_len)
{
    u_char	*global_data,		*sec_params,	*spdu_hdr_e;
    int		 global_data_len,	 sec_params_len;
    u_char	 spdu_buf[SNMP_MAX_MSG_SIZE];
    int		 spdu_buf_len, spdu_len;
    u_char	*cp;

EM(-1);

    snmp_errno  = SNMPERR_BAD_ASN1_BUILD;
    global_data = packet;


    /* 
     * build the headers for the packet, returned addr = start of secParams
     */
    sec_params = snmpv3_header_build(pdu, global_data, out_length, 0, NULL);
    if (sec_params == NULL) return -1;
    global_data_len = sec_params - global_data;
    sec_params_len = *out_length; /* length left in packet buf for sec_params */


    /* 
     * build a scopedPDU structure into spdu_buf
     */
    spdu_buf_len = SNMP_MAX_MSG_SIZE;
    cp = snmpv3_scopedPDU_header_build(pdu,spdu_buf,&spdu_buf_len,&spdu_hdr_e);
    if (cp == NULL) return -1;

    /* build the PDU structure onto the end of spdu_buf 
     */
    if (pdu_data) {
      memcpy(cp, pdu_data, pdu_data_len);
      cp += pdu_data_len;
    } else {
      cp = snmp_pdu_build(pdu, cp, &spdu_buf_len);
      if (cp == NULL) return -1;
    }


    /* 
     * re-encode the actual ASN.1 length of the scopedPdu
     */
    spdu_len = cp - spdu_hdr_e; /* length of scopedPdu minus ASN.1 headers */
    spdu_buf_len = SNMP_MAX_MSG_SIZE;
    if (asn_build_sequence(spdu_buf, &spdu_buf_len,
                           (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                           spdu_len) == NULL)
      return -1;
    spdu_len = cp - spdu_buf;	/* the length of the entire scopedPdu */


    /* 
     * call the security module to possibly encrypt and authenticate the
     * message - the entire message to transmitted on the wire is returned
     */
    cp = NULL; *out_length = SNMP_MAX_MSG_SIZE;
    snmp_errno =
     	usm_generate_out_msg(
			SNMP_VERSION_3,		
			global_data,		global_data_len,
                        SNMP_MAX_MSG_SIZE,	
			SNMP_SEC_MODEL_USM,
                        pdu->contextEngineID,	pdu->contextEngineIDLen,
                        pdu->securityName,	pdu->securityNameLen,
                        pdu->securityLevel,	
			spdu_buf,		spdu_len, 
			pdu->securityStateRef,
			sec_params,		&sec_params_len,
                        &cp,			out_length);
    if (snmp_errno != 0)
      return -1;

    snmp_errno = 0;


    return 0;

}  /* end snmpv3_packet_build() */



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
    u_char *h0, *h0e, *h1;
    register u_char  *cp;
    struct  packet_info pkt, *pi = &pkt;
    int length;
#ifdef USE_V2PARTY_PROTOCOL
    int packet_length;
#endif /* USE_V2PARTY_PROTOCOL */
    long version;

    if (pdu->version == SNMP_VERSION_3)
      return snmpv3_build(session, pdu, packet, out_length);

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
    default:
	return -1;
    }
    h1 = cp;
    cp = snmp_pdu_build(pdu, cp, out_length);

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
        snmp_party_build(packet, &length, pi, cp - h1,
                         pdu->srcParty, pdu->srcPartyLen,
                         pdu->dstParty, pdu->dstPartyLen,
                         pdu->context, pdu->contextLen,
                         &packet_length, LAST_PASS);

	/* Encryption might bump length of packet.
	 */
	cp = packet + packet_length;
	break;
#endif /* USE_V2PARTY_PROTOCOL */

    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    default:
	return -1;
    }
    *out_length = cp - packet;
    snmp_errno = 0;
    session->s_snmp_errno = 0;
    return 0;
}

u_char *
snmp_pdu_build (struct snmp_pdu *pdu, u_char *cp, int *out_length)
{
  u_char *h1, *h1e, *h2, *h2e;
  struct variable_list *vp;
  int length;

  length = *out_length;
  /* Save current location and build PDU tag and length placeholder
     (actual length will be inserted later) */
  h1 = cp;
  cp = asn_build_sequence(cp, out_length, (u_char)pdu->command, 0);
  if (cp == NULL)
    return NULL;
  h1e = cp;

  /* store fields in the PDU preceeding the variable-bindings sequence */
  if (pdu->command != SNMP_MSG_TRAP){
    /* PDU is not an SNMPv1 trap */

    /* request id */
    cp = asn_build_int(cp, out_length,
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &pdu->reqid, sizeof(pdu->reqid));
    if (cp == NULL)
      return NULL;

    /* error status (getbulk non-repeaters) */
    cp = asn_build_int(cp, out_length,
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &pdu->errstat, sizeof(pdu->errstat));
    if (cp == NULL)
      return NULL;

    /* error index (getbulk max-repetitions) */
    cp = asn_build_int(cp, out_length,
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       &pdu->errindex, sizeof(pdu->errindex));
    if (cp == NULL)
      return NULL;
  } else {
    /* an SNMPv1 trap PDU */

        /* enterprise */
    cp = asn_build_objid(cp, out_length,
			 (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
			 (oid *)pdu->enterprise, pdu->enterprise_length);
    if (cp == NULL)
      return NULL;

        /* agent-addr */
    cp = asn_build_string(cp, out_length,
			  (u_char)(ASN_IPADDRESS | ASN_PRIMITIVE),
			  (u_char *)&pdu->agent_addr.sin_addr.s_addr,
			  sizeof(pdu->agent_addr.sin_addr.s_addr));
    if (cp == NULL)
      return NULL;

        /* generic trap */
    cp = asn_build_int(cp, out_length,
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       (long *)&pdu->trap_type, sizeof(pdu->trap_type));
    if (cp == NULL)
      return NULL;

        /* specific trap */
    cp = asn_build_int(cp, out_length,
		       (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		       (long *)&pdu->specific_type, sizeof(pdu->specific_type));
    if (cp == NULL)
      return NULL;

        /* timestamp  */
    cp = asn_build_unsigned_int(cp, out_length,
				(u_char)(ASN_TIMETICKS | ASN_PRIMITIVE),
				&pdu->time, sizeof(pdu->time));
    if (cp == NULL)
      return NULL;
  }

  /* Save current location and build SEQUENCE tag and length placeholder
       for variable-bindings sequence
       (actual length will be inserted later) */
  h2 = cp;
  cp = asn_build_sequence(cp, out_length,
                          (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                          0);
  if (cp == NULL)
    return NULL;
  h2e = cp;

  /* Store variable-bindings */
  for(vp = pdu->variables; vp; vp = vp->next_variable){
    cp = snmp_build_var_op(cp, vp->name, &vp->name_length, vp->type,
			   vp->val_len, (u_char *)vp->val.string,
			   out_length);
    if (cp == NULL)
      return NULL;
  }

  /* insert actual length of variable-bindings sequence */
  asn_build_sequence(h2,&length,(u_char)(ASN_SEQUENCE|ASN_CONSTRUCTOR),cp-h2e);

  /* insert actual length of PDU sequence */
  asn_build_sequence(h1, &length, (u_char)pdu->command, cp - h1e);

  return cp;
}


/*
 * Parses the packet received to determine version, either directly
 * from packets version field or inferred from ASN.1 construct.
 */
static int
snmp_parse_version (data, length)
     u_char *data;
     int length;
{
  u_char type;
  long version;

  data = asn_parse_header(data, &length, &type);

  if (type == (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
    data = asn_parse_int(data, &length, &type, &version, sizeof(version));
  }
#ifdef USE_V2PARTY_PROTOCOL
  else {
    version = SNMP_VERSION_2p;
  }
#endif /* USE_V2PARTY_PROTOCOL */
  return version;
}

int
snmpv3_parse(pdu, data, length, after_header)
     struct snmp_pdu	 *pdu;
     u_char 		 *data;
     int    		 *length;
     u_char 		**after_header;
{
  u_char	 type;
  long		 ver, msg_max_size, msg_sec_model;
  int		 max_size_response;
  u_char	 tmp_buf[SNMP_MAX_MSG_SIZE];
  int		 tmp_buf_len;
  u_char	 pdu_buf[SNMP_MAX_MSG_SIZE];
  int		 pdu_buf_len = SNMP_MAX_MSG_SIZE;
  u_char	*sec_params;
  u_char	*msg_data;
  u_char	*cp;
  int		 asn_len, msg_len, sec_params_len, ret;
  int		 ret_val;

EM(-1);

  msg_data =  data;
  msg_len  = *length;


  /* message is an ASN.1 SEQUENCE
   */
  data = asn_parse_header(data, length, &type);
  if (data == NULL){
    ERROR_MSG("bad header");
    return -1;
  }
  if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)){
    ERROR_MSG("wrong message header type");
    return -1;
  }


  /* parse msgVersion
   */
  data = asn_parse_int(data, length, &type, &ver, sizeof(ver));
  if (data == NULL){
    ERROR_MSG("bad parse of version");
    return -1;
  }
  pdu->version = ver;


  /* parse msgGlobalData sequence
   */
  cp	  = data;
  asn_len = *length;
  data	  = asn_parse_header(data, &asn_len, &type);

  if (data == NULL){
    ERROR_MSG("bad header");
    return -1;
  }
  if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)){
    ERROR_MSG("wrong msgGlobalData  header type");
    return -1;
  }
  *length -= data - cp;  /* subtract off the length of the header */

  /* msgID - storing in reqid for now - may need seperate storage
   */
  data = asn_parse_int(data, length, &type, &pdu->reqid, sizeof(pdu->reqid));
  if (data == NULL) {
    ERROR_MSG("error parsing msgID");
    return -1;
  }

  							/* msgMaxSize */
  data = asn_parse_int(data, length, &type, &msg_max_size,
		       sizeof(msg_max_size));	/* FIX -- correct? */
  if (data == NULL) {
    ERROR_MSG("error parsing msgMaxSize");
    return -1;
  }
  tmp_buf_len = SNMP_MAX_MSG_SIZE;

  							/* msgFlags */
  data = asn_parse_string(data, length, &type, tmp_buf, &tmp_buf_len);
  if (data == NULL) {
    ERROR_MSG("error parsing msgFlags");
    return -1;
  }
  pdu->securityLevel = ( (*tmp_buf & SNMP_MSG_FLAG_AUTH_BIT)
				?  ( (*tmp_buf & SNMP_MSG_FLAG_PRIV_BIT)
					? SNMP_SEC_LEVEL_AUTHPRIV
					: SNMP_SEC_LEVEL_AUTHNOPRIV )
				: SNMP_SEC_LEVEL_NOAUTH );

  							/* msgSecurityModel */
  data = asn_parse_int(data, length, &type, &msg_sec_model,
		       sizeof(msg_sec_model));
  if (data == NULL) {
    ERROR_MSG("error parsing msgSecurityModel");
    return -1;
  }
  pdu->securityModel = msg_sec_model;

  /* end of msgGlobalData */

  /* securtityParameters OCTET STRING begins after msgGlobalData
   */
  sec_params			= data;
  pdu->contextEngineID		= SNMP_MALLOC(SNMP_MAX_ENG_SIZE);
  pdu->contextEngineIDLen	= SNMP_MAX_ENG_SIZE;
  pdu->securityName		= SNMP_MALLOC(SNMP_MAX_SEC_NAME_SIZE);
  pdu->securityNameLen		= SNMP_MAX_SEC_NAME_SIZE;

  memset(pdu_buf, 0, pdu_buf_len);
  cp = pdu_buf;

  ret_val = 
    usm_process_in_msg(
	 SNMP_VERSION_3,	 msg_max_size,
	 sec_params,		 msg_sec_model,		pdu->securityLevel,
	 msg_data,		 msg_len,
         pdu->contextEngineID,	&pdu->contextEngineIDLen,
         pdu->securityName,	&pdu->securityNameLen,
        &cp,
	&pdu_buf_len,		&max_size_response,
	&pdu->securityStateRef);

  if (ret_val != USM_ERR_NO_ERROR) {
    snmp_errno = ret_val;
    return -1;
  }
  

  /* parse plaintext ScopedPDU sequence
   */
  asn_len = *length = pdu_buf_len;
  data = asn_parse_header(cp, &asn_len, &type);
  if (data == NULL){
    ERROR_MSG("bad plaintext header");
    return -1;
  }
  if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)){
    ERROR_MSG("wrong plaintext header type");
    return -1;
  }
  *length -= data - cp;


  /* parse contextEngineID from scopedPdu 
   */
  tmp_buf_len = SNMP_MAX_MSG_SIZE;
  data = asn_parse_string(data, length, &type, tmp_buf, &tmp_buf_len);
  if (data == NULL) {
    ERROR_MSG("error parsing contextEngineID from scopedPdu");
    return -1;
  }


  /* check that it agrees with engineID returned from USM above
   */
  if (tmp_buf_len) {
    /* FIX BUG: USM is not returning pdu->contextEngineID on discovey probe */
    if (pdu->contextEngineIDLen == 0) {
      memcpy(pdu->contextEngineID, tmp_buf, tmp_buf_len);
      pdu->contextEngineIDLen = tmp_buf_len;
    }
    if (tmp_buf_len != pdu->contextEngineIDLen ||
	memcmp(tmp_buf, pdu->contextEngineID, tmp_buf_len) != 0) {
      ERROR_MSG("inconsistent engineID information in message");
      return -1;
    }
  }


  /* parse contextName from scopedPdu
   */
  tmp_buf_len = SNMP_MAX_CONTEXT_SIZE;
  data = asn_parse_string(data, length, &type, tmp_buf, &tmp_buf_len);
  if (data == NULL) {
    ERROR_MSG("error parsing contextName from scopedPdu");
    return -1;
  }

  if (tmp_buf_len) {
    pdu->contextName	 = strdup(tmp_buf);
    pdu->contextNameLen	 = tmp_buf_len;
  } else {
    pdu->contextName	 = strdup("");
    pdu->contextNameLen	 = 0;
  }

  /* parse the PDU.
   */
  if (after_header != NULL) {
    tmp_buf_len		 = *length;
    *after_header	 = data;
  }

  ret = snmp_pdu_parse((struct snmp_pdu *)pdu, data, length);

  if (after_header != NULL)
    *length = tmp_buf_len;


  return ret;
}  /* end snmpv3_parse() */

int
snmpv3_make_report(u_char *out_data, int *out_length,
                       struct snmp_pdu *pdu,
                       int error, oid *err_var, int err_var_len,
                       u_char *engineID, int engineIDLen)
{

  long ltmp;
  char buf[SNMP_MAXBUF];
  
  /* 
   * unknown incoming security engineID, return ours and a varbind
   */
  snmp_free_varbind(pdu->variables);	/* free the current varbind */

  pdu->variables		= NULL;
  pdu->contextEngineID		= engineID;
  pdu->contextEngineIDLen	= engineIDLen;
  pdu->command		 	= SNMP_MSG_REPORT;
  pdu->errstat		 	= 0;
  pdu->errindex		 	= 0;
  pdu->contextName		= strdup("");
  pdu->contextNameLen		= strlen(pdu->contextName);

  /* reports shouldn't cache previous data. */
  if (pdu->securityStateRef) {
    usm_free_usmStateReference(pdu->securityStateRef);
    pdu->securityStateRef = NULL;
  }
  
  if (error != STAT_USMSTATSNOTINTIMEWINDOWS) 
    pdu->securityLevel          = SNMP_SEC_LEVEL_NOAUTH;

  /* find the appropriate error counter
   */
  ltmp = snmp_get_statistic(error);

  /* return the appropriate error counter
   */
  snmp_pdu_add_variable(pdu, err_var, err_var_len,
                        ASN_COUNTER, (u_char *) &ltmp, sizeof(ltmp));
  snmpv3_packet_build(pdu, out_data, out_length, NULL, 0);
  sprint_objid(buf, err_var, err_var_len);
  DEBUGP("sending report with:\n  %s = %d\n", buf, ltmp);
  snmp_free_pdu(pdu);

  return 1;

}  /* end snmpv3_make_report() */


int
snmpv3_get_report_type(struct snmp_pdu *pdu)
{
  static oid snmpMPDStats[] = {1,3,6,1,6,3,11,2,1};
  static oid usmStats[] = {1,3,6,1,6,3,12,1,1};
  struct variable_list *vp;
  int rpt_type = SNMPERR_UNKNOWN_REPORT;

  if (pdu == NULL || pdu->variables == NULL) return rpt_type;
  vp = pdu->variables;
  if (vp->name_length == REPORT_STATS_LEN+1) {
    if (memcmp(snmpMPDStats,vp->name,REPORT_STATS_LEN*sizeof(oid)) == 0) {
      switch (vp->name[REPORT_STATS_LEN]) {
      case REPORT_snmpUnknownSecurityModels_NUM:
	rpt_type = SNMPERR_UNKNOWN_SEC_MODEL;
	break;
      case REPORT_snmpInvalidMsgs_NUM:
	rpt_type = SNMPERR_INVALID_MSG;
	break;
      }
    } else if (memcmp(usmStats,vp->name,REPORT_STATS_LEN*sizeof(oid)) == 0) {
      switch (vp->name[REPORT_STATS_LEN]) {
      case REPORT_usmStatsUnsupportedSecLevels_NUM:
	rpt_type = SNMPERR_UNSUPPORTED_SEC_LEVEL;
	break;
      case REPORT_usmStatsNotInTimeWindows_NUM:
	rpt_type = SNMPERR_NOT_IN_TIME_WINDOW;
	break;
      case REPORT_usmStatsUnknownUserNames_NUM:
	rpt_type = SNMPERR_UNKNOWN_USER_NAME;
	break;
      case REPORT_usmStatsUnknownEngineIDs_NUM:
	rpt_type = SNMPERR_UNKNOWN_ENG_ID;
	break;
      case REPORT_usmStatsWrongDigests_NUM:
	rpt_type = SNMPERR_AUTHENTICATION_FAILURE;
	break;
      case REPORT_usmStatsDecryptionErrors_NUM:
	rpt_type = SNMPERR_DECRYPTION_ERR;
	break;
      }
    }
  }
  return rpt_type;
}

/*
 * Parses the packet received on the input session, and places the data into
 * the input pdu.  length is the length of the input packet.  If any errors
 * are encountered, -1 is returned.  Otherwise, a 0 is returned.
 */
static int
snmp_parse(session, pdu, data, length)
    struct snmp_session *session;
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    length;
{
    u_char  type;
    struct packet_info pkt, *pi = &pkt;
    u_char community[COMMUNITY_MAX_LEN];
    int community_length = COMMUNITY_MAX_LEN;
    int result = -1;

    snmp_errno = SNMPERR_BAD_PARSE;
    session->s_snmp_errno = SNMPERR_BAD_PARSE;

    if (session->version != SNMP_DEFAULT_VERSION)
	pdu->version = session->version;
    else
        pdu->version = snmp_parse_version(data,length);

    switch (pdu->version) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
        DEBUGP("Parsing SNMPv%d message...\n", (1 + pdu->version));

	/* authenticates message and returns length if valid */
	data = snmp_comstr_parse(data, &length,
                                 community, &community_length,
			         &pdu->version);
	if (data == NULL)
	    return -1;
        if (pdu->version != session->version &&
	    session->version != SNMP_DEFAULT_VERSION)
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
	result = snmp_pdu_parse(pdu, data, &length);
        break;

    case SNMP_VERSION_2p:
#ifdef USE_V2PARTY_PROTOCOL
        /* message tag is a tagged context specific sequence
           that is,  "[1] IMPLICIT SEQUENCE" */
        if (type != (ASN_CONTEXT | ASN_CONSTRUCTOR | 1))
	    return -1;

        DEBUGP("Parsing SNMPv2p message...\n");
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
	pdu->version = pi->version;

	result = snmp_pdu_parse(pdu, data, &length);
        break;
#endif /* USE_V2PARTY_PROTOCOL */

    case SNMP_VERSION_3:
      result = snmpv3_parse((struct snmp_pdu *)pdu, data, &length, NULL);
      if (!result) {
	DEBUGP("Parsed SNMPv3 message (secName:%s, secLevel:%s).\n",
	       pdu->securityName, usmSecLevelName[pdu->securityLevel]);
      } else {
	DEBUGP("Error parsing SNMPv3 message (secName:%s, secLevel:%s).\n",
	       pdu->securityName, usmSecLevelName[pdu->securityLevel]);
      }
      break;

    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
    default:
        ERROR_MSG("unsupported/unknown message header type");
	return -1;
    }

    if (result == 0) {
      snmp_errno = 0;
      session->s_snmp_errno = 0;
      return 0;
    } else {
      return -1;
    }
}

int
snmp_pdu_parse(pdu, data, length)
    struct snmp_pdu *pdu;
    u_char  *data;
    int	    *length;
{
  u_char  type;
  u_char  msg_type;
  u_char  *var_val;
  int      badtype;
  int	    four, len;
  struct variable_list *vp = NULL;
  oid objid[MAX_NAME_LEN];
  char err[256];

  badtype = 0;

  /* Get the PDU type */
  data = asn_parse_header(data, length, &msg_type);
  if (data == NULL)
    return -1;
  pdu->command = msg_type;

  /* get the fields in the PDU preceeding the variable-bindings sequence */
  if (pdu->command != SNMP_MSG_TRAP){
    /* PDU is not an SNMPv1 TRAP */

    /* request id */
    data = asn_parse_int(data, length, &type, &pdu->reqid,
			 sizeof(pdu->reqid));
    if (data == NULL) {
      ERROR_MSG(strcat(strcpy(err, "parsing request-id: "), snmp_detail));
      return -1;
    }

    /* error status (getbulk non-repeaters) */
    data = asn_parse_int(data, length, &type, &pdu->errstat,
			 sizeof(pdu->errstat));
    if (data == NULL) {
      ERROR_MSG(strcat(strcpy(err, "parsing error status: "), snmp_detail));
      return -1;
    }

    /* error index (getbulk max-repetitions) */
    data = asn_parse_int(data, length, &type, &pdu->errindex,
			 sizeof(pdu->errindex));
    if (data == NULL) {
      ERROR_MSG(strcat(strcpy(err, "parsing error index: "), snmp_detail));
      return -1;
    }
  } else {
    /* an SNMPv1 trap PDU */

    /* enterprise */
    pdu->enterprise_length = MAX_NAME_LEN;
    data = asn_parse_objid(data, length, &type, objid,
			   &pdu->enterprise_length);
    if (data == NULL)
      return -1;
    pdu->enterprise = (oid *)malloc(pdu->enterprise_length * sizeof(oid));
    memmove(pdu->enterprise, objid, pdu->enterprise_length * sizeof(oid));

    /* agent-addr */
    four = 4;
    data = asn_parse_string(data, length, &type,
			    (u_char *)&pdu->agent_addr.sin_addr.s_addr,
			    &four);
    if (data == NULL)
      return -1;

    /* generic trap */
    data = asn_parse_int(data, length, &type, (long *)&pdu->trap_type,
			 sizeof(pdu->trap_type));
    if (data == NULL)
      return -1;
    /* specific trap */
    data = asn_parse_int(data, length, &type, (long *)&pdu->specific_type,
			 sizeof(pdu->specific_type));
    if (data == NULL)
      return -1;

    /* timestamp  */
    data = asn_parse_unsigned_int(data, length, &type, &pdu->time,
				  sizeof(pdu->time));
    if (data == NULL)
      return -1;
  }

  /* get header for variable-bindings sequence */
  data = asn_parse_header(data, length, &type);
  if (data == NULL)
    return -1;
  if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR))
    return -1;

    /* get each varBind sequence */
  while((int)*length > 0){
    if (vp == NULL){
      vp = (struct variable_list *)malloc(sizeof(struct variable_list));
      pdu->variables = (struct variable_list *)vp;
    } else {
      vp->next_variable = (struct variable_list *)malloc(sizeof(struct variable_list));
      vp = (struct variable_list *)vp->next_variable;
    }

    vp->next_variable = NULL;
    vp->val.string = NULL;
    vp->name_length = MAX_NAME_LEN;
    vp->name = vp->name_loc;
    vp->usedBuf = FALSE;
    data = snmp_parse_var_op(data, vp->name, &vp->name_length, &vp->type,
			     &vp->val_len, &var_val, (int *)length);
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
  return badtype;
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
      /* ENHANCE: we should support multi-lingual sessions */
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
          snmp_errno = SNMPERR_V1_IN_V2;
          session->s_snmp_errno = SNMPERR_V1_IN_V2;
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
        DEBUGP("Building SNMPv%d message...\n", (1 + pdu->version));
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
        DEBUGP("Building SNMPv2p message...\n");
        break;
#endif /* USE_V2PARTY_PROTOCOL */
    case SNMP_VERSION_3:
      if (pdu->contextEngineIDLen == 0) {
	if (session->contextEngineIDLen != 0){
	  pdu->contextEngineID =
	    (u_char*)malloc((unsigned)session->contextEngineIDLen *
			    sizeof(u_char));
	  if (pdu->contextEngineID == NULL) {
	    snmp_errno = SNMPERR_GENERR;
	    session->s_snmp_errno = SNMPERR_GENERR;
	    return 0;
	  }
	  memmove(pdu->contextEngineID, session->contextEngineID,
		  session->contextEngineIDLen * sizeof(u_char));
	  pdu->contextEngineIDLen = session->contextEngineIDLen;
	}
      }

      if (pdu->contextNameLen < 0) {
	if (!session->contextName){
	  snmp_errno = SNMPERR_BAD_CONTEXT;
	  session->s_snmp_errno = SNMPERR_BAD_CONTEXT;
	  return 0;
	}
	pdu->contextName = strdup(session->contextName);
	if (pdu->contextName == NULL) {
	  snmp_errno = SNMPERR_GENERR;
	  session->s_snmp_errno = SNMPERR_GENERR;
	  return 0;
	}
	pdu->contextNameLen = session->contextNameLen;
      }

      if (pdu->securityNameLen < 0) {
	if (session->securityNameLen == 0){
	  snmp_errno = SNMPERR_BAD_SEC_NAME;
	  session->s_snmp_errno = SNMPERR_BAD_SEC_NAME;
	  return 0;
	}
	pdu->securityName = strdup(session->securityName);
	if (pdu->securityName == NULL) {
	  snmp_errno = SNMPERR_GENERR;
	  session->s_snmp_errno = SNMPERR_GENERR;
	  return 0;
	}
	pdu->securityNameLen = session->securityNameLen;
      }
      if (pdu->securityLevel == 0) {
	if (session->securityLevel == 0) {
	    snmp_errno = SNMPERR_BAD_SEC_LEVEL;
	    session->s_snmp_errno = SNMPERR_BAD_SEC_LEVEL;
	    return 0;
	}
	pdu->securityLevel = session->securityLevel;
      }
      DEBUGP("Building SNMPv3 message (secName:%s, secLevel:%s)...\n", session->securityName, usmSecLevelName[pdu->securityLevel]);
      break;

    case SNMP_VERSION_sec:
    case SNMP_VERSION_2u:
    case SNMP_VERSION_2star:
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
	printf("\nSending %d bytes to %s:%hu\n", length,
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

void snmp_free_varbind(var)
    struct variable_list *var;
{
  struct variable_list *ptr;
  while(var) {
    if (var->name) free((char *)var->name);
    if (var->val.string) free((char *)var->val.string);
    ptr = var->next_variable;
    free((char *)var);
    var = ptr;
  }
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
	if (vp->name && vp->name != vp->name_loc)
	    free((char *)vp->name);
	if (vp->val.string && vp->val.string != vp->buf)
	    free((char *)vp->val.string);
	ovp = vp;
	vp = vp->next_variable;
	free((char *)ovp);
    }
    if (pdu->enterprise) free((char *)pdu->enterprise);
    if (pdu->community) free((char *)pdu->community);
    if (pdu->contextEngineID) free((char*)pdu->contextEngineID);
    if (pdu->contextName) free((char*)pdu->contextName);
    if (pdu->securityName) free((char*)pdu->securityName);
    if (pdu->srcParty && pdu->srcParty != pdu->srcPartyBuf) 
      free((char *)pdu->srcParty);
    if (pdu->dstParty && pdu->dstParty != pdu->dstPartyBuf) 
      free((char *)pdu->dstParty);
    if (pdu->context && pdu->context != pdu->contextBuf) 
      free((char *)pdu->context);
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
	    snmp_sess_read((void *)slp, fdset);
    }
}

/* Same as snmp_read, but works just one session. */
void
snmp_sess_read(sessp, fdset)
    void *sessp;
    fd_set  *fdset;
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
    int rpt_type;

    if (!(FD_ISSET(slp->internal->sd, fdset)))
        return;

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
	printf("\nReceived %d bytes from %s:%hu\n", length,
	       inet_ntoa(from.sin_addr), ntohs(from.sin_port));
	xdump(packet, length, "");
                printf("\n");
    }

    pdu = (struct snmp_pdu *)malloc(sizeof(struct snmp_pdu));
    memset (pdu, 0, sizeof(*pdu));
    pdu->address = from;

    if (snmp_parse(sp, pdu, packet, length) != SNMP_ERR_NOERROR){
	snmp_free_pdu(pdu);
	return;
    }

    if (pdu->command == SNMP_MSG_RESPONSE || pdu->command == SNMP_MSG_REPORT) {
	/* call USM to free any securityStateRef supplied with the message */
	if (pdu->securityStateRef) {
	  usm_free_usmStateReference(pdu->securityStateRef);
	  pdu->securityStateRef = NULL;
	}
	for(rp = isp->requests; rp; rp = rp->next_request){
	    if (rp->request_id == pdu->reqid){
		callback = sp->callback;
		magic = sp->callback_magic;
		if (rp->callback) callback = rp->callback;
		if (rp->cb_data) magic = rp->cb_data;
	        if (callback == NULL || 
		    callback(RECEIVED_MESSAGE,sp,pdu->reqid,pdu,magic) == 1){
		  if (pdu->command == SNMP_MSG_REPORT) {
		    if (sp->s_snmp_errno == SNMPERR_NOT_IN_TIME_WINDOW) {
		      /* trigger immediate retry on recoverable Reports 
		       * (notInTimeWindow), incr_retries == TRUE to prevent
		       * inifinite resend 		       */
		      if (rp->retries <= sp->retries) {
			snmp_resend_request(slp, rp, TRUE);
		        break;
		      }
		    } else {
		      if (SNMPV3_IGNORE_UNAUTH_REPORTS) break;
		    }
		    /* handle engineID discovery - */
		    if (!sp->contextEngineIDLen && pdu->contextEngineIDLen) {
		      sp->contextEngineID = malloc(pdu->contextEngineIDLen);
		      memcpy(sp->contextEngineID, pdu->contextEngineID,
			     pdu->contextEngineIDLen);
		      sp->contextEngineIDLen = pdu->contextEngineIDLen;
		    }
		  }
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
    /* call USM to free any securityStateRef supplied with the message */
    if (pdu->securityStateRef && pdu->command == SNMP_MSG_TRAP2) {
      usm_free_usmStateReference(pdu->securityStateRef);
      pdu->securityStateRef = NULL;
    }
    snmp_free_pdu(pdu);
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

static int
snmp_resend_request(struct session_list *slp, struct request_list *rp, 
		    int incr_retries)
{
  u_char  packet[PACKET_LENGTH];
  int length = PACKET_LENGTH;
  struct timeval tv;
  struct snmp_session *sp;
  struct snmp_internal_session *isp;
  struct timeval now;

  sp = slp->session; isp = slp->internal;

  if (incr_retries) rp->retries++;

  /* retransmit this pdu */
  if (snmp_build(sp, rp->pdu, packet, &length) < 0){
    /* this should never happen */
    return -1;
  }
  if (snmp_dump_packet){
    printf("\nResending %d bytes to %s:%hu\n", length,
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
    return -1;
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
  return 0;
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
	  if (snmp_resend_request(slp, rp, TRUE)) break;
    	}
        }
        orp = rp;
    }
    if (freeme != NULL){
        free((char *)freeme);
        freeme = NULL;
    }
}


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
DEBUGPOID(theoid, len)
  oid *theoid;
  int len;
{
  char c_oid[4096];
  sprint_objid(c_oid,theoid,len);
  DEBUGP(c_oid);
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

int
snmp_oid_compare(name1, len1, name2, len2)
    register oid	    *name1, *name2;
    register int	    len1, len2;
{
    register int    len;

    /* len = minimum of len1 and len2 */
    if (len1 < len2)
	len = len1;
    else
	len = len2;
    /* find first non-matching byte */
    while(len-- > 0){
	if (*name1 < *name2)
	    return -1;
	if (*name2++ < *name1++)
	    return 1;
    }
    /* bytes match up to length of shorter string */
    if (len1 < len2)
	return -1;  /* name1 shorter, so it is "less" */
    if (len2 < len1)
	return 1;
    return 0;	/* both strings are equal */
}

/*
 * Add a variable with the requested name to the end of the list of
 * variables for this pdu.
 */
void
snmp_pdu_add_variable(pdu, name, name_length, type, value, len)
    struct snmp_pdu *pdu;
    oid *name;
    int name_length;
    u_char type;
    u_char *value;
    int len;
{
    struct variable_list *vars;

    if (pdu->variables == NULL){
      pdu->variables = vars =
            (struct variable_list *)malloc(sizeof(struct variable_list));
    } else {
      for(vars = pdu->variables;
            vars->next_variable;
            vars = vars->next_variable)
        ;

      vars->next_variable =
            (struct variable_list *)malloc(sizeof(struct variable_list));
      vars = vars->next_variable;
    }

    vars->next_variable = NULL;
    vars->name = (oid *)malloc(name_length * sizeof(oid));
    memmove(vars->name, name, name_length * sizeof(oid));
    vars->name_length = name_length;

    vars->type = type;
    vars->val_len = len;
    switch(type){
      case ASN_INTEGER:
      case ASN_UNSIGNED:
      case ASN_TIMETICKS:
      case ASN_IPADDRESS:
      case ASN_COUNTER:
        vars->val.integer = (long *)malloc(sizeof(long));
        memmove(vars->val.integer, value, vars->val_len);
        vars->val_len = sizeof(long);
        break;

      case ASN_OBJECT_ID:
        vars->val.objid = (oid *)malloc(vars->val_len);
        memmove(vars->val.objid, value, vars->val_len);
        break;

      case ASN_OCTET_STR:
        vars->val.string = (u_char *)malloc(vars->val_len);
        memmove(vars->val.string, value, vars->val_len);
        break;

      case ASN_NULL:
        vars->val_len = 0;
        vars->val.string = NULL;
        break;

#ifdef OPAQUE_SPECIAL_TYPES
      case ASN_OPAQUE_U64:
      case ASN_OPAQUE_I64:
        vars->val.counter64 =
          (struct counter64 *) malloc(sizeof(struct counter64));
        memmove(vars->val.counter64, value, vars->val_len);
        break;

      case ASN_OPAQUE_FLOAT:
        vars->val.floatVal = (float *) malloc(sizeof(float));
        memmove(vars->val.floatVal, value, vars->val_len);
        break;

      case ASN_OPAQUE_DOUBLE:
        vars->val.doubleVal = (double *) malloc(sizeof(double));
        memmove(vars->val.doubleVal, value, vars->val_len);

#endif /* OPAQUE_SPECIAL_TYPES */

      default:
        snmp_set_detail("Internal error in type switching\n");
        snmp_errno = SNMPERR_BAD_PARSE; /* XX SNMP_BAD_ENCODE */
        return;
    }
}

int
ascii_to_binary(cp, bufp)
    u_char  *cp;
    u_char *bufp;
{
    int  subidentifier;
    u_char *bp = bufp;

    for(; *cp != '\0'; cp++){
      if (isspace(*cp) || *cp == '.')
        continue;
      if (!isdigit(*cp)){
        fprintf(stderr, "Input error\n");
        return -1;
      }
      subidentifier = atoi(cp);
      if (subidentifier > 255){
        fprintf(stderr, "subidentifier %d is too large ( > 255)\n",
                subidentifier);
        return -1;
      }
      *bp++ = (u_char)subidentifier;
      while(isdigit(*cp))
        cp++;
      cp--;
    }
    return bp - bufp;
}

int
hex_to_binary(str, bufp)
    u_char  *str;
    u_char *bufp;
{
  int len, itmp;
  if (!bufp) return -1;
  if (*str && *str == '0' && (*(str+1) == 'x' || *(str+1) == 'X')) str += 2;
  for (len = 0; *str; str++) {
    if (isspace(*str)) continue;
    if (!isxdigit(*str)) return -1;
    len++;
    sscanf(str++, "%2x", &itmp);
    *bufp++ = itmp;
    if (!*str) return -1; /* odd number of chars is an error */
  }
  return len;
}


/*
 * Add a variable with the requested name to the end of the list of
 * variables for this pdu.
 */
int
snmp_add_var(pdu, name, name_length, type, value)
    struct snmp_pdu *pdu;
    oid *name;
    int name_length;
    char type, *value;
{
    char buf[2048];
    int tint;
    long ltmp;
#ifdef OPAQUE_SPECIAL_TYPES
    double dtmp;
    float ftmp;
    struct counter64 c64tmp;
#endif /* OPAQUE_SPECIAL_TYPES */

    switch(type){
      case 'i':
        ltmp = atol(value);
        snmp_pdu_add_variable(pdu, name, name_length, ASN_INTEGER,
                              (u_char *) &ltmp, sizeof(ltmp));
        break;

      case 'u':
        sscanf(value, "%lu", &ltmp);
        snmp_pdu_add_variable(pdu, name, name_length, ASN_UNSIGNED,
                              (u_char *) &ltmp, sizeof(ltmp));
        break;

      case 't':
        sscanf(value, "%lu", &ltmp);
        snmp_pdu_add_variable(pdu, name, name_length, ASN_TIMETICKS,
                              (u_char *) &ltmp, sizeof(long));
        break;

      case 'a':
        ltmp = inet_addr(value);
        snmp_pdu_add_variable(pdu, name, name_length, ASN_IPADDRESS,
                              (u_char *) &ltmp, sizeof(long));
        break;

      case 'o':
        tint = sizeof(buf);
        read_objid(value, (oid *)buf, &tint);
        snmp_pdu_add_variable(pdu, name, name_length, ASN_OBJECT_ID, buf,
                              sizeof(oid)*tint);
        break;

      case 's':
      case 'x':
      case 'd':
        if (type == 'd'){
          tint = ascii_to_binary((u_char *)value, buf);
        } else if (type == 's'){
          strcpy(buf, value);
          tint = strlen(buf);
        } else if (type == 'x'){
          tint = hex_to_binary((u_char *)value, buf);
        }
        if (tint < 0) {
          sprintf(buf, "Bad value: %s\n", value);
          snmp_set_detail(buf);
          return 1;
        }
        snmp_pdu_add_variable(pdu, name, name_length, ASN_OCTET_STR, buf, tint);
        break;

      case 'n':
        snmp_pdu_add_variable(pdu, name, name_length, ASN_NULL, 0, 0);
        break;

#ifdef OPAQUE_SPECIAL_TYPES
      case 'U':
        read64(&c64tmp, value);
        snmp_pdu_add_variable(pdu, name, name_length, ASN_OPAQUE_U64,
                              (u_char *) &c64tmp, sizeof(c64tmp));
        break;

      case 'I':
        read64(&c64tmp, value);
        snmp_pdu_add_variable(pdu, name, name_length, ASN_OPAQUE_I64,
                              (u_char *) &c64tmp, sizeof(c64tmp));
        break;

      case 'F':
        ftmp = (float) atof(value);
        snmp_pdu_add_variable(pdu, name, name_length, ASN_OPAQUE_FLOAT, 
                              (u_char *) &ftmp, sizeof(ftmp));
        break;

      case 'D':
        dtmp = atof(value);
        snmp_pdu_add_variable(pdu, name, name_length, ASN_OPAQUE_DOUBLE,
                              (u_char *) &dtmp, sizeof(dtmp));
        break;
#endif /* OPAQUE_SPECIAL_TYPES */

      default:
        snmp_set_detail("Internal error in type switching\n");
        return 1;
    }
    return 0;
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

/* snmp_duplicate_objid: duplicates (mallocs) an objid based on the
   input objid */
oid *
snmp_duplicate_objid(oid *objToCopy, int objToCopyLen)
{
  oid *returnOid;
  returnOid = (oid *) malloc(objToCopyLen*sizeof(oid));
  if (returnOid) {
    memmove(returnOid, objToCopy, objToCopyLen*sizeof(oid));
  }
  return returnOid;
}

/* generic statistics counter functions */
static u_int statistics[MAX_STATS];

u_int
snmp_increment_statistic(int which)
{
  if (which >= 0 && which <= MAX_STATS) {
    statistics[which]++;
    return statistics[which];
  }
  return 0;
}

u_int
snmp_increment_statistic_by(int which, int count)
{
  if (which >= 0 && which <= MAX_STATS) {
    statistics[which] += count;
    return statistics[which];
  }
  return 0;
}

u_int
snmp_get_statistic(int which)
{
  if (which >= 0 && which <= MAX_STATS)
    return statistics[which];
  return 0;
}

void
snmp_init_statistics(void)
{
  memset(statistics, 0, sizeof(statistics));
}

