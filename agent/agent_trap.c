/* agent_trap.c: define trap generation routines for mib modules, etc,
   to use */

#include <config.h>

#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "snmp.h"
#include "system.h"
#include "read_config.h"
#include "snmp_debug.h"

struct trap_sink {
    struct snmp_session	 ses;
    struct snmp_session	*sesp;
    struct trap_sink	*next;
};

struct trap_sink *sinks	  = NULL;
struct trap_sink *v2sinks = NULL;

extern struct timeval	starttime;

static oid objid_enterprisetrap[] = { EXTENSIBLEMIB, 251, 0, 0 };
static int length_enterprisetrap  =
	sizeof(objid_enterprisetrap)/sizeof(objid_enterprisetrap[0]);
oid version_id[]	 = { EXTENSIBLEMIB, AGENTID, OSTYPE };
int version_id_len	 = sizeof(version_id)/sizeof(version_id[0]);



#define SNMP_AUTHENTICATED_TRAPS_ENABLED	1
#define SNMP_AUTHENTICATED_TRAPS_DISABLED	2

int	 snmp_enableauthentraps	= SNMP_AUTHENTICATED_TRAPS_DISABLED;
char	*snmp_trapcommunity	= NULL;

/* Prototypes */
static int create_v1_trap_session (const char *, const char *);
static int create_v2_trap_session (const char *, const char *);
static void free_v1_trap_session (struct trap_sink *sp);
static void free_v2_trap_session (struct trap_sink *sp);
static void send_v1_trap (struct snmp_session *, int, int);
static void send_v2_trap (struct snmp_session *, int, int, int);

static int create_v1_trap_session (const char *sink, 
				   const char *com)
{
    struct trap_sink *new_sink =
      (struct trap_sink *) malloc (sizeof (*new_sink));

    memset (&new_sink->ses, 0, sizeof (struct snmp_session));
    new_sink->ses.peername = strdup(sink);
    new_sink->ses.version = SNMP_VERSION_1;
    if (com) {
        new_sink->ses.community = (u_char *)strdup (com);
        new_sink->ses.community_len = strlen (com);
    }
    new_sink->ses.remote_port = SNMP_TRAP_PORT;
    new_sink->sesp = snmp_open (&new_sink->ses);
    if (new_sink->sesp) {
	new_sink->next = sinks;
	sinks = new_sink;
	return 1;
    }
    snmp_sess_perror("snmpd: create_v1_trap", &new_sink->ses);
    free(new_sink);
    return 0;
}

static void free_v1_trap_session (struct trap_sink *sp)
{
    snmp_close(sp->sesp);
    if (sp->ses.community) free(sp->ses.community);
    free (sp);
}

static int create_v2_trap_session (const char *sink, 
				   const char *com)
{
    struct trap_sink *new_sink =
      (struct trap_sink *) malloc (sizeof (*new_sink));

    memset (&new_sink->ses, 0, sizeof (struct snmp_session));
    new_sink->ses.peername = strdup(sink);
    new_sink->ses.version = SNMP_VERSION_2c;
    if (com) {
        new_sink->ses.community = (u_char *)strdup (com);
        new_sink->ses.community_len = strlen (com);
    }
    new_sink->ses.remote_port = SNMP_TRAP_PORT;
    new_sink->sesp = snmp_open (&new_sink->ses);
    if (new_sink->sesp) {
	new_sink->next = sinks;
	sinks = new_sink;
	return 1;
    }
    snmp_sess_perror("snmpd: create_v2_trap", &new_sink->ses);
    free(new_sink);
    return 0;
}

static void free_v2_trap_session (struct trap_sink *sp)
{
    snmp_close(sp->sesp);
    if (sp->ses.community) free(sp->ses.community);
    free (sp);
}

void snmpd_free_trapsinks (void)
{
    struct trap_sink *sp = sinks;
    while (sp) {
	sinks = sinks->next;
	switch (sp->ses.version) {
	case SNMP_VERSION_1:
	    free_v1_trap_session(sp);
	    break;
	case SNMP_VERSION_2c:
	    free_v2_trap_session(sp);
	    break;
	}
	sp = sinks;
    }
}

static void send_v1_trap (struct snmp_session *ss,
			  int trap, 
			  int specific)
{
    struct snmp_pdu *pdu;
    struct timeval now;
    struct sockaddr_in *pduIp;

    gettimeofday(&now, NULL);

    pdu = snmp_pdu_create (SNMP_MSG_TRAP);
    pduIp = (struct sockaddr_in *)&pdu->agent_addr;

    if (trap == SNMP_TRAP_ENTERPRISESPECIFIC) {
	pdu->enterprise		 = (oid *)malloc(sizeof(objid_enterprisetrap));
	memcpy (pdu->enterprise, objid_enterprisetrap, sizeof(objid_enterprisetrap));
	pdu->enterprise_length	 = length_enterprisetrap-2;

    } else { 
	pdu->enterprise		 = (oid *)malloc(sizeof(version_id));
	memcpy (pdu->enterprise, version_id, sizeof(version_id));
	pdu->enterprise_length	 = version_id_len;
    }
    pduIp->sin_family		 = AF_INET;
    pduIp->sin_addr.s_addr	 = get_myaddr();
    pdu->trap_type		 = trap;
    pdu->specific_type		 = specific;
    pdu->time		 	 = calculate_time_diff(&now, &starttime);

    if (snmp_send (ss, pdu) == 0) {
        snmp_sess_perror ("snmpd: send_v1_trap", ss);
        snmp_free_pdu(pdu);
    }

    snmp_increment_statistic(STAT_SNMPOUTTRAPS);
}

/*******************************************************************-o-******
 * send_v2_trap
 *
 * Parameters:
 *	*ss		Pointer to an open session.
 *	 trap		Trap type.
 *	 specific	Specific trap type (when trap is
 *			  SNMP_TRAP_ENTERPRISESPECIFIC).
 *	 type		PDU type.
 */
static void send_v2_trap (struct snmp_session *ss,
			  int trap, 
			  int specific, 
			  int type)
{
    struct snmp_pdu *pdu;
    struct variable_list *var;
    struct timeval now;
    static oid objid_sysuptime[] = {1, 3, 6, 1, 2, 1, 1, 3, 0};
    static const size_t objid_sysuptime_len =
	sizeof(objid_sysuptime) / sizeof(objid_sysuptime[0]);
    static oid objid_snmptrap[]  = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    static const size_t objid_snmptrap_len =
	sizeof(objid_snmptrap) / sizeof(objid_snmptrap[0]);
    static oid objid_trapoid[]   = {1, 3, 6, 1, 6, 3, 1, 1, 5, 1};
    static const size_t objid_trapoid_len =
	sizeof(objid_trapoid) / sizeof(objid_trapoid[0]);

    gettimeofday(&now, NULL);

    pdu = snmp_pdu_create (type);


    /*
     * Create var-bind for sysUpTime.0
     */
    pdu->variables	 = var
			 = (struct variable_list *)
					malloc(sizeof(struct variable_list));
    var->next_variable	 = NULL;

    var->name		 = (oid *)malloc(sizeof(objid_sysuptime));
    memcpy (var->name, objid_sysuptime, sizeof(objid_sysuptime));
    var->name_length	 = objid_sysuptime_len;
    var->type		 = ASN_TIMETICKS;
    var->val.integer	 = (long *)malloc(sizeof(long));
    *var->val.integer	 = calculate_time_diff(&now, &starttime);
    var->val_len	 = sizeof(long);

    /*
     * Allocate space for another var-bind to contain the trap data.
     */
    var->next_variable	 = (struct variable_list *)
					malloc(sizeof(struct variable_list));
    var		 	 = var->next_variable;
    var->next_variable	 = NULL;

    if (trap == SNMP_TRAP_ENTERPRISESPECIFIC) {
	var->name	 = (oid *)malloc(sizeof(objid_snmptrap));
	var->name_length = objid_snmptrap_len;
	memcpy(var->name, objid_snmptrap, sizeof(objid_snmptrap));
	var->type	 = ASN_OBJECT_ID;
	var->val.objid	 = (oid *)malloc(sizeof(objid_enterprisetrap));
	var->val_len	 = sizeof(objid_enterprisetrap);
	memcpy(var->val.objid,
		objid_enterprisetrap, sizeof(objid_enterprisetrap));
	var->val.objid[length_enterprisetrap-1] = specific;
    } else {
	var->name	 = (oid *)malloc(sizeof(objid_snmptrap));
	var->name_length = objid_snmptrap_len;
	memcpy(var->name, objid_snmptrap, sizeof(objid_snmptrap));
	var->type	 = ASN_OBJECT_ID;
	var->val.objid	 = (oid *)malloc(sizeof(objid_trapoid));
	var->val_len	 = sizeof(objid_trapoid);
	memcpy(var->val.objid, objid_trapoid, sizeof(objid_trapoid));
	var->val.objid[9] = trap+1;
    }

    if (snmp_send (ss, pdu) == 0) {
        snmp_sess_perror ("snmpd: send_v2_trap", ss);
        snmp_free_pdu(pdu);
    }

    snmp_increment_statistic(STAT_SNMPOUTTRAPS);

}  /* end send_v2_trap() */

void
send_trap_pdu(struct snmp_pdu *pdu)
{
  struct snmp_pdu *mypdu;
  
  struct trap_sink *sink = sinks;

  if ((snmp_enableauthentraps == SNMP_AUTHENTICATED_TRAPS_ENABLED)
      && (sink != NULL)) {
    while (sink) {
      if (sink->ses.version == SNMP_VERSION_2c) {
        DEBUGMSGTL(("snmpd", " found v2 session...\n"));
        mypdu = snmp_clone_pdu(pdu);
        if (snmp_send(sink->sesp, mypdu) == 0) {
          snmp_sess_perror ("snmpd: send_trap_pdu", sink->sesp);
          snmp_free_pdu(mypdu);
        }
        snmp_increment_statistic(STAT_SNMPOUTTRAPS);
      }
      sink = sink->next;
    }
    DEBUGMSGTL(("snmpd", "  done\n"));
  }
}  /* end send_trap_pdu() */

void send_easy_trap (int trap, 
		     int specific)
/*
 * FIX  Need case for v3? 
 */
{
    struct trap_sink *sink = sinks;

    if ( ((snmp_enableauthentraps == SNMP_AUTHENTICATED_TRAPS_ENABLED)
		|| (trap != SNMP_TRAP_AUTHFAIL))
			&& (sink != NULL) )
    {
	while (sink) {
	    switch (sink->ses.version) {
	    case SNMP_VERSION_1:
		    send_v1_trap (sink->sesp, trap, specific);
		    break;
	    case SNMP_VERSION_2c:
		    send_v2_trap (sink->sesp, trap, specific, SNMP_MSG_TRAP2);
		    /*
		       send_v2_trap (sink->sesp, trap, specific, SNMP_MSG_INFORM);
		     */
		    break;
	    }
	    sink = sink->next;
	}
    }
}

void snmpd_parse_config_authtrap(char *token, 
				 char *cptr)
{
    int i;

    i = atoi(cptr);
    if (i < 1 || i > 2)
	config_perror("authtrapenable must be 1 or 2");
    else
	snmp_enableauthentraps = i;
}

void snmpd_parse_config_trapsink(char *token, 
				 char *cptr)
{
    char tmpbuf[1024];
    char *sp, *cp;
  
    if (!snmp_trapcommunity) snmp_trapcommunity = strdup("public");
    sp = strtok(cptr, " \t\n");
    cp = strtok(NULL, " \t\n");
    if (create_v1_trap_session(sp, cp ? cp : snmp_trapcommunity) == 0) {
	sprintf(tmpbuf,"cannot create trapsink: %s", cptr);
	config_perror(tmpbuf);
    }
}


void
snmpd_parse_config_trap2sink(char *word, char *cptr)
{
    char tmpbuf[1024];
    char *sp, *cp;
  
    if (!snmp_trapcommunity) snmp_trapcommunity = strdup("public");
    sp = strtok(cptr, " \t\n");
    cp = strtok(NULL, " \t\n");
    if (create_v2_trap_session(sp, cp ? cp : snmp_trapcommunity) == 0) {
	sprintf(tmpbuf,"cannot create trap2sink: %s", cptr);
	config_perror(tmpbuf);
    }
}

void
snmpd_parse_config_trapcommunity(char *word, char *cptr)
{
    if (snmp_trapcommunity) free(snmp_trapcommunity);
    snmp_trapcommunity = malloc (strlen(cptr));
    copy_word(cptr, snmp_trapcommunity);
}

void snmpd_free_trapcommunity (void)
{
    if (snmp_trapcommunity) {
	free(snmp_trapcommunity);
	snmp_trapcommunity = NULL;
    }
}
