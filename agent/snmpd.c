/*
 * snmpd.c - rrespond to SNMP queries from management stations
 *
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
#include <config.h>

#include <stdio.h>
#include <errno.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
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
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_NET_IF_H
#include <net/if.h>
#endif
#if HAVE_INET_MIB2_H
#include <inet/mib2.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#if HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <sys/wait.h>
#include <signal.h>

#ifndef FD_SET
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
typedef long    fd_mask;
#define NFDBITS (sizeof(fd_mask) * NBBY)        /* bits per mask */
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      memset((p), 0, sizeof(*(p)))
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "system.h"
#include "read_config.h"
#include "snmp.h"
#include "mib.h"
#include "m2m.h"
#include "snmp_vars.h"
#include "agent_read_config.h"
#include "snmpv3.h"
#include "callback.h"
#include "snmp_alarm.h"
#include "mib_module_config.h"
#ifdef USING_SNMPV3_USMUSER_MODULE 
#include "mibgroup/snmpv3/usmUser.h"
#endif

#include "snmp_client.h"
#include "snmpd.h"
#include "var_struct.h"
#include "mibgroup/struct.h"
#include "mibgroup/util_funcs.h"
#include "snmp_debug.h"

#include "snmpusm.h"
#include "tools.h"
#include "lcd_time.h"

#include "transform_oids.h"

#include "snmp_agent.h"
#include "agent_read_config.h"
#include "../snmplib/snmp_logging.h"

#include "version.h"

#include "mib_module_includes.h"

/*
 * Globals.
 */
#ifdef USE_LIBWRAP
#include <tcpd.h>

int allow_severity	 = LOG_INFO;
int deny_severity	 = LOG_WARNING;
#endif  /* USE_LIBWRAP */

int   agent_role;

#define TIMETICK         500000L
#define ONE_SEC         1000000L

struct timeval	starttime;
int 		log_addresses	 = 0;
int 		verbose		 = 0;
int 		snmp_dump_packet;
int             running          = 1;
int		reconfig	 = 0;

oid version_id[]	 = { EXTENSIBLEMIB, AGENTID, OSTYPE };
int version_id_len	 = sizeof(version_id)/sizeof(version_id[0]);

static oid objid_enterprisetrap[] = { EXTENSIBLEMIB, 251, 0, 0 };
static int length_enterprisetrap  =
	sizeof(objid_enterprisetrap)/sizeof(objid_enterprisetrap[0]);


struct addrCache {
    in_addr_t	addr;
    int		status;
#define UNUSED	0
#define USED	1
#define OLD	2
};

#define ADDRCACHE 10

static struct addrCache	addrCache[ADDRCACHE];
static int		lastAddrAge = 0;


struct trap_sink {
    struct snmp_session	 ses;
    struct snmp_session	*sesp;
    struct trap_sink	*next;
};

struct trap_sink *sinks	  = NULL;
struct trap_sink *v2sinks = NULL;


#define SNMP_AUTHENTICATED_TRAPS_ENABLED	1
#define SNMP_AUTHENTICATED_TRAPS_DISABLED	2

int	 snmp_enableauthentraps	= SNMP_AUTHENTICATED_TRAPS_DISABLED;
char	*snmp_trapcommunity	= NULL;



char **argvrestartp;
char  *argvrestart;
char  *argvrestartname;

extern char *optconfigfile;
extern char  dontReadConfigFiles;


#define NUM_SOCKETS	32

#ifdef USING_SD_HANDLERS
static int	  sdlist[NUM_SOCKETS],
		  sdlen = 0;
static int	  portlist[NUM_SOCKETS];
int		(*sd_handlers[NUM_SOCKETS]) (int);
#endif

/*
 * Prototypes.
 */
int snmp_read_packet (int);
int snmp_input (int, struct snmp_session *, int, struct snmp_pdu *, void *);
static char *sprintf_stamp (time_t *);
static int create_v1_trap_session (const char *, const char *);
static int create_v2_trap_session (const char *, const char *);
static void free_v1_trap_session (struct trap_sink *sp);
static void free_v2_trap_session (struct trap_sink *sp);
static void send_v1_trap (struct snmp_session *, int, int);
static void send_v2_trap (struct snmp_session *, int, int, int);
static void usage (char *);
int main (int, char **);
static void SnmpTrapNodeDown (void);
static int receive(void);
int snmp_check_packet(struct snmp_session*, snmp_ipaddr);
int snmp_check_parse(struct snmp_session*, struct snmp_pdu*, int);

static char *
sprintf_stamp (time_t *now)
{
    time_t Now;
    struct tm *tm;
    static char sbuf [32];

    if (now == NULL) {
	now = &Now;
	time (now);
    }
    tm = localtime (now);
    sprintf(sbuf, "%.4d-%.2d-%.2d %.2d:%.2d:%.2d",
	    tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
	    tm->tm_hour, tm->tm_min, tm->tm_sec);
    return sbuf;
}


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
    pduIp = (struct sockaddr_in *)&(pdu->address);

    if (trap == SNMP_TRAP_ENTERPRISESPECIFIC) {
	pdu->enterprise		 = objid_enterprisetrap;
	pdu->enterprise_length	 = length_enterprisetrap-2;

    } else { 
	pdu->enterprise		 = version_id;
	pdu->enterprise_length	 = version_id_len;
    }
    pduIp->sin_addr.s_addr	  = get_myaddr();
    pdu->trap_type		 = trap;
    pdu->specific_type		 = specific;
    pdu->time		 	 = calculate_time_diff(&now, &starttime);

    if (snmp_send (ss, pdu) == 0) {
        snmp_sess_perror ("snmpd: send_v1_trap", ss);
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
    static oid objid_snmptrap[]  = {1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0};
    static oid objid_trapoid[]   = {1, 3, 6, 1, 6, 3, 1, 1, 5, 1};


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
    var->name_length	 = sizeof(objid_sysuptime)/sizeof(objid_sysuptime[0]);

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
	objid_enterprisetrap[length_enterprisetrap-1] = specific;

	var->name		 = (oid *)malloc(sizeof(objid_snmptrap));
	var->name_length	 = length_enterprisetrap;
	memcpy(var->name, objid_snmptrap, sizeof(objid_snmptrap));
	var->type		 = ASN_OBJECT_ID;
	var->val.objid		 = (oid *)malloc(sizeof(objid_enterprisetrap));
	var->val_len		 = sizeof(objid_enterprisetrap);
	memcpy(var->val.objid,
		objid_enterprisetrap, sizeof(objid_enterprisetrap));

    } else {
	objid_trapoid[9] = trap+1;

	var->name	 = (oid *)malloc(sizeof(objid_snmptrap));
	var->name_length = sizeof(objid_snmptrap)/sizeof(objid_snmptrap[0]);
	memcpy(var->name, objid_snmptrap, sizeof(objid_snmptrap));
	var->type	 = ASN_OBJECT_ID;
	var->val.objid	 = (oid *)malloc(sizeof(objid_trapoid));
	var->val_len	 = sizeof(objid_trapoid);
	memcpy(var->val.objid, objid_trapoid, sizeof(objid_trapoid));
    }

    if (snmp_send (ss, pdu) == 0) {
        snmp_sess_perror ("snmpd: send_v2_trap", ss);
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
  
static void usage(char *prog)
{
  printf("\nUsage:  %s [-h] [-v] [-f] [-a] [-d] [-V] [-P PIDFILE] [-q] [-D] [-p NUM] [-L] [-l LOGFILE]",prog);
#if HAVE_UNISTD_H
  printf(" [-u uid] [-g gid]");
#endif
  printf("\n");
  printf("\n\tVersion:  %s\n",VersionInfo);
  printf("\tAuthor:   Wes Hardaker\n");
  printf("\tEmail:    ucd-snmp-coders@ucd-snmp.ucdavis.edu\n");
  printf("\n-h\t\tThis usage message.\n");
  printf("-H\t\tDisplay configuration file directives understood.\n");
  printf("-v\t\tVersion information.\n");
  printf("-f\t\tDon't fork from the shell.\n");
  printf("-a\t\tLog addresses.\n");
  printf("-d\t\tDump sent and received UDP SNMP packets\n");
  printf("-V\t\tVerbose display\n");
  printf("-P PIDFILE\tUse PIDFILE to store process id\n");
  printf("-q\t\tPrint information in a more parsable format (quick-print)\n");
  printf("-D\t\tTurn on debugging output\n");
  printf("-p NUM\t\tRun on port NUM instead of the default:  161\n");
  printf("-c CONFFILE\tRead CONFFILE as a configuration file.\n");
  printf("-C\t\tDon't read the default configuration files.\n");
  printf("-L\t\tPrint warnings/messages to stdout/err\n");
  printf("-s\t\tLog warnings/messages to syslog\n");
  printf("-A\t\tAppend to the logfile rather than truncating it.\n");
  printf("-l LOGFILE\tPrint warnings/messages to LOGFILE\n");
  printf("\t\t(By default LOGFILE=%s)\n",
#ifdef LOGFILE
         LOGFILE
#else
    "none"
#endif
    );
#if HAVE_UNISTD_H
  printf("-g \t\tChange to this gid after opening port\n");
  printf("-u \t\tChange to this uid after opening port\n");
#endif
  printf("\n");
  exit(1);
}

RETSIGTYPE
SnmpdShutDown(int a)
{
  running = 0;
}

#ifdef SIGHUP
RETSIGTYPE
SnmpdReconfig(int a)
{
  reconfig = 1;
  signal(SIGHUP, SnmpdReconfig);
}
#endif

static void
SnmpTrapNodeDown(void)
{
    send_easy_trap (SNMP_TRAP_ENTERPRISESPECIFIC, 2);
    /* XXX  2 - Node Down #define it as NODE_DOWN_TRAP */
}

void
init_master_agent(int dest_port)
{
    struct snmp_session
                        sess,
                       *session=&sess;

    if ( agent_role != MASTER_AGENT )
	return;

    /* set up a fake session for incoming requests that opens a port
     * that we listen to. */

    snmp_sess_init(session);
    
    session->version = SNMP_DEFAULT_VERSION;
    session->peername = SNMP_DEFAULT_PEERNAME;
    session->community_len = SNMP_DEFAULT_COMMUNITY_LEN;
     
    session->local_port = dest_port;
    session->callback = handle_snmp_packet;
    session->authenticator = NULL;
    session = snmp_open( session );

    if ( session == NULL ) {
	snmp_sess_perror("init_master_agent", &sess);
	/*return;*/
	exit(1);
    }

    set_pre_parse( session, snmp_check_packet );
    set_post_parse( session, snmp_check_parse );
}

/*******************************************************************-o-******
 * main
 *
 * Parameters:
 *	 argc
 *	*argv[]
 *      
 * Returns:
 *	0	Always succeeds.  (?)
 *
 *
 * Setup and start the agent daemon.
 *
 * Also successfully EXITs with zero for some options.
 */
int
main(int argc, char *argv[])
{
	int             arg, i;
	int             ret;
	u_short         dest_port = SNMP_PORT;
	int             dont_fork = 0;
	char            logfile[SNMP_MAXBUF_SMALL];
	char           *cptr, **argvptr;
        struct usmUser *user, *userListPtr;
        char           *pid_file = NULL;
        FILE           *PID;
        int             dont_zero_log = 0;
        int             stderr_log=0, syslog_log=0;
        int             uid=0, gid=0;

	logfile[0]		= 0;
	optconfigfile		= NULL;
	dontReadConfigFiles	= 0;

#ifdef LOGFILE
	strcpy(logfile, LOGFILE);
#endif


	/*
	 * usage: snmpd
	 */
	for (arg = 1; arg < argc; arg++)
          {
            if (argv[arg][0] == '-') {
              switch (argv[arg][1]) {

                case 'c':
                  if (++arg == argc)
                    usage(argv[0]);
                  optconfigfile = strdup(argv[arg]);
                  break;

                case 'C':
                    dontReadConfigFiles = 1;
                    break;

		case 'd':
                    snmp_set_dump_packet(++snmp_dump_packet);
		    verbose = 1;
		    break;

		case 'q':
		    snmp_set_quick_print(1);
		    break;

		case 'D':
                    debug_register_tokens(&argv[arg][2]);
		    snmp_set_do_debugging(1);
		    break;

                case 'p':
                  if (++arg == argc)
                    usage(argv[0]);
                  dest_port = atoi(argv[arg]);
                  if (dest_port <= 0)
                    usage(argv[0]);
                  break;

                case 'P':
                  if (++arg == argc)
                    usage(argv[0]);
                  pid_file = argv[arg];

                case 'a':
                      log_addresses++;
                  break;

                case 'V':
                  verbose = 1;
                  break;

                case 'f':
                  dont_fork = 1;
                  break;

                case 'l':
                  if (++arg == argc)
                    usage(argv[0]);
                  strcpy(logfile, argv[arg]);
                  break;

                case 'L':
		    stderr_log=1;
                    break;
		case 's':
		    syslog_log=1;
		    break;
                case 'A':
                    dont_zero_log = 1;
                    break;
#if HAVE_UNISTD_H
		case 'u':
                    if (++arg == argc) usage(argv[0]);
                    uid = atoi(argv[arg]);
                    break;
		case 'g':
                    if (++arg == argc) usage(argv[0]);
                    gid = atoi(argv[arg]);
                    break;
#endif
                case 'h':
                    usage(argv[0]);
                    break;
                case 'H':
                    init_snmpv3("snmpd");
                    init_agent();            /* register our .conf handlers */
                    register_mib_handlers(); /* snmplib .conf handlers */
                    fprintf(stderr, "Configuration directives understood:\n");
                    enable_stderrlog();
                    read_config_print_usage("  ");
                    exit(0);
                case 'v':
                    printf("\nUCD-snmp version:  %s\n",VersionInfo);
                    printf("Author:            Wes Hardaker\n");
                    printf("Email:             ucd-snmp-coders@ucd-snmp.ucdavis.edu\n\n");
                    exit (0);
                case '-':
                  switch(argv[arg][2]){
                    case 'v': 
                      printf("\nUCD-snmp version:  %s\n",VersionInfo);
                      printf("Author:            Wes Hardaker\n");
                      printf("Email:             ucd-snmp-coders@ucd-snmp.ucdavis.edu\n\n");
                      exit (0);
                    case 'h':
                      usage(argv[0]);
                      exit(0);
                  }

                default:
                  printf("invalid option: %s\n", argv[arg]);
                  usage(argv[0]);
                  break;
              }
              continue;
            }
          }  /* end-for */


	/* 
	 * Initialize a argv set to the current for restarting the agent.
	 */
	argvrestartp = (char **) malloc((argc + 2) * sizeof(char *));
	argvptr = argvrestartp;
	for (i = 0, ret = 1; i < argc; i++) {
		ret += strlen(argv[i]) + 1;
	}
	argvrestart = (char *) malloc(ret);
	argvrestartname = (char *) malloc(strlen(argv[0]) + 1);
	strcpy(argvrestartname, argv[0]);
	if ( strstr(argvrestartname, "agentxd") != NULL)
	    agent_role = SUB_AGENT;
	else
	    agent_role = MASTER_AGENT;
	for (cptr = argvrestart, i = 0; i < argc; i++) {
		strcpy(cptr, argv[i]);
		*(argvptr++) = cptr;
		cptr += strlen(argv[i]) + 1;
	}
	*cptr = 0;
	*argvptr = NULL;


	/* 
	 * Open the logfile if necessary.
	 */

    /* Should open logfile and/or syslog based on arguments */
    if (logfile[0])
      enable_filelog(logfile, dont_zero_log);
    /* decide to not log stderr after init succeeds */
      enable_stderrlog();
    if (syslog_log)
      enable_syslog(); 
#ifdef BUFSIZ
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
#endif
    /* 
     * Initialize the world.  Detach from the shell.
     * Create initial user.
     */
    if (!dont_fork && fork() != 0) {
      exit(0);
    }

    if (pid_file != NULL) {
      if ((PID = fopen(pid_file, "w")) == NULL) {
        log_perror("fopen");
        exit(1);
      }
      fprintf(PID, "%d\n", (int)getpid());
      fclose(PID);
    }

    snmp_debug_init();
    init_master_agent( dest_port );

    usm_set_reportErrorOnUnknownID(1);
    init_agent();		/* register our .conf handlers */
    init_snmp_alarm();
    init_snmpv3("snmpd");	/* register the v3 handlers */
    register_mib_handlers();	/* snmplib .conf handlers */
    read_premib_configs();	/* read pre-mib-reading .conf handlers */

    /* create the initial and template users */
    user = usm_create_initial_user("initial", usmHMACMD5AuthProtocol,
                                   USM_LENGTH_OID_TRANSFORM,
                                   usmDESPrivProtocol,
                                   USM_LENGTH_OID_TRANSFORM);
    userListPtr = usm_add_user(user);
    if (userListPtr == NULL) /* user already existed */
      usm_free_user(user);
    user = usm_create_initial_user("templateMD5", usmHMACMD5AuthProtocol,
                                   USM_LENGTH_OID_TRANSFORM,
                                   usmDESPrivProtocol,
                                   USM_LENGTH_OID_TRANSFORM);
    userListPtr = usm_add_user(user);
    if (userListPtr == NULL) /* user already existed */
      usm_free_user(user);
    user = usm_create_initial_user("templateSHA", usmHMACSHA1AuthProtocol,
                                   USM_LENGTH_OID_TRANSFORM,
                                   usmDESPrivProtocol,
                                   USM_LENGTH_OID_TRANSFORM);
    userListPtr = usm_add_user(user);
    if (userListPtr == NULL) /* user already existed */
      usm_free_user(user);
    register_mib_handlers(); /* snmplib .conf handlers */
    read_premib_configs();   /* read pre-mib-reading .conf handlers */
    init_mib();              /* initialize the mib structures */
    update_config();         /* read in config files and register HUP */

    /* get current time (ie, the time the agent started) */
    gettimeofday(&starttime, NULL);
    starttime.tv_sec--;
    starttime.tv_usec += 1000000L;

    /* send coldstart trap via snmptrap(1) if possible */
    send_easy_trap (0, 0);
#ifdef SIGTERM
    signal(SIGTERM, SnmpdShutDown);
#endif
#ifdef SIGINT
    signal(SIGINT, SnmpdShutDown);
#endif
#ifdef SIGHUP
    signal(SIGHUP, SnmpdReconfig);
#endif
        
#if HAVE_UNISTD_H
    if (gid) {
      DEBUGMSGTL(("snmpd", "Changing gid to %d.\n", gid));
      if (setgid(gid)==-1) {
          log_perror("setgid failed: ");
          exit(1);
      }
    }
    if (uid) {
      DEBUGMSGTL(("snmpd", "Changing uid to %d.\n", uid));
      if(setuid(uid)==-1) {
          log_perror("setuid failed: ");
          exit(1);
      }
    }
#endif

    /* honor selection of standard error output */
    if (!stderr_log)
      disable_stderrlog();

    /* we're up, log our version number */
    snmp_log(LOG_INFO, "UCD-SNMP version %s\n", VersionInfo);

    memset(addrCache, 0, sizeof(addrCache));
    /* 
     * Forever monitor the dest_port for incoming PDUs.
     */
    DEBUGMSGTL(("snmpd", "We're up.  Starting to process data.\n"));
    receive();
#include "mib_module_shutdown.h"
    DEBUGMSGTL(("snmpd", "sending shutdown trap\n"));
    SnmpTrapNodeDown();
    DEBUGMSGTL(("snmpd", "Bye...\n"));
    return 0;

}  /* End main() -- snmpd */

/*******************************************************************-o-******
 * receive
 *
 * Parameters:
 *      
 * Returns:
 *	0	On success.
 *	-1	System error.
 *
 * Infinite while-loop which monitors incoming messges for the agent.
 * Invoke the established message handlers for incoming messages on a per
 * port basis.  Handle timeouts.
 */
static int
receive(void)
{
    int numfds;
    fd_set fdset;
    struct timeval	timeout, *tvp = &timeout;
    struct timeval	sched,   *svp = &sched,
			now,     *nvp = &now;
    int count, block;



    /*
     * Set the 'sched'uled timeout to the current time + one TIMETICK.
     */
    gettimeofday(nvp, (struct timezone *) NULL);
    svp->tv_usec = nvp->tv_usec + TIMETICK;
    svp->tv_sec = nvp->tv_sec;
    
    while (svp->tv_usec >= ONE_SEC){
	svp->tv_usec -= ONE_SEC;
	svp->tv_sec++;
    }

    /*
     * Loop-forever: execute message handlers for sockets with data,
     * reset the 'sched'uler.
     */
    while (running) {
	if (reconfig) {
	    reconfig = 0;
	    update_config();
	}
	tvp =  &timeout;
	tvp->tv_sec = 0;
	tvp->tv_usec = TIMETICK;

	numfds = 0;
	FD_ZERO(&fdset);
        block = 0;
        snmp_select_info(&numfds, &fdset, tvp, &block);
        if (block == 1)
            tvp = NULL; /* block without timeout */
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
		    log_perror("select");
		}
		return -1;
	    default:
		snmp_log(LOG_ERR, "select returned %d\n", count);
		return -1;
	}  /* endif -- count>0 */


	/*
	 * If the time 'now' is greater than the 'sched'uled time, then:
	 *
	 *	Check alarm and event timers if v2p is configured.
	 *	Reset the 'sched'uled time to current time + one TIMETICK.
	 *	Age the cache network addresses (from whom messges have
	 *		been received).
	 */
        gettimeofday(nvp, (struct timezone *) NULL);

	if (nvp->tv_sec > svp->tv_sec
	    || (nvp->tv_sec == svp->tv_sec && nvp->tv_usec > svp->tv_usec)){
            svp->tv_usec = nvp->tv_usec + TIMETICK;
            svp->tv_sec = nvp->tv_sec;
    
            while (svp->tv_usec >= ONE_SEC){
	        svp->tv_usec -= ONE_SEC;
	        svp->tv_sec++;
            }
	    if (log_addresses && lastAddrAge++ > 600){
		
		lastAddrAge = 0;
		for(count = 0; count < ADDRCACHE; count++){
		    if (addrCache[count].status == OLD)
			addrCache[count].status = UNUSED;
		    if (addrCache[count].status == USED)
			addrCache[count].status = OLD;
		}
	    }
	}  /* endif -- now>sched */
    }  /* endwhile */

    /* We've received a sigTERM.  Shutdown by calling mib-module
       functions and sending out a shutdown trap. */
    snmp_log(LOG_INFO, "Received TERM or STOP signal...  shutting down...\n");
    snmp_shutdown("snmpd");

  #include "mib_module_shutdown.h"

    DEBUGMSGTL(("snmpd", "sending shutdown trap\n"));
    SnmpTrapNodeDown();
    DEBUGMSGTL(("snmpd", "Bye...\n"));

    return 0;

}  /* end receive() */




/*******************************************************************-o-******
 * snmp_check_packet
 *
 * Parameters:
 *	session, from
 *      
 * Returns:
 *	1	On success.
 *	0	On error.
 *
 * Handler for all incoming messages (a.k.a. packets) for the agent.  If using
 * the libwrap utility, log the connection and deny/allow the access. Print
 * output when appropriate, and increment the incoming counter.
 *
 */
int
snmp_check_packet(struct snmp_session *session,
  snmp_ipaddr from)
{
    struct sockaddr_in *fromIp = (struct sockaddr_in *)&from;

#ifdef USE_LIBWRAP
    char *addr_string;
    /*
     * Log the message and/or dump the message.
     * Optionally cache the network address of the sender.
     */
    addr_string = inet_ntoa(fromIp->sin_addr);

    if(!addr_string) {
      addr_string = STRING_UNKNOWN;
    }
    if(hosts_ctl("snmpd", addr_string, addr_string, STRING_UNKNOWN)) {
      snmp_log(allow_severity, "Connection from %s", addr_string);
    } else {
      snmp_log(deny_severity, "Connection from %s refused", addr_string);
      return(0);
    }
#endif	/* USE_LIBWRAP */

    snmp_increment_statistic(STAT_SNMPINPKTS);

    if (log_addresses){
	int count;
	
	for(count = 0; count < ADDRCACHE; count++){
	    if (addrCache[count].status > UNUSED /* used or old */
		&& fromIp->sin_addr.s_addr == addrCache[count].addr)
		break;
	}

	if (count >= ADDRCACHE || verbose){
	    DEBUGMSGTL(("snmpd", "Received SNMP packet(s) from %s\n",
                        inet_ntoa(fromIp->sin_addr)));
	    for(count = 0; count < ADDRCACHE; count++){
		if (addrCache[count].status == UNUSED){
		    addrCache[count].addr = fromIp->sin_addr.s_addr;
		    addrCache[count].status = USED;
		    break;
		}
	    }
	} else {
	    addrCache[count].status = USED;
	}
    }

    return ( 1 );
}


int
snmp_check_parse( struct snmp_session *session,
    struct snmp_pdu     *pdu,
    int    result)
{
    if ( result == 0 ) {
        if ( verbose) {
             char buf [256];
	     struct variable_list *var_ptr;
	     
	     for ( var_ptr = pdu->variables ;
	           var_ptr != NULL ; var_ptr=var_ptr->next_variable ) {
                    sprint_objid (buf, var_ptr->name, var_ptr->name_length);
                    snmp_log(LOG_DEBUG, "    -- %s\n", buf);
	     }
	}
    	return 1;
    }
    return 0; /* XXX: does it matter what the return value is? */
}

/*******************************************************************-o-******
 * snmp_input
 *
 * Parameters:
 *	 op
 *	*session
 *	 requid
 *	*pdu
 *	*magic
 *      
 * Returns:
 *	1		On success	-OR-
 *	Passes through	Return from alarmGetResponse() when 
 *	  		  USING_V2PARTY_ALARM_MODULE is defined.
 *
 * Call-back function to manage responses to traps (informs) and alarms.
 * Not used by the agent to process other Response PDUs.
 */
int
snmp_input(int op,
	   struct snmp_session *session,
	   int reqid,
	   struct snmp_pdu *pdu,
	   void *magic)
{
    struct get_req_state *state = (struct get_req_state *)magic;
    
    if (op == RECEIVED_MESSAGE) {
	if (pdu->command == SNMP_MSG_GET) {
	    if (state->type == EVENT_GET_REQ) {
		/* this is just the ack to our inform pdu */
		return 1;
	    }
	}
    }
    else if (op == TIMED_OUT) {
	if (state->type == ALARM_GET_REQ) {
		/* Need a mechanism to replace obsolete SNMPv2p alarm */
	}
    }
    return 1;

}  /* end snmp_input() */


    
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

