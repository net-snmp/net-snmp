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
#include <sys/socket.h>
#include <net/if.h>
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

#include "mib_module_config.h"
#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "system.h"
#include "read_config.h"
#include "snmp.h"
#include "mib.h"
#include "m2m.h"
#include "snmpv3.h"
#include "snmp_vars.h"
#include "mibgroup/snmpv3/usmUser.h"

#ifdef USING_V2PARTY_ALARM_MODULE
#include "mibgroup/v2party/alarm.h"
#endif
#ifdef USING_V2PARTY_EVENT_MODULE
#include "mibgroup/v2party/event.h"
#endif

#include "snmp_client.h"
#include "snmpd.h"
#include "var_struct.h"
#include "mibgroup/struct.h"
#include "mibgroup/util_funcs.h"
#include "snmpusm.h"
#include "tools.h"
#include "lcd_time.h"

#include "transform_oids.h"

#include "agent_read_config.h"

#include "version.h"



/*
 * Globals.
 */
#ifdef USE_LIBWRAP
#include <syslog.h>
#include <tcpd.h>

int allow_severity	 = LOG_INFO;
int deny_severity	 = LOG_WARNING;
#endif  /* USE_LIBWRAP */


#define TIMETICK         500000L
#define ONE_SEC         1000000L

struct timeval	starttime;
int 		log_addresses	 = 0;
int 		verbose		 = 0;
int 		snmp_dump_packet;

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

static int	  sdlist[NUM_SOCKETS],
		  sdlen = 0;
static int	  portlist[NUM_SOCKETS];
int		(*sd_handlers[NUM_SOCKETS])__P((int));




/*
 * Prototypes.
 */
static int receive __P((int *, int));
int snmp_read_packet __P((int));
int snmp_input __P((int, struct snmp_session *, int, struct snmp_pdu *, void *));
static char *sprintf_stamp __P((time_t *));
static int create_v1_trap_session __P((char *, char *));
static int create_v2_trap_session __P((char *, char *));
static void free_v1_trap_session __P((struct trap_sink *sp));
static void free_v2_trap_session __P((struct trap_sink *sp));
static void send_v1_trap __P((struct snmp_session *, int, int));
static void send_v2_trap __P((struct snmp_session *, int, int, int));
static void usage __P((char *));
int main __P((int, char **));
static RETSIGTYPE SnmpTrapNodeDown __P((int));



static char *
sprintf_stamp (now)
    time_t *now;
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


static int
create_v1_trap_session (sink, com)
    char *sink, *com;
{
    struct trap_sink *new_sink =
      (struct trap_sink *) malloc (sizeof (*new_sink));

    if (!snmp_trapcommunity) snmp_trapcommunity = strdup("public");
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
    snmp_perror("snmpd");
    free(new_sink);
    return 0;
}

static void
free_v1_trap_session (sp)
    struct trap_sink *sp;
{
    snmp_close(sp->sesp);
    if (sp->ses.community) free(sp->ses.community);
    free (sp);
}

static int
create_v2_trap_session (sink, com)
    char *sink, *com;
{
    struct trap_sink *new_sink =
      (struct trap_sink *) malloc (sizeof (*new_sink));

    if (!snmp_trapcommunity) snmp_trapcommunity = strdup("public");
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
    snmp_perror("snmpd");
    free(new_sink);
    return 0;
}

static void
free_v2_trap_session (sp)
    struct trap_sink *sp;
{
    snmp_close(sp->sesp);
    if (sp->ses.community) free(sp->ses.community);
    free (sp);
}

void
snmpd_free_trapsinks __P((void))
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

static void
send_v1_trap (ss, trap, specific)
    struct snmp_session *ss;
    int trap, specific;
{
    struct snmp_pdu *pdu;
    struct timeval now;

    gettimeofday(&now, NULL);

    pdu = snmp_pdu_create (SNMP_MSG_TRAP);

    if (trap == SNMP_TRAP_ENTERPRISESPECIFIC) {
	pdu->enterprise		 = objid_enterprisetrap;
	pdu->enterprise_length	 = length_enterprisetrap-2;

    } else { 
	pdu->enterprise		 = version_id;
	pdu->enterprise_length	 = version_id_len;
    }
    pdu->agent_addr.sin_addr.s_addr
				 = get_myaddr();
    pdu->trap_type		 = trap;
    pdu->specific_type		 = specific;
    pdu->time		 	 = calculate_time_diff(&now, &starttime);

    if (snmp_send (ss, pdu) == 0) {
        snmp_perror ("snmpd: send_v1_trap");
    }

    snmp_increment_statistic(STAT_SNMPOUTTRAPS);


}  /* end send_v1_trap() */



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
static void
send_v2_trap (ss, trap, specific, type)
    struct snmp_session *ss;
    int trap, specific, type;
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
        snmp_perror ("snmpd: send_v2_trap");
    }

    snmp_increment_statistic(STAT_SNMPOUTTRAPS);

}  /* end send_v2_trap() */

void
send_trap_pdu(pdu)
    struct snmp_pdu *pdu;
{
  struct snmp_pdu *mypdu;
  
  struct trap_sink *sink = sinks;

  if ((snmp_enableauthentraps == SNMP_AUTHENTICATED_TRAPS_ENABLED)
      && (sink != NULL)) {
    while (sink) {
      if (sink->ses.version == SNMP_VERSION_2c) {
        DEBUGP(" found v2 session...\n");
        mypdu = snmp_clone_pdu(pdu);
        if (snmp_send(sink->sesp, mypdu) == 0) {
          snmp_perror ("snmpd: send_trap_pdu");
        }
        snmp_increment_statistic(STAT_SNMPOUTTRAPS);
      }
      sink = sink->next;
    }
    DEBUGP("  done\n");
  }
}  /* end send_trap_pdu() */

/*
 * FIX  Need case for v3? 
 */
void
send_easy_trap (trap, specific)
    int trap;
    int specific;
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
}  /* end send_easy_trap() */
 
char *
reverse_bytes(buf,num)
  char *buf;
  int num;
{
  static char outbuf[100];
  int i;

  if (num > 100)
    return NULL;
  
  for(i=num-1;i>=0;i--)
    outbuf[i] = *buf++;
  return(outbuf);
}  /* end reverse_bytes() */


static void
usage(prog)
char *prog;
{
  printf("\nUsage:  %s [-h] [-v] [-f] [-a] [-d] [-q] [-D] [-p NUM] [-L] [-l LOGFILE]\n",prog);
  printf("\n\tVersion:  %s\n",VersionInfo);
  printf("\tAuthor:   Wes Hardaker\n");
  printf("\tEmail:    ucd-snmp-coders@ece.ucdavis.edu\n");
  printf("\n-h\t\tThis usage message.\n");
  printf("-H\t\tDisplay configuration file directives understood.\n");
  printf("-v\t\tVersion information.\n");
  printf("-f\t\tDon't fork from the shell.\n");
  printf("-a\t\tLog addresses.\n");
  printf("-d\t\tDump sent and received UDP SNMP packets\n");
  printf("-q\t\tPrint information in a more parsable format (quick-print)\n");
  printf("-D\t\tTurn on debugging output\n");
  printf("-p NUM\t\tRun on port NUM instead of the default:  161\n");
  printf("-c CONFFILE\tRead CONFFILE as a configuration file.\n");
  printf("-C\t\tDon't read the default configuration files.\n");
  printf("-L\t\tPrint warnings/messages to stdout/err rather than a logfile\n");
  printf("-L\t\tAppend to the logfile rather than truncating it.\n");
  printf("-l LOGFILE\tPrint warnings/messages to LOGFILE\n");
  printf("\t\t(By default LOGFILE=%s)\n",
#ifdef LOGFILE
         LOGFILE
#else
    "stdout/err"
#endif
    );
  printf("\n");
  exit(1);
}


RETSIGTYPE
SnmpdShutDown(a)
  int a;
{
	/*
	 * We've received a sigTERM.  Shutdown by calling mib-module
	 * functions and sending out a shutdown trap.
	 */
	fprintf(stderr, "Received TERM or INT signal...  shutting down...\n");

        snmp_shutdown("snmpd");

#include "mib_module_shutdown.h"

	DEBUGP("sending shutdown trap\n");
	SnmpTrapNodeDown(a);


	DEBUGP("Bye...\n");
	exit(1);

}  /* end SnmpdShutDown() */


static RETSIGTYPE
SnmpTrapNodeDown(a)
  int a;
{
    send_easy_trap (SNMP_TRAP_ENTERPRISESPECIFIC, 2);
    /* XXX  2 - Node Down #define it as NODE_DOWN_TRAP */
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
main(argc, argv)
    int	    argc;
    char    *argv[];
{
	int             arg, i;
	int             ret;
	u_short         dest_port = SNMP_PORT;
	int             dont_fork = 0;
	char            logfile[SNMP_MAXBUF_SMALL],
			file[SNMP_MAXBUF_SMALL];
	char           *cptr, **argvptr;
	u_char          *engineID;
	int             engineIDLen;
        struct usmUser *user, *userListPtr;
        char           *pid_file = NULL;
        FILE           *PID;
        int             dont_zero_log = 0;

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
                  snmp_dump_packet++;
                  verbose = 1;
                  break;

                case 'q':
                  snmp_set_quick_print(1);
                  break;

                case 'D':
                  snmp_set_do_debugging(!snmp_get_do_debugging());
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
                    logfile[0] = 0;
                    break;
                case 'A':
                    dont_zero_log = 1;
                    break;
                case 'h':
                    usage(argv[0]);
                    break;
                case 'H':
                    init_snmpv3("snmpd");
                    init_agent();            /* register our .conf handlers */
                    register_mib_handlers(); /* snmplib .conf handlers */
                    fprintf(stderr, "Configuration directives understood:\n");
                    read_config_print_usage("  ");
                    break;
                case 'v':
                  printf(
                    "\n"
                    "UCD-snmp version:  %s\n"
                    "Author:            Wes Hardaker\n"
                    "Email:             ucd-snmp-coders@ece.ucdavis.edu\n\n",
                    VersionInfo);
                  exit(0);

                case '-':
                  switch (argv[arg][2]) {
                    case 'v':
                      printf(
                        "\n"
                        "UCD-snmp version:  %s\n"
                        "Author:            Wes Hardaker\n"
                        "Email:             ucd-snmp-coders@ece.ucdavis.edu\n\n",
                        VersionInfo);
                      exit(0);
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
	argvrestart = (char *) malloc((ret));
	argvrestartname = (char *) malloc(strlen(argv[0]) + 1);
	strcpy(argvrestartname, argv[0]);
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
	if (logfile[0]) {
		close(1);
		open(logfile, O_WRONLY | O_CREAT | O_TRUNC, 0644);
		close(2);
		dup(1);
		close(0);
	}
#ifdef USE_LIBWRAP
	openlog("snmpd", LOG_CONS, LOG_AUTH | LOG_INFO);
#endif
	setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
	printf("%s UCD-SNMP version %s\n", sprintf_stamp(NULL), VersionInfo);


	/* 
	 * Initialize the world.  Detach from the shell.
	 * Create initial user.
	 */
	if (!dont_fork && fork() != 0) {
		exit(0);
	}

        if (pid_file != NULL) {
          if ((PID = fopen(pid_file, "w")) == NULL) {
            perror("fopen");
            exit(1);
          }
          fprintf(PID, "%d\n", getpid());
          fclose(PID);
        }

        usm_set_reportErrorOnUnknownID(1);
	init_agent();		/* register our .conf handlers */
	init_snmpv3("snmpd");	/* register the v3 handlers */
	register_mib_handlers();/* snmplib .conf handlers */
	read_premib_configs();	/* read pre-mib-reading .conf handlers */

        /* create the initial and template users */
        user = usm_create_initial_user("initial", usmHMACMD5AuthProtocol,
                                       USM_LENGTH_OID_TRANSFORM,
                                       usmDESPrivProtocol,
                                       USM_LENGTH_OID_TRANSFORM);
        userListPtr = usm_add_user(user);
        user = usm_create_initial_user("templateMD5", usmHMACMD5AuthProtocol,
                                       USM_LENGTH_OID_TRANSFORM,
                                       usmDESPrivProtocol,
                                       USM_LENGTH_OID_TRANSFORM);
        userListPtr = usm_add_user(user);
        user = usm_create_initial_user("templateSHA", usmHMACSHA1AuthProtocol,
                                       USM_LENGTH_OID_TRANSFORM,
                                       usmDESPrivProtocol,
                                       USM_LENGTH_OID_TRANSFORM);
        userListPtr = usm_add_user(user);
        
        if (userListPtr == NULL) /* user already existed */
          usm_free_user(user);
	init_mib();		/* initialize the mib structures */
	update_config(0);	/* read in config files and register HUP */
        init_usm_post_config();
        init_snmpv3_post_config();

	/* 
	 * Open ports.
	 * Set the time.
	 * Tell the world we're up.
	 * Set signal handlers.
	 *
	 * Forever monitor the dest_port for incoming PDUs.
	 */
	init_snmp2p(dest_port);
	printf("Opening port(s): ");
	fflush(stdout);
	if ((ret = open_port(dest_port)) > 0) {
		/* Save pointer to function.
		 */
		sd_handlers[ret - 1] = snmp_read_packet;	
	}
	open_ports_snmp2p();
	printf("\n");
	fflush(stdout);

	gettimeofday(&starttime, NULL);
	starttime.tv_sec--;
	starttime.tv_usec += 1000000L;

	send_easy_trap(SNMP_TRAP_COLDSTART, 0);
	signal(SIGTERM, SnmpdShutDown);
	signal(SIGINT, SnmpdShutDown);

	memset(addrCache, 0, sizeof(addrCache));
	receive(sdlist, sdlen);


	return 0;

}  /* end main() -- snmpd */


/*******************************************************************-o-******
 * open_port
 *
 * Parameters:
 *	dest_port	Port number for destination to open.
 *      
 * Returns:
 *	>0	On success: socket descriptor number.
 *	 0	If the requested port is already open.
 *	<0	Socket manipulation error.
 *
 * ASSUMEs dest_port is in host-byte order.
 */
int
open_port ( dest_port )
     u_short dest_port;
{
    int sd, index;
    struct sockaddr_in	me;
        
        for(index = 0; index < sdlen; index++)
	    if (dest_port == portlist[index])
		break;
	if (index < sdlen)  /* found a hit before the end of the list */
	    return 0;
	printf("%u ", dest_port); 
	fflush(stdout);
	/* Set up connections */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0){
	    perror("socket");
	    return -1;
	}
	me.sin_family = AF_INET;
	me.sin_addr.s_addr = INADDR_ANY;
	me.sin_port = htons(dest_port);
	if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
	    fprintf(stderr,"bind: udp/%d: ", ntohs(me.sin_port));
	    perror(NULL);
	    return -2;
	}
	sdlist[sdlen] = sd;
	portlist[sdlen] = dest_port;
        fcntl(sd,F_SETFD,1);           /* close on exec */
	if (++sdlen == NUM_SOCKETS){
	    printf("No more sockets... ignoring rest of file\n");
	    return -3;
	}	
        return sdlen;
}





/*******************************************************************-o-******
 * receive
 *
 * Parameters:
 *	sdlist[]
 *	sdlen
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
receive(sdlist, sdlen)
    int sdlist[];
    int sdlen;
{
    int numfds, index;
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
    while(1){
	tvp =  &timeout;
	tvp->tv_sec = 0;
	tvp->tv_usec = TIMETICK;

	numfds = 0;
	FD_ZERO(&fdset);
	for(index = 0; index < sdlen; index++){
	    if (sdlist[index] + 1 > numfds)
		numfds = sdlist[index] + 1;
	    FD_SET(sdlist[index], &fdset);
	}
        block = 0;
        snmp_select_info(&numfds, &fdset, tvp, &block);
        if (block == 1)
            tvp = NULL; /* block without timeout */
	count = select(numfds, &fdset, 0, 0, tvp);

	if (count > 0){
	    for(index = 0; index < sdlen; index++){
		if(FD_ISSET(sdlist[index], &fdset)){
		    sd_handlers[index](sdlist[index]);
		    FD_CLR(sdlist[index], &fdset);
		}
	    }
	    snmp_read(&fdset);
	} else switch(count){
	    case 0:
                snmp_timeout();
                break;
	    case -1:
		if (errno == EINTR){
		    continue;
		} else {
		    perror("select");
		}
		return -1;
	    default:
		printf("select returned %d\n", count);
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
#ifdef USING_V2PARTY_ALARM_MODULE
	    alarmTimer(nvp);
#endif
#ifdef USING_V2PARTY_EVENT_MODULE
	    eventTimer(nvp);
#endif
            svp->tv_usec = nvp->tv_usec + TIMETICK;
            svp->tv_sec = nvp->tv_sec;
    
            while (svp->tv_usec >= ONE_SEC){
	        svp->tv_usec -= ONE_SEC;
	        svp->tv_sec++;
            }
	    if (log_addresses && lastAddrAge++ > 600){
		int count;
		
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

    return 0;

}  /* end receive() */




/*******************************************************************-o-******
 * snmp_read_packet
 *
 * Parameters:
 *	sd
 *      
 * Returns:
 *	1	On success.
 *	0	On error.
 *
 * Handler for all incoming messages (a.k.a. packets) for the agent.  Pass
 * them on to snmp_agent_parse().  Write to the log file.
 *
 */
int
snmp_read_packet(sd)
    int sd;
{
    struct sockaddr_in	from;
    int length, out_length, fromlength;
    u_char  packet[SNMP_MAXBUF_MESSAGE], outpacket[SNMP_MAXBUF_MESSAGE];
#ifdef USE_LIBWRAP
    char *addr_string;
#endif


    /*
     * Receive a message.
     */
    fromlength = sizeof from;
    length = recvfrom(sd, (char *) packet, SNMP_MAXBUF_MESSAGE,
		      0, (struct sockaddr *)&from,
		      &fromlength);
    if (length == -1)
	perror("recvfrom");



    /*
     * Log the message and/or dump the message.
     * Optionally cache the network address of the sender.
     */
#ifdef USE_LIBWRAP
    addr_string = inet_ntoa(from.sin_addr);

    if(!addr_string) {
      addr_string = STRING_UNKNOWN;
    }
    if(hosts_ctl("snmpd", addr_string, addr_string, STRING_UNKNOWN)) {
      syslog(allow_severity, "Connection from %s", addr_string);
    } else {
      syslog(deny_severity, "Connection from %s refused", addr_string);
      return(0);
    }
#endif	/* USE_LIBWRAP */

    snmp_increment_statistic(STAT_SNMPINPKTS);


    if (snmp_dump_packet){
	printf("\nReceived %d bytes from %s:\n", length,
	       inet_ntoa(from.sin_addr));
	xdump(packet, length, "");
	printf("\n");
        fflush(stdout);

    } else if (log_addresses){
	int count;
	
	for(count = 0; count < ADDRCACHE; count++){
	    if (addrCache[count].status > UNUSED /* used or old */
		&& from.sin_addr.s_addr == addrCache[count].addr)
		break;
	}

	if (count >= ADDRCACHE || verbose){
	    printf("%s Received SNMP packet(s) from %s\n",
		   sprintf_stamp(NULL), inet_ntoa(from.sin_addr));
	    for(count = 0; count < ADDRCACHE; count++){
		if (addrCache[count].status == UNUSED){
		    addrCache[count].addr = from.sin_addr.s_addr;
		    addrCache[count].status = USED;
		    break;
		}
	    }
	} else {
	    addrCache[count].status = USED;
	}
    }  /* endif -- snmp_dump_packet */



    /*
     * Parse the message and send a response.
     * Optionally dump the response message.
     */
    out_length = SNMP_MAXBUF_MESSAGE;
    if (snmp_agent_parse(packet, length, outpacket, &out_length,
			 from.sin_addr.s_addr)){
	if (snmp_dump_packet){
	    printf("\nSent %d bytes to %s:\n", out_length,
		   inet_ntoa(from.sin_addr));
	    xdump(outpacket, out_length, "");
	    printf("\n");
            fflush(stdout);
	}

  	snmp_increment_statistic(STAT_SNMPOUTPKTS);

	if (sendto(sd, (char *)outpacket, out_length, 0,
		   (struct sockaddr *)&from, sizeof(from)) < 0){
	    perror("sendto");
	    return 0;
	}

    } else {
      snmp_perror("snmp_agent_parse()");
    }  /* endif -- snmp_agent_parse */

    return 1;

}  /* end snmp_read_packet() */




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
snmp_input(op, session, reqid, pdu, magic)
    int op;
    struct snmp_session *session;
    int reqid;
    struct snmp_pdu *pdu;
    void *magic;
{
    struct get_req_state *state = (struct get_req_state *)magic;
    
    if (op == RECEIVED_MESSAGE) {
	if (pdu->command == SNMP_MSG_GET) {
	    if (state->type == EVENT_GET_REQ) {
		/* this is just the ack to our inform pdu */
		return 1;
	    }
#ifdef USING_V2PARTY_ALARM_MODULE
	    return alarmGetResponse(pdu, state, op, session);
#endif
	}
    }
    else if (op == TIMED_OUT) {
	if (state->type == ALARM_GET_REQ) {
#ifdef USING_V2PARTY_ALARM_MODULE
	    return alarmGetResponse(pdu, state, op, session);
#endif
	}
    }
    return 1;

}  /* end snmp_input() */


    
void
snmpd_parse_config_authtrap(word, cptr)
    char *word;
    char *cptr;
{
    int i;
  
    i = atoi(cptr);
    if (i < 1 || i > 2)
	config_perror("authtrapenable must be 1 or 2");
    else
	snmp_enableauthentraps = i;
}

void
snmpd_parse_config_trapsink(word, cptr)
    char *word;
    char *cptr;
{
    char tmpbuf[1024];
  
    if (create_v1_trap_session(cptr, snmp_trapcommunity) == 0) {
	sprintf(tmpbuf,"cannot create trapsink: %s", cptr);
	config_perror(tmpbuf);
    }
}


void
snmpd_parse_config_trap2sink(word, cptr)
    char *word;
    char *cptr;
{
    char tmpbuf[1024];
  
    if (create_v2_trap_session(cptr, snmp_trapcommunity) == 0) {
	sprintf(tmpbuf,"cannot create trap2sink: %s", cptr);
	config_perror(tmpbuf);
    }
}

void
snmpd_parse_config_trapcommunity(word,cptr)
    char *word;
    char *cptr;
{
    if (snmp_trapcommunity) free(snmp_trapcommunity);
    snmp_trapcommunity = malloc (strlen(cptr));
    copy_word(cptr, snmp_trapcommunity);
}

void
snmpd_free_trapcommunity __P((void))
{
    if (snmp_trapcommunity) {
	free(snmp_trapcommunity);
	snmp_trapcommunity = NULL;
    }
}

