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
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#elif HAVE_WINSOCK_H
#include <winsock.h>
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
#if HAVE_SYS_WAIT_H
#include <sys/wait.h>
#endif
#include <signal.h>
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_PROCESS_H  /* Win32-getpid */
#include <process.h>
#endif
#if HAVE_LIMITS_H
#include <limits.h>
#endif
#if HAVE_PWD_H
#include <pwd.h>
#endif
#if HAVE_GRP_H
#include <grp.h>
#endif

#ifndef PATH_MAX
# ifdef _POSIX_PATH_MAX
#  define PATH_MAX _POSIX_PATH_MAX
# else
#  define PATH_MAX 255
# endif
#endif

#ifndef FD_SET
typedef long    fd_mask;
#define NFDBITS (sizeof(fd_mask) * NBBY)        /* bits per mask */
#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      memset((p), 0, sizeof(*(p)))
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
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
#include "default_store.h"
#include "mib_module_config.h"

#include "snmp_client.h"
#include "snmpd.h"
#include "var_struct.h"
#include "mibgroup/struct.h"
#include "snmp_debug.h"
#include "mib_modules.h"

#include "snmpusm.h"
#include "tools.h"
#include "lcd_time.h"
#include "mibgroup/util_funcs.h"

#include "snmp_agent.h"
#include "agent_trap.h"
#include "ds_agent.h"
#include "agent_read_config.h"
#include "snmp_logging.h"

#include "version.h"

#include "mib_module_includes.h"

/*
 * Include winservice.h to support Windows Service
 */
#ifdef WIN32
#include <windows.h>
#include <tchar.h>
#include "winservice.h"
#endif

/*
 * Globals.
 */
#ifdef USE_LIBWRAP
#include <tcpd.h>

int allow_severity	 = LOG_INFO;
int deny_severity	 = LOG_WARNING;
#endif  /* USE_LIBWRAP */

#define TIMETICK         500000L
#define ONE_SEC         1000000L

int 		log_addresses	 = 0;
int 		snmp_dump_packet;
int             running          = 1;
int		reconfig	 = 0;

#ifdef WIN32
/* SNMP Agent Status */
#define AGENT_RUNNING 1
#define AGENT_STOPPED 0
int agent_status = AGENT_STOPPED;
#endif

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

extern char **argvrestartp;
extern char  *argvrestart;
extern char  *argvrestartname;

#define NUM_SOCKETS	32

#ifdef USING_SMUX_MODULE
static int sdlist[NUM_SOCKETS], sdlen = 0;
#endif /* USING_SMUX_MODULE */

/*
 * Declare Windows Service related global variables
 */
#ifdef WIN32
LPTSTR g_szAppName = _T("Net-Snmp Agent");   /* Application Name */
#endif

/*
 * Prototypes
 */
int snmp_read_packet (int);
int snmp_input (int, struct snmp_session *, int, struct snmp_pdu *, void *);
static void usage (char *);

#ifdef WIN32
int __cdecl _tmain(int argc, TCHAR *argv[]);
#else
int main (int, char **);
#endif

static void SnmpTrapNodeDown (void);
static int receive(void);
int snmp_check_packet(struct snmp_session*, snmp_ipaddr);
int snmp_check_parse(struct snmp_session*, struct snmp_pdu*, int);

#ifdef WIN32
/* Stop Function to break the infinite loop
 * This is requried to stop proccess, when STOP request
 * received from the SCM
 */
void StopSnmpAgent(void);
/*
 * Main Snmp Deamon
 * Moving all main() code to this function to support
 * Windows Serivce functionality
 */
int SnmpDaemonMain(int argc, TCHAR *argv[]);
#endif


static void usage(char *prog)
{
#ifdef WIN32
printf("\nUsage:  %s -register [param list] |",prog);
printf("\n\t\t-unregister |"); 
printf("\n\t\t[-h] [-v] [-f] [-a] [-d] [-V] [-P PIDFILE] [-q] [-D] [-p NUM] [-L] [-l LOGFILE] [-r]");
#else
	printf("\nUsage:  %s [-h] [-v] [-f] [-a] [-d] [-V] [-P PIDFILE] [-q] [-D] [-p NUM] [-L] [-l LOGFILE] [-r]",prog);
#endif /* WIN32 */
#if HAVE_UNISTD_H
	printf(" [-u uid] [-g gid]");
#endif
	printf("\n");
	printf("\n\tVersion:  %s\n",VersionInfo);
	printf("\tEmail:    net-snmp-coders@lists.sourceforge.net\n");
	printf("\n-h\t\tThis usage message.\n");
#ifdef WIN32
	printf("-register [param list]");
	printf("\n\t\tRegister as windows service");
	printf("\n\t\t\"param list\"\tStartup parameter list for service, same as normal parameters");
	printf("\n\t\tE.g.: %s -register -p 2002",prog);
	printf("\n\t\tThis registers %s as service, which listens on port 2002",prog);
	printf("\n\t\tNote:- Some options doesn't make sense when running as service");
	printf("\n-unregister\tUnregisters service, if already registered\n");
#endif
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
#if defined(USING_AGENTX_SUBAGENT_MODULE) || defined(USING_AGENTX_MASTER_MODULE)
	printf("-x SOCKADDR\tBind AgentX port to this address\n");
#endif
#ifdef USING_AGENTX_SUBAGENT_MODULE
	printf("-X\t\tRun as an AGENTX subagent rather than an SNMP master agent.\n");
#endif
	printf("-c CONFFILE\tRead CONFFILE as a configuration file.\n");
	printf("-C\t\tDon't read the default configuration files.\n");
	printf("-L\t\tPrint warnings/messages to stdout/err\n");
	printf("-s\t\tLog warnings/messages to syslog\n");
	printf("-A\t\tAppend to the logfile rather than truncating it.\n");
	printf("-r\t\tDon't exit if root only accessible files can't be opened\n");
	printf("-I [-]INITLIST\tList of mib modules to initialize (or not).\n");
	printf("\t\t (run snmpd with -Dmib_init for a list)\n");
	printf("-l LOGFILE\tPrint warnings/messages to LOGFILE\n");
#ifdef LOGFILE
	printf("\t\t(By default LOGFILE=%s)\n", LOGFILE);
#else
	printf("\t\t(By default LOGFILE=none)\n");
#endif

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
        extern struct snmp_session *main_session;
	running = 0;
#ifdef WIN32
	/*
	 * In case of windows, select() in receive() function will not return 
	 * on signal. Thats why following function is called, which closes the 
	 * main socket descriptor and causes the select() to return
	*/
	snmp_close(main_session);
#endif
}

#ifdef SIGHUP
	RETSIGTYPE
SnmpdReconfig(int a)
{
	reconfig = 1;
	signal(SIGHUP, SnmpdReconfig);
}
#endif

#ifdef SIGUSR1
extern void dump_registry( void );
	RETSIGTYPE
SnmpdDump(int a)
{
	dump_registry();
	signal(SIGUSR1, SnmpdDump);
}
#endif


static void
SnmpTrapNodeDown(void)
{
    send_easy_trap (SNMP_TRAP_ENTERPRISESPECIFIC, 2);
    /* XXX  2 - Node Down #define it as NODE_DOWN_TRAP */
}

static void
setup_log(int restart, int dont_zero, int stderr_log, int syslog_log, 
	  char *logfile)
{
    static char logfile_s[PATH_MAX + 1] = { 0 };
    static int dont_zero_s  = 0;
    static int stderr_log_s = 0;
    static int syslog_log_s = 0;

    if (restart == 0) {
	if (logfile != NULL) {
	    strncpy(logfile_s, logfile, PATH_MAX);
	}
	dont_zero_s  = dont_zero;
	stderr_log_s = stderr_log;
	syslog_log_s = syslog_log;
    }

    if (!stderr_log_s) {
	snmp_disable_stderrlog();
    }

    if (logfile_s[0]) {
	snmp_enable_filelog(logfile_s, dont_zero_s);
    }

    if (syslog_log_s) {
	snmp_enable_syslog();
    }
}

/*******************************************************************-o-******
 * main - Non Windows
 * SnmpDeamonMain - Windows to support windows serivce
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
#ifdef WIN32
SnmpDaemonMain(int argc, TCHAR *argv[])
#else
main(int argc, char *argv[])
#endif
{
	int             arg, i;
	int             ret;
	int             dont_fork = 0;
	char            logfile[PATH_MAX + 1] = { 0 };
	char           *cptr, **argvptr;
	char           *pid_file = NULL;
        char            buf[SPRINT_MAX_LEN];
#if HAVE_GETPID
	FILE           *PID;
#endif
	int             dont_zero_log = 0;
	int             stderr_log=0, syslog_log=0;
	int             uid=0, gid=0;
        int             agent_mode=-1;	

#ifdef LOGFILE
	strncpy(logfile, LOGFILE, PATH_MAX);
#endif

#ifdef NO_ROOT_ACCESS
        /* default to no */
        ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS, 1);
#endif
			/* Default to NOT running an AgentX master */
        ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_AGENTX_MASTER, 0);


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
                  ds_set_string(DS_LIBRARY_ID, DS_LIB_OPTIONALCONFIG,
                                 argv[arg]);
                  break;

                case 'C':
                    ds_set_boolean(DS_LIBRARY_ID, DS_LIB_DONT_READ_CONFIGS, 1);
                    break;

		case 'd':
                    snmp_set_dump_packet(++snmp_dump_packet);
		    ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE, 1);
		    break;

		case 'q':
		    snmp_set_quick_print(1);
		    break;

                case 'T':
                    if (argv[arg][2] != '\0') 
                        cptr = &argv[arg][2];
                    else if (++arg>argc) {
                        fprintf(stderr,"%s: Need UDP or TCP after -T flag.\n", argv[0]);
                        usage(argv[0]);
                        exit(1);
                    } else {
                        cptr = argv[arg];
                    }
                    if (strcasecmp(cptr,"TCP") == 0) {
                        ds_set_int(DS_APPLICATION_ID, DS_AGENT_FLAGS,
                                   ds_get_int(DS_APPLICATION_ID, DS_AGENT_FLAGS)
                                   | SNMP_FLAGS_STREAM_SOCKET);
                    } else if (strcasecmp(cptr,"UDP") == 0) {
                        /* default, do nothing */
                    } else {
                        fprintf(stderr,
                                "%s: Unknown transport \"%s\" after -T flag.\n",
                                argv[0], cptr);
                        usage(argv[0]);
                        exit(1);
                    }
                    break;

		case 'D':
                    debug_register_tokens(&argv[arg][2]);
		    snmp_set_do_debugging(1);
		    break;

                case 'p':
                  if (++arg == argc)
                    usage(argv[0]);

                  /* has something been specified before? */
                  cptr = ds_get_string(DS_APPLICATION_ID, DS_AGENT_PORTS);
                      
                  /* set the specification string up */
                  if (cptr)
                      /* append to the older specification string */
                      snprintf(buf, sizeof(buf), "%s,%s", cptr, argv[arg]);
                  else
                      strncpy(buf, argv[arg], sizeof(buf));
                  buf[ sizeof(buf)-1 ] = 0;

                  DEBUGMSGTL(("snmpd_ports","port spec: %s\n", buf));
                  ds_set_string(DS_APPLICATION_ID, DS_AGENT_PORTS, buf);
                  break;

#if defined(USING_AGENTX_SUBAGENT_MODULE) || defined(USING_AGENTX_MASTER_MODULE)
                case 'x':
                  if (++arg == argc)
                    usage(argv[0]);
                  ds_set_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET, argv[arg]);
		  ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_AGENTX_MASTER, 1 );
                  break;
#endif

                case 'X':
#if defined(USING_AGENTX_SUBAGENT_MODULE)
                  agent_mode = SUB_AGENT;
#else
                  fprintf(stderr,"%s: Illegal argument -X: AgentX support not compiled in.\n", argv[0]);
                  usage(argv[0]);
                  exit(1);
#endif
                  break;

		case 'r':
                    ds_toggle_boolean(DS_APPLICATION_ID,
                                      DS_AGENT_NO_ROOT_ACCESS);
		    break;

		case 'U':
                    ds_toggle_boolean(DS_APPLICATION_ID,
                                      DS_AGENT_LEAVE_PIDFILE);
		    break;

                case 'P':
                  if (++arg == argc)
                    usage(argv[0]);
                  pid_file = argv[arg];
		  break;

                case 'a':
		  log_addresses++;
                  break;

                case 'V':
                  ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE, 1);
                  break;

                case 'f':
                  dont_fork = 1;
                  break;

                case 'l':
                  if (++arg == argc) {
                    usage(argv[0]);
		  }
		  if (strlen(argv[arg]) > PATH_MAX) {
		    fprintf(stderr,
			    "%s: logfile path too long (limit %d chars)\n",
			    argv[0], PATH_MAX);
		    exit(1);
		  }
                  strncpy(logfile, argv[arg], PATH_MAX);
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

                case 'I':
                  if (++arg == argc) usage(argv[0]);
                  add_to_init_list(argv[arg]);
                  break;

#if HAVE_UNISTD_H
                case 'u':
                  if (++arg == argc) usage(argv[0]);
		  { char *ecp;
		    int uid;
		    uid = strtoul(argv[arg], &ecp, 10);
		    if (*ecp) {
#if HAVE_GETPWNAM && HAVE_PWD_H
		      struct passwd *info;
		      info = getpwnam(argv[arg]);
		      if (info) uid = info->pw_uid;
		      else {
#endif
			fprintf(stderr, "Bad user id: %s\n", argv[arg]);
			exit(1);
#if HAVE_GETPWNAM && HAVE_PWD_H
		      }
#endif
		    }
		  ds_set_int(DS_APPLICATION_ID, DS_AGENT_USERID, uid);
		}
                  break;
                case 'g':
                  if (++arg == argc) usage(argv[0]);
                  ds_set_int(DS_APPLICATION_ID, DS_AGENT_GROUPID, atoi(argv[arg]));
                  break;
#endif
                case 'h':
                  usage(argv[0]);
                  break;
                case 'H':
                  ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS, 1);
                  init_agent("snmpd");   /* register our .conf handlers */
                  init_mib_modules();
                  init_snmp("snmpd");
                  fprintf(stderr, "Configuration directives understood:\n");
                  read_config_print_usage("  ");
                  exit(0);
                case 'v':
                  printf("\nUCD-snmp version:  %s\n",VersionInfo);
                  printf("Email:             net-snmp-coders@lists.sourceforge.net\n\n");
                  exit (0);
                case '-':
                  switch(argv[arg][2]){
                    case 'v': 
                      printf("\nUCD-snmp version:  %s\n",VersionInfo);
                      printf("Email:             net-snmp-coders@lists.sourceforge.net\n\n");
                      exit (0);
                    case 'h':
                      usage(argv[0]);
                      exit(0);
                  }

                default:
                  fprintf(stderr, "%s: Invalid option: %s\n", argv[0], argv[arg]);
                  usage(argv[0]);
                  break;
              }
              continue;
            }
	    else {
	      fprintf(stderr, "%s: Bad argument: %s\n", argv[0], argv[arg]);
	      exit(1);
	    }
	}  /* end-for */

	setup_log(0, dont_zero_log, stderr_log, syslog_log, logfile);

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
        if (!argvrestartp || !argvrestart || !argvrestartname) {
            fprintf(stderr, "malloc failure processing argvrestart\n");
            exit(1);
        }
	strcpy(argvrestartname, argv[0]);
        if (agent_mode == -1) {
            if ( strstr(argvrestartname, "agentxd") != NULL )
                ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, SUB_AGENT);
            else
                ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, MASTER_AGENT);
        } else {
            ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, agent_mode);
        }
        
	for (cptr = argvrestart, i = 0; i < argc; i++) {
		strcpy(cptr, argv[i]);
		*(argvptr++) = cptr;
		cptr += strlen(argv[i]) + 1;
	}
	*cptr = 0;
	*argvptr = NULL;

#ifdef BUFSIZ
	setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
#endif
    /* 
     * Initialize the world.  Detach from the shell.
     * Create initial user.
     */
#if HAVE_FORK
    if (!dont_fork && fork() != 0) {
      exit(0);
    }
#endif

#if defined(SIGPIPE) && defined(SIG_IGN)
    signal(SIGPIPE, SIG_IGN);  /* 'Inline' failure of wayward readers */
#endif

    SOCK_STARTUP;
    init_agent("snmpd");		/* do what we need to do first. */
    init_mib_modules();
    

    /* start library */
    init_snmp("snmpd");

    ret = init_master_agent( 0,
                       snmp_check_packet,
                       snmp_check_parse );
	if( ret != 0 )
		Exit(1); /* Exit logs exit val for us */

#ifdef SIGTERM
    signal(SIGTERM, SnmpdShutDown);
#endif
#ifdef SIGINT
    signal(SIGINT, SnmpdShutDown);
#endif
#ifdef SIGHUP
    signal(SIGHUP, SnmpdReconfig);
#endif
#ifdef SIGUSR1
    signal(SIGUSR1, SnmpdDump);
#endif

    /* store persistent data immediately in case we crash later */
    snmp_store("snmpd");

    /* send coldstart trap via snmptrap(1) if possible */
    send_easy_trap (0, 0);
        
#if HAVE_GETPID
    if (pid_file != NULL) {
      if ((PID = fopen(pid_file, "w")) == NULL) {
        snmp_log_perror("fopen");
        if (!ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS))
          exit(1);
      }
      else {
        fprintf(PID, "%d\n", (int)getpid());
        fclose(PID);
      }
    }
#endif

#if HAVE_UNISTD_H
#ifdef HAVE_SETGID
	if ((gid = ds_get_int(DS_APPLICATION_ID, DS_AGENT_GROUPID)) != 0) {
		DEBUGMSGTL(("snmpd", "Changing gid to %d.\n", gid));
		if (setgid(gid)==-1
#ifdef HAVE_SETGROUPS
		 || setgroups(1, &gid)==-1
#endif
		) {
			snmp_log_perror("setgid failed");
			if (!ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS))
			    exit(1);
		}
	}
#endif
#ifdef HAVE_SETUID
	if ((uid = ds_get_int(DS_APPLICATION_ID, DS_AGENT_USERID)) != 0) {
		DEBUGMSGTL(("snmpd", "Changing uid to %d.\n", uid));
		if(setuid(uid)==-1) {
			snmp_log_perror("setuid failed");
			if (!ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS))
			    exit(1);
		}
	}
#endif
#endif

	/* we're up, log our version number */
	snmp_log(LOG_INFO, "UCD-SNMP version %s\n", VersionInfo);
#ifdef WIN32
	/* SNMP Agent started, set the status to running */
	agent_status = AGENT_RUNNING;
#endif	
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
	snmp_shutdown("snmpd");
	if (!ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_LEAVE_PIDFILE) &&
            (pid_file != NULL)) {
            unlink(pid_file);
        }
#ifdef WIN32
	agent_status = AGENT_STOPPED; 
#endif
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
    fd_set readfds, writefds, exceptfds;
    struct timeval	timeout, *tvp = &timeout;
    struct timeval	sched,   *svp = &sched,
			now,     *nvp = &now;
    int count, block, i;
#ifdef	USING_SMUX_MODULE
    int sd;
#endif	/* USING_SMUX_MODULE */


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
	    snmp_log(LOG_INFO, "Reconfiguring daemon\n");
	    /*  Stop and restart logging.  This allows logfiles to be
		rotated etc.  */
	    snmp_disable_log();
	    setup_log(1, 0, 0, 0, NULL);
	    snmp_log(LOG_INFO, "UCD-SNMP version %s restarted\n", VersionInfo);
	    update_config();
        }

	for (i = 0; i < NUM_EXTERNAL_SIGS; i++) {
	    if (external_signal_scheduled[i]) {
		external_signal_scheduled[i]--;
		external_signal_handler[i](i);
	    }
	}

	tvp =  &timeout;
	tvp->tv_sec = 0;
	tvp->tv_usec = TIMETICK;

	numfds = 0;
	FD_ZERO(&readfds);
	FD_ZERO(&writefds);
	FD_ZERO(&exceptfds);
        block = 0;
        snmp_select_info(&numfds, &readfds, tvp, &block);
        if (block == 1)
            tvp = NULL; /* block without timeout */

#ifdef	USING_SMUX_MODULE
	if (smux_listen_sd >= 0) {
	    FD_SET(smux_listen_sd, &readfds);
	    numfds = smux_listen_sd >= numfds ? smux_listen_sd + 1 : numfds;
	    for (i = 0; i < sdlen; i++) {
		FD_SET(sdlist[i], &readfds);
		numfds = sdlist[i] >= numfds ? sdlist[i] + 1 : numfds;
	    }
	}
#endif	/* USING_SMUX_MODULE */

	for (i = 0; i < external_readfdlen; i++) {
	    FD_SET(external_readfd[i], &readfds);
	    if (external_readfd[i] >= numfds)
		numfds = external_readfd[i] + 1;
	}
	for (i = 0; i < external_writefdlen; i++) {
	    FD_SET(external_writefd[i], &writefds);
	    if (external_writefd[i] >= numfds)
		numfds = external_writefd[i] + 1;
	}
	for (i = 0; i < external_exceptfdlen; i++) {
	    FD_SET(external_exceptfd[i], &exceptfds);
	    if (external_exceptfd[i] >= numfds)
		numfds = external_exceptfd[i] + 1;
	}
	
reselect:
	count = select(numfds, &readfds, &writefds, &exceptfds, tvp);

#ifdef WIN32
        /*
         * Check if select() returned on signal. 
         * In case of windows to return from select() on signal, closesocket 
         * is used which causes the select() to return with count>0.  
        */
	if(!running)
	   break;
#endif

	if (count > 0) {

#ifdef USING_SMUX_MODULE 
            /* handle the SMUX sd's */ 
            if (smux_listen_sd >= 0) { 
                for (i = 0; i < sdlen; i++) { 
                    if (FD_ISSET(sdlist[i], &readfds)) { 
                        if (smux_process(sdlist[i]) < 0) { 
                            for (; i < (sdlen - 1); i++) { 
                                sdlist[i] = sdlist[i+1]; 
                            } 
                            sdlen--; 
                        } 
                    } 
                } 
                /* new connection */ 
                if (FD_ISSET(smux_listen_sd, &readfds)) { 
                    if ((sd = smux_accept(smux_listen_sd)) >= 0) { 
                        sdlist[sdlen++] = sd; 
                    } 
                } 
            } 
#endif /* USING_SMUX_MODULE */ 

	    snmp_read(&readfds);

	    for (i = 0; count && (i < external_readfdlen); i++) {
		if (FD_ISSET(external_readfd[i], &readfds)) {
		    external_readfdfunc[i](external_readfd[i],
					   external_readfd_data[i]);
		    FD_CLR(external_readfd[i], &readfds);
		    count--;
		}
	    }
	    for (i = 0; count && (i < external_writefdlen); i++) {
		if (FD_ISSET(external_writefd[i], &writefds)) {
		    external_writefdfunc[i](external_writefd[i],
					    external_writefd_data[i]);
		    FD_CLR(external_writefd[i], &writefds);
		    count--;
		}
	    }
	    for (i = 0; count && (i < external_exceptfdlen); i++) {
		if (FD_ISSET(external_exceptfd[i], &exceptfds)) {
		    external_exceptfdfunc[i](external_exceptfd[i],
					     external_exceptfd_data[i]);
		    FD_CLR(external_exceptfd[i], &exceptfds);
		    count--;
		}
	    }
	    
	} else switch (count) {
	    case 0:
                snmp_timeout();
                break;
	    case -1:
		if (errno == EINTR) {
		    /*
		     * Likely we got a signal - check before retrying select
		     */
		    if (running & !reconfig)
                        goto reselect;
		    continue;
		} else {
                    snmp_log_perror("select");
		}
		return -1;
	    default:
		snmp_log(LOG_ERR, "select returned %d\n", count);
		return -1;
	}  /* endif -- count>0 */




        /*
         * If the time 'now' is greater than the 'sched'uled time, then:
         *
         *    Check alarm and event timers.
         *    Reset the 'sched'uled time to current time + one TIMETICK.
         *    Age the cache network addresses (from whom messges have
         *        been received).
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

        /* run requested alarms */
        run_alarms();
        
    }  /* endwhile */

    snmp_log(LOG_INFO, "Received TERM or STOP signal...  shutting down...\n");
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
    const char *addr_string;
    /*
     * Log the message and/or dump the message.
     * Optionally cache the network address of the sender.
     */
    addr_string = inet_ntoa(fromIp->sin_addr);

    if(!addr_string) {
      addr_string = STRING_UNKNOWN;
    }
    if(hosts_ctl("snmpd", addr_string, addr_string, STRING_UNKNOWN)) {
      snmp_log(allow_severity, "Connection from %s\n", addr_string);
    } else {
      snmp_log(deny_severity, "Connection from %s REFUSED\n", addr_string);
      return(0);
    }
#endif	/* USE_LIBWRAP */

    snmp_increment_statistic(STAT_SNMPINPKTS);

    if (log_addresses || ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE)){
	int count;
	
	for(count = 0; count < ADDRCACHE; count++){
	    if (addrCache[count].status > UNUSED /* used or old */
		&& fromIp->sin_addr.s_addr == addrCache[count].addr)
		break;
	}

	if (count >= ADDRCACHE ||
            ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE)){
	    snmp_log(LOG_INFO, "Received SNMP packet(s) from %s\n",
                        inet_ntoa(fromIp->sin_addr));
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
        if ( ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE) &&
             snmp_get_do_logging() ) {
	     char c_oid [SPRINT_MAX_LEN];
	     struct variable_list *var_ptr;
	    
	    switch (pdu->command) {
	    case SNMP_MSG_GET:
	    	snmp_log(LOG_DEBUG, "  GET message\n"); break;
	    case SNMP_MSG_GETNEXT:
	    	snmp_log(LOG_DEBUG, "  GETNEXT message\n"); break;
	    case SNMP_MSG_RESPONSE:
	    	snmp_log(LOG_DEBUG, "  RESPONSE message\n"); break;
	    case SNMP_MSG_SET:
	    	snmp_log(LOG_DEBUG, "  SET message\n"); break;
	    case SNMP_MSG_TRAP:
	    	snmp_log(LOG_DEBUG, "  TRAP message\n"); break;
	    case SNMP_MSG_GETBULK:
	    	snmp_log(LOG_DEBUG, "  GETBULK message, non-rep=%d, max_rep=%d\n",
			pdu->errstat, pdu->errindex); break;
	    case SNMP_MSG_INFORM:
	    	snmp_log(LOG_DEBUG, "  INFORM message\n"); break;
	    case SNMP_MSG_TRAP2:
	    	snmp_log(LOG_DEBUG, "  TRAP2 message\n"); break;
	    case SNMP_MSG_REPORT:
	    	snmp_log(LOG_DEBUG, "  REPORT message\n"); break;
	    }
	     
	    for ( var_ptr = pdu->variables ;
	        var_ptr != NULL ; var_ptr=var_ptr->next_variable )
	    {
                snprint_objid (c_oid, sizeof(c_oid),
                               var_ptr->name, var_ptr->name_length);
                snmp_log(LOG_DEBUG, "    -- %s\n", c_oid);
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

} /* end snmp_input() */



/* Windows Service Related functions */
#ifdef WIN32
/************************************************************
* main function for Windows
* Parse command line arguments for startup options,
* to start as service or console mode application in windows.
* Invokes appropriate startup funcitons depending on the 
* parameters passesd
*************************************************************/
int
__cdecl _tmain(int argc, TCHAR *argv[])
{

	/* Define Service Name and Description, which appears in windows SCM */
	LPCTSTR lpszServiceName = g_szAppName; /* Service Registry Name */
	LPCTSTR lpszServiceDisplayName = _T("Net SNMP Agent Daemon"); /* Display Name */
	LPCTSTR lpszServiceDescription = _T("SNMP agent for windows from Net-SNMP");
	InputParams InputOptions;


	int nRunType = RUN_AS_CONSOLE;
	nRunType = ParseCmdLineForServiceOption(argc,argv);

	switch(nRunType)
	{
		case REGISTER_SERVICE:
			/* Register As service */
			InputOptions.Argc = argc;
			InputOptions.Argv = argv;
			RegisterService(lpszServiceName,
							lpszServiceDisplayName,
							lpszServiceDescription,
							&InputOptions);
			exit(0);
			break;
		case UN_REGISTER_SERVICE:
			/* Unregister service */
			UnregisterService(lpszServiceName);
			exit(0);
			break;
		case RUN_AS_SERVICE:
			/* Run as service */
			/* Register Stop Function */
			RegisterStopFunction(StopSnmpAgent);
			return RunAsService(SnmpDaemonMain);
			break;
		default:
			/* Run Net-Snmpd in console mode */
			/* Invoke SnmpDeamonMain with input arguments */
			return SnmpDaemonMain(argc,argv);
			break;
	}
}

/*
 * To stop Snmp Agent deamon 
 * This portion is still not working
 */
void StopSnmpAgent(void)
{
	/* Shut Down Agent */
	SnmpdShutDown(1);

	/* Wait till agent is completely stopped */

	while(agent_status != AGENT_STOPPED)
	{
		Sleep(100);
	}
}

#endif   /* if WIN32 */

