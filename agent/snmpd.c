/*
 * snmpd.c
 */
/** @defgroup agent The snmp agent
 * The snmp agent responds to SNMP queries from management stations
 */
/*
 * Copyright 1988, 1989 by Carnegie Mellon University
 * 
 * All Rights Reserved
 * 
 * Permission to use, copy, modify, and distribute this software and its 
 * documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appear in all copies and that
 * both that copyright notice and this permission notice appear in 
 * supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.  
 * 
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 * *****************************************************************
 */
#include <net-snmp/net-snmp-config.h>

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
#if HAVE_PROCESS_H              /* Win32-getpid */
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

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>

#include "m2m.h"
#include <net-snmp/agent/mib_module_config.h>

#include "snmpd.h"
#include "mibgroup/struct.h"
#include <net-snmp/agent/mib_modules.h>

#include "mibgroup/util_funcs.h"

#include <net-snmp/agent/agent_trap.h>

#include <net-snmp/agent/table.h>
#include <net-snmp/agent/table_iterator.h>
#include "mib_module_includes.h"

/*
 * Include winservice.h to support Windows Service
 */
#ifdef WIN32
#include <windows.h>
#include <tchar.h>
#include <net-snmp/library/winservice.h>
#endif

/*
 * Globals.
 */
#ifdef USE_LIBWRAP
#include <tcpd.h>

int             allow_severity = LOG_INFO;
int             deny_severity = LOG_WARNING;
#endif                          /* USE_LIBWRAP */

#define TIMETICK         500000L
#define ONE_SEC         1000000L

int             snmp_dump_packet;
int             running = 1;
int             reconfig = 0;

#ifdef WIN32
/*
 * SNMP Agent Status 
 */
#define AGENT_RUNNING 1
#define AGENT_STOPPED 0
int             agent_status = AGENT_STOPPED;
LPTSTR          g_szAppName = _T("Net-Snmp Agent");     /* Application Name */
#endif

extern char   **argvrestartp;
extern char    *argvrestart;
extern char    *argvrestartname;

#define NUM_SOCKETS	32

#ifdef USING_SMUX_MODULE
static int      sdlist[NUM_SOCKETS], sdlen = 0;
#endif                          /* USING_SMUX_MODULE */

/*
 * Prototypes.
 */
int             snmp_read_packet(int);
int             snmp_input(int, netsnmp_session *, int, netsnmp_pdu *,
                           void *);
static void     usage(char *);
static void     SnmpTrapNodeDown(void);
static int      receive(void);
#ifdef WIN32
void            StopSnmpAgent(void);
int             SnmpDaemonMain(int argc, TCHAR * argv[]);
int __cdecl     _tmain(int argc, TCHAR * argv[]);
#else
int             main(int, char **);
#endif

static void
usage(char *prog)
{
#ifdef WIN32
    printf("\nUsage:  %s [-register] [OPTIONS] [LISTENING ADDRESSES]",
           prog);
    printf("\n        %s -unregister", prog);
#else
    printf("\nUsage:  %s [OPTIONS] [LISTENING ADDRESSES]", prog);
#endif
    printf("\n");
    printf("\n\tVersion:  %s\n", netsnmp_get_version());
    printf("\tWeb:      http://www.net-snmp.org/\n");
    printf("\tEmail:    net-snmp-coders@lists.sourceforge.net\n");
    printf("\n  -a\t\t\tlog addresses\n");
    printf("  -A\t\t\tappend to the logfile rather than truncating it\n");
    printf("  -c FILE\t\tread FILE as a configuration file\n");
    printf("  -C\t\t\tdo not read the default configuration files\n");
    printf("  -d\t\t\tdump sent and received SNMP packets\n");
    printf("  -D\t\t\tturn on debugging output\n");
    printf("  -f\t\t\tdo not fork from the shell\n");
#if HAVE_UNISTD_H
    printf
        ("  -g GID\t\tchange to this numeric gid after opening\n\t\t\t  transport endpoints\n");
#endif
    printf("  -h, --help\t\tdisplay this usage message\n");
    printf("  -H\t\t\tdisplay configuration file directives understood\n");
    printf
        ("  -I [-]INITLIST\tlist of mib modules to initialize (or not)\n");
    printf("\t\t\t  (run snmpd with -Dmib_init for a list)\n");
    printf("  -l FILE\t\tprint warnings/messages to FILE\n");
#ifdef LOGFILE
    printf("\t\t\t  (by default FILE=%s)\n", LOGFILE);
#else
    printf("\t\t\t  (by default FILE=none)\n");
#endif
    printf("  -L\t\t\tprint warnings/messages to stdout/err\n");
    printf("  -P FILE\t\tstore process id in FILE\n");
    printf("  -q\t\t\tprint information in a more parsable format\n");
    printf
        ("  -r\t\t\tdo not exit if files only accessible to root\n\t\t\t  cannot be opened\n");
#ifdef WIN32
    printf("  -register\t\tregister as a Windows service\n");
    printf("  \t\t\t  (followed by the startup parameter list)\n");
    printf
        ("  \t\t\t  Note that not all parameters are relevant when running as a service\n");
#endif
    printf("  -s\t\t\tlog warnings/messages to syslog\n");
#if HAVE_UNISTD_H
    printf
        ("  -u UID\t\tchange to this uid (numeric or textual) after\n\t\t\t  opening transport endpoints\n");
#endif
#ifdef WIN32
    printf("  -unregister\t\tunregister as a Windows service\n");
#endif
    printf("  -v, --version\t\tdisplay version information\n");
    printf("  -V\t\t\tverbose display\n");
#if defined(USING_AGENTX_SUBAGENT_MODULE)|| defined(USING_AGENTX_MASTER_MODULE)
    printf("  -x ADDRESS\t\tuse ADDRESS as AgentX address\n");
#endif
#ifdef USING_AGENTX_SUBAGENT_MODULE
    printf
        ("  -X\t\t\trun as an AgentX subagent rather than as an\n\t\t\t  SNMP master agent\n");
#endif

    printf("\n");
    exit(1);
}

static void
version(void)
{
    printf("\nNET-SNMP version:  %s\n", netsnmp_get_version());
    printf("Web:               http://www.net-snmp.org/\n");
    printf("Email:             net-snmp-coders@lists.sourceforge.net\n\n");
    exit(0);
}

RETSIGTYPE
SnmpdShutDown(int a)
{
    extern netsnmp_session *main_session;
    running = 0;
#ifdef WIN32
    /*
     * In case of windows, select() in receive() function will not return 
     * on signal. Thats why following function is called, which closes the 
     * socket descriptors and causes the select() to return
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
extern void     dump_registry(void);
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
    send_easy_trap(SNMP_TRAP_ENTERPRISESPECIFIC, 2);
    /*
     * XXX  2 - Node Down #define it as NODE_DOWN_TRAP 
     */
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
SnmpDaemonMain(int argc, TCHAR * argv[])
#else
main(int argc, char *argv[])
#endif
{
    char            options[128] = "aAc:CdD::fhHI:l:LP:qrsvV-:";
    int             arg, i, ret;
    int             dont_fork = 0;
    int             dont_zero_log = 0;
    int             stderr_log = 0, syslog_log = 0;
    int             uid = 0, gid = 0;
    int             agent_mode = -1;
    char            logfile[PATH_MAX + 1] = { 0 };
    char           *cptr, **argvptr;
    char           *pid_file = NULL;
#if HAVE_GETPID
    FILE           *PID;
#endif

#ifdef LOGFILE
    strncpy(logfile, LOGFILE, PATH_MAX);
#endif

#ifdef NO_ROOT_ACCESS
    /*
     * Default to no.  
     */
    ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS, 1);
#endif
    /*
     * Default to NOT running an AgentX master.  
     */
    ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_AGENTX_MASTER, 0);

    /*
     * Add some options if they are available.  
     */
#if HAVE_UNISTD_H
    strcat(options, "g:u:");
#endif
#if defined(USING_AGENTX_SUBAGENT_MODULE)|| defined(USING_AGENTX_MASTER_MODULE)
    strcat(options, "x:");
#endif
#ifdef USING_AGENTX_SUBAGENT_MODULE
    strcat(options, "X");
#endif

    /*
     * Now process options normally.  
     */

    while ((arg = getopt(argc, argv, options)) != EOF) {
        switch (arg) {
        case '-':
            if (strcasecmp(optarg, "help") == 0) {
                usage(argv[0]);
            }
            if (strcasecmp(optarg, "version") == 0) {
                version();
            }

            handle_long_opt(optarg);
            break;

        case 'a':
            log_addresses++;
            break;

        case 'A':
            dont_zero_log = 1;
            break;

        case 'c':
            if (optarg != NULL) {
                ds_set_string(DS_LIBRARY_ID, DS_LIB_OPTIONALCONFIG,
                              optarg);
            } else {
                usage(argv[0]);
            }
            break;

        case 'C':
            ds_set_boolean(DS_LIBRARY_ID, DS_LIB_DONT_READ_CONFIGS, 1);
            break;

        case 'd':
            snmp_set_dump_packet(++snmp_dump_packet);
            ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE, 1);
            break;

        case 'D':
            debug_register_tokens(optarg);
            snmp_set_do_debugging(1);
            break;

        case 'f':
            dont_fork = 1;
            break;

#if HAVE_UNISTD_H
        case 'g':
            if (optarg != NULL) {
                ds_set_int(DS_APPLICATION_ID, DS_AGENT_GROUPID,
                           atoi(optarg));
            } else {
                usage(argv[0]);
            }
            break;
#endif

        case 'h':
            usage(argv[0]);
            break;

        case 'H':
            ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS, 1);
            init_agent("snmpd");        /* register our .conf handlers */
            init_mib_modules();
            init_snmp("snmpd");
            fprintf(stderr, "Configuration directives understood:\n");
            read_config_print_usage("  ");
            exit(0);

        case 'I':
            if (optarg != NULL) {
                add_to_init_list(optarg);
            } else {
                usage(argv[0]);
            }
            break;

        case 'l':
            if (optarg != NULL) {
                if (strlen(optarg) > PATH_MAX) {
                    fprintf(stderr,
                            "%s: logfile path too long (limit %d chars)\n",
                            argv[0], PATH_MAX);
                    exit(1);
                }
                strncpy(logfile, optarg, PATH_MAX);
            } else {
                usage(argv[0]);
            }
            break;

        case 'L':
            stderr_log = 1;
            break;

        case 'P':
            if (optarg != NULL) {
                pid_file = optarg;
            } else {
                usage(argv[0]);
            }
            break;

        case 'q':
            snmp_set_quick_print(1);
            break;

        case 'r':
            ds_toggle_boolean(DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS);
            break;

        case 's':
            syslog_log = 1;
            break;

#if HAVE_UNISTD_H
        case 'u':
            if (optarg != NULL) {
                char           *ecp;
                int             uid;

                uid = strtoul(optarg, &ecp, 10);
                if (*ecp) {
#if HAVE_GETPWNAM && HAVE_PWD_H
                    struct passwd  *info;
                    info = getpwnam(argv[arg]);
                    if (info) {
                        uid = info->pw_uid;
                    } else {
#endif
                        fprintf(stderr, "Bad user id: %s\n", optarg);
                        exit(1);
#if HAVE_GETPWNAM && HAVE_PWD_H
                    }
#endif
                }
                ds_set_int(DS_APPLICATION_ID, DS_AGENT_USERID, uid);
            } else {
                usage(argv[0]);
            }
            break;
#endif

        case 'v':
            version();

        case 'V':
            ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_VERBOSE, 1);
            break;

#if defined(USING_AGENTX_SUBAGENT_MODULE)|| defined(USING_AGENTX_MASTER_MODULE)
        case 'x':
            if (optarg != NULL) {
                ds_set_string(DS_APPLICATION_ID, DS_AGENT_X_SOCKET,
                              optarg);
            } else {
                usage(argv[0]);
            }
            ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_AGENTX_MASTER, 1);
            break;
#endif

        case 'X':
#if defined(USING_AGENTX_SUBAGENT_MODULE)
            agent_mode = SUB_AGENT;
#else
            fprintf(stderr,
                    "%s: Illegal argument -X: AgentX support not compiled in.\n",
                    argv[0]);
            usage(argv[0]);
            exit(1);
#endif
            break;

        default:
            fprintf(stderr, "%s: Invalid option: -%c\n", argv[0], arg);
            usage(argv[0]);
            break;
        }
    }

    if (optind < argc) {
        /*
         * There are optional transport addresses on the command line.  
         */
        DEBUGMSGTL(("snmpd/main", "optind %d, argc %d\n", optind, argc));
        for (i = optind; i < argc; i++) {
            char           *c, *astring;
            if ((c = ds_get_string(DS_APPLICATION_ID, DS_AGENT_PORTS))) {
                astring = malloc(strlen(c) + 2 + strlen(argv[i]));
                if (astring == NULL) {
                    fprintf(stderr, "malloc failure processing argv[%d]\n",
                            i);
                    exit(1);
                }
                sprintf(astring, "%s,%s", c, argv[i]);
                ds_set_string(DS_APPLICATION_ID, DS_AGENT_PORTS, astring);
                free(astring);
            } else {
                ds_set_string(DS_APPLICATION_ID, DS_AGENT_PORTS, argv[i]);
            }
        }
        DEBUGMSGTL(("snmpd/main", "port spec: %s\n",
                    ds_get_string(DS_APPLICATION_ID, DS_AGENT_PORTS)));
    }

    /*
     * Honor selection of standard error output.  
     */
    if (!stderr_log) {
        snmp_disable_stderrlog();
    }

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
    if (agent_mode == -1) {
        if (strstr(argvrestartname, "agentxd") != NULL) {
            ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, SUB_AGENT);
        } else {
            ds_set_boolean(DS_APPLICATION_ID, DS_AGENT_ROLE, MASTER_AGENT);
        }
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

    /*
     * Open the logfile if necessary.  
     */

    /*
     * Should open logfile and/or syslog based on arguments.  
     */
    if (logfile[0]) {
        snmp_enable_filelog(logfile, dont_zero_log);
    }

    if (syslog_log) {
        snmp_enable_syslog();
    }
#ifdef BUFSIZ
    setvbuf(stdout, NULL, _IOLBF, BUFSIZ);
#endif
    /*
     * Initialize the world.  Detach from the shell.  Create initial user.  
     */
#if HAVE_FORK
    if (!dont_fork && fork() != 0 &&
        !ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_QUIT_IMMEDIATELY)
        ) {
        exit(0);
    }
#endif

#if HAVE_GETPID
    if (pid_file != NULL) {
        if ((PID = fopen(pid_file, "w")) == NULL) {
            snmp_log_perror("fopen");
            if (!ds_get_boolean
                (DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS)) {
                exit(1);
            }
        } else {
            fprintf(PID, "%d\n", (int) getpid());
            fclose(PID);
        }
    }
#endif

    SOCK_STARTUP;
    init_agent("snmpd");        /* do what we need to do first. */
    init_mib_modules();

    /*
     * start library 
     */
    init_snmp("snmpd");

    if ((ret = init_master_agent()) != 0) {
        /*
         * Some error opening one of the specified agent transports.  
         */
        Exit(1);                /*  Exit logs exit val for us  */
    }
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
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);   /* 'Inline' failure of wayward readers */
#endif

    /*
     * Store persistent data immediately in case we crash later.  
     */
    snmp_store("snmpd");

    /*
     * Send coldstart trap if possible.  
     */
    send_easy_trap(0, 0);

#if HAVE_UNISTD_H
#ifdef HAVE_SETGID
    if ((gid = ds_get_int(DS_APPLICATION_ID, DS_AGENT_GROUPID)) != 0) {
        DEBUGMSGTL(("snmpd/main", "Changing gid to %d.\n", gid));
        if (setgid(gid) == -1
#ifdef HAVE_SETGROUPS
            || setgroups(1, &gid) == -1
#endif
            ) {
            snmp_log_perror("setgid failed");
            if (!ds_get_boolean
                (DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS)) {
                exit(1);
            }
        }
    }
#endif
#ifdef HAVE_SETUID
    if ((uid = ds_get_int(DS_APPLICATION_ID, DS_AGENT_USERID)) != 0) {
        DEBUGMSGTL(("snmpd/main", "Changing uid to %d.\n", uid));
        if (setuid(uid) == -1) {
            snmp_log_perror("setuid failed");
            if (!ds_get_boolean
                (DS_APPLICATION_ID, DS_AGENT_NO_ROOT_ACCESS)) {
                exit(1);
            }
        }
    }
#endif
#endif

    /*
     * We're up, log our version number.  
     */
    snmp_log(LOG_INFO, "NET-SNMP version %s\n", netsnmp_get_version());
#ifdef WIN32
    agent_status = AGENT_RUNNING;
#endif
    netsnmp_addrcache_initialise();

    /*
     * Forever monitor the dest_port for incoming PDUs.  
     */
    DEBUGMSGTL(("snmpd/main", "We're up.  Starting to process data.\n"));
    if (!ds_get_boolean(DS_APPLICATION_ID, DS_AGENT_QUIT_IMMEDIATELY))
        receive();
#include "mib_module_shutdown.h"
    DEBUGMSGTL(("snmpd/main", "sending shutdown trap\n"));
    SnmpTrapNodeDown();
    DEBUGMSGTL(("snmpd/main", "Bye...\n"));
    snmp_shutdown("snmpd");
#ifdef WIN32
    agent_status = AGENT_STOPPED;
#endif
    return 0;
}                               /* End main() -- snmpd */

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
    int             numfds;
    fd_set          readfds, writefds, exceptfds;
    struct timeval  timeout, *tvp = &timeout;
    struct timeval  sched, *svp = &sched, now, *nvp = &now;
    int             count, block, i;
#ifdef	USING_SMUX_MODULE
    int             sd;
#endif                          /* USING_SMUX_MODULE */


    /*
     * Set the 'sched'uled timeout to the current time + one TIMETICK.
     */
    gettimeofday(nvp, (struct timezone *) NULL);
    svp->tv_usec = nvp->tv_usec + TIMETICK;
    svp->tv_sec = nvp->tv_sec;

    while (svp->tv_usec >= ONE_SEC) {
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
            update_config();
            send_easy_trap(SNMP_TRAP_ENTERPRISESPECIFIC, 3);
        }

        for (i = 0; i < NUM_EXTERNAL_SIGS; i++) {
            if (external_signal_scheduled[i]) {
                external_signal_scheduled[i]--;
                external_signal_handler[i] (i);
            }
        }

        tvp = &timeout;
        tvp->tv_sec = 0;
        tvp->tv_usec = TIMETICK;

        numfds = 0;
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        FD_ZERO(&exceptfds);
        block = 0;
        snmp_select_info(&numfds, &readfds, tvp, &block);
        if (block == 1)
            tvp = NULL;         /* block without timeout */

#ifdef	USING_SMUX_MODULE
        if (smux_listen_sd >= 0) {
            FD_SET(smux_listen_sd, &readfds);
            numfds =
                smux_listen_sd >= numfds ? smux_listen_sd + 1 : numfds;
            for (i = 0; i < sdlen; i++) {
                FD_SET(sdlist[i], &readfds);
                numfds = sdlist[i] >= numfds ? sdlist[i] + 1 : numfds;
            }
        }
#endif                          /* USING_SMUX_MODULE */

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

        count = select(numfds, &readfds, &writefds, &exceptfds, tvp);
        DEBUGMSGTL(("snmpd/select", "returned, count = %d\n", count));

        if (count > 0) {

#ifdef USING_SMUX_MODULE
            /*
             * handle the SMUX sd's 
             */
            if (smux_listen_sd >= 0) {
                for (i = 0; i < sdlen; i++) {
                    if (FD_ISSET(sdlist[i], &readfds)) {
                        if (smux_process(sdlist[i]) < 0) {
                            for (; i < (sdlen - 1); i++) {
                                sdlist[i] = sdlist[i + 1];
                            }
                            sdlen--;
                        }
                    }
                }
                /*
                 * new connection 
                 */
                if (FD_ISSET(smux_listen_sd, &readfds)) {
                    if ((sd = smux_accept(smux_listen_sd)) >= 0) {
                        sdlist[sdlen++] = sd;
                    }
                }
            }
#endif                          /* USING_SMUX_MODULE */

            snmp_read(&readfds);

            for (i = 0; count && (i < external_readfdlen); i++) {
                if (FD_ISSET(external_readfd[i], &readfds)) {
                    external_readfdfunc[i] (external_readfd[i],
                                            external_readfd_data[i]);
                    FD_CLR(external_readfd[i], &readfds);
                    count--;
                }
            }
            for (i = 0; count && (i < external_writefdlen); i++) {
                if (FD_ISSET(external_writefd[i], &writefds)) {
                    external_writefdfunc[i] (external_writefd[i],
                                             external_writefd_data[i]);
                    FD_CLR(external_writefd[i], &writefds);
                    count--;
                }
            }
            for (i = 0; count && (i < external_exceptfdlen); i++) {
                if (FD_ISSET(external_exceptfd[i], &exceptfds)) {
                    external_exceptfdfunc[i] (external_exceptfd[i],
                                              external_exceptfd_data[i]);
                    FD_CLR(external_exceptfd[i], &exceptfds);
                    count--;
                }
            }

        } else
            switch (count) {
            case 0:
                snmp_timeout();
                break;
            case -1:
                if (errno == EINTR) {
                    continue;
                } else {
                    snmp_log_perror("select");
                }
                return -1;
            default:
                snmp_log(LOG_ERR, "select returned %d\n", count);
                return -1;
            }                   /* endif -- count>0 */




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
            || (nvp->tv_sec == svp->tv_sec
                && nvp->tv_usec > svp->tv_usec)) {
            svp->tv_usec = nvp->tv_usec + TIMETICK;
            svp->tv_sec = nvp->tv_sec;

            while (svp->tv_usec >= ONE_SEC) {
                svp->tv_usec -= ONE_SEC;
                svp->tv_sec++;
            }
            if (log_addresses && lastAddrAge++ > 600) {
                netsnmp_addrcache_age();
            }
        }

        /*
         * endif -- now>sched 
         */
        /*
         * run requested alarms 
         */
        run_alarms();

        netsnmp_check_outstanding_agent_requests();

    }                           /* endwhile */

    snmp_log(LOG_INFO,
             "Received TERM or STOP signal...  shutting down...\n");
    return 0;

}                               /* end receive() */



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
           netsnmp_session * session,
           int reqid, netsnmp_pdu *pdu, void *magic)
{
    struct get_req_state *state = (struct get_req_state *) magic;

    if (op == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
        if (pdu->command == SNMP_MSG_GET) {
            if (state->type == EVENT_GET_REQ) {
                /*
                 * this is just the ack to our inform pdu 
                 */
                return 1;
            }
        }
    } else if (op == NETSNMP_CALLBACK_OP_TIMED_OUT) {
        if (state->type == ALARM_GET_REQ) {
            /*
             * Need a mechanism to replace obsolete SNMPv2p alarm 
             */
        }
    }
    return 1;

}                               /* end snmp_input() */



/*
 * Windows Service Related functions 
 */
#ifdef WIN32
/************************************************************
* main function for Windows
* Parse command line arguments for startup options,
* to start as service or console mode application in windows.
* Invokes appropriate startup funcitons depending on the 
* parameters passesd
*************************************************************/
int
    __cdecl
_tmain(int argc, TCHAR * argv[])
{

    /*
     * Define Service Name and Description, which appears in windows SCM 
     */
    LPCTSTR         lpszServiceName = g_szAppName;      /* Service Registry Name */
    LPCTSTR         lpszServiceDisplayName = _T("Net SNMP Agent Daemon");       /* Display Name */
    LPCTSTR         lpszServiceDescription =
        _T("SNMP agent for windows from Net-SNMP");
    InputParams     InputOptions;


    int             nRunType = RUN_AS_CONSOLE;
    nRunType = ParseCmdLineForServiceOption(argc, argv);

    switch (nRunType) {
    case REGISTER_SERVICE:
        /*
         * Register As service 
         */
        InputOptions.Argc = argc;
        InputOptions.Argv = argv;
        RegisterService(lpszServiceName,
                        lpszServiceDisplayName,
                        lpszServiceDescription, &InputOptions);
        exit(0);
        break;
    case UN_REGISTER_SERVICE:
        /*
         * Unregister service 
         */
        UnregisterService(lpszServiceName);
        exit(0);
        break;
    case RUN_AS_SERVICE:
        /*
         * Run as service 
         */
        /*
         * Register Stop Function 
         */
        RegisterStopFunction(StopSnmpAgent);
        return RunAsService(SnmpDaemonMain);
        break;
    default:
        /*
         * Run Net-Snmpd in console mode 
         */
        /*
         * Invoke SnmpDeamonMain with input arguments 
         */
        return SnmpDaemonMain(argc, argv);
        break;
    }
}

/*
 * To stop Snmp Agent deamon 
 * This portion is still not working
 */
void
StopSnmpAgent(void)
{
    /*
     * Shut Down Agent 
     */
    SnmpdShutDown(1);

    /*
     * Wait till agent is completely stopped 
     */

    while (agent_status != AGENT_STOPPED) {
        Sleep(100);
    }
}

#endif                          /* if WIN32 */
