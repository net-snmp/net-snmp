/*
 * snmptrapd.c - receive and log snmp traps
 *
 */
/*****************************************************************
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
#include <config.h>

#include <sys/types.h>
#include <sys/socket.h>
#if HAVE_SYS_SOCKIO_H
#include <sys/sockio.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
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
#include <sys/param.h>
#include <errno.h>
#if HAVE_SYSLOG_H
#include <syslog.h>
#endif
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#include <net/if.h>

#include "snmp.h"
#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "party.h"
#include "view.h"
#include "acl.h"

#ifndef BSD4_3
#define BSD4_2
#endif

#ifndef FD_SET

typedef long	fd_mask;
#define NFDBITS	(sizeof(fd_mask) * NBBY)	/* bits per mask */

#define	FD_SET(n, p)	((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define	FD_CLR(n, p)	((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define	FD_ISSET(n, p)	((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#ifdef SVR4
#define FD_ZERO(p)	memset((char *)(p), NULL, sizeof(*(p)))
#else
#define FD_ZERO(p)	bzero((char *)(p), sizeof(*(p)))
#endif
#endif

extern int  errno;
int	snmp_dump_packet = 0;
int Print = 0;
int Event = 0;
int Syslog = 0;
struct timeval Now;

char *
trap_description(trap)
    int trap;
{
    switch(trap){
	case SNMP_TRAP_COLDSTART:
	    return "Cold Start";
	case SNMP_TRAP_WARMSTART:
	    return "Warm Start";
	case SNMP_TRAP_LINKDOWN:
	    return "Link Down";
	case SNMP_TRAP_LINKUP:
	    return "Link Up";
	case SNMP_TRAP_AUTHFAIL:
	    return "Authentication Failure";
	case SNMP_TRAP_EGPNEIGHBORLOSS:
	    return "EGP Neighbor Loss";
	case SNMP_TRAP_ENTERPRISESPECIFIC:
	    return "Enterprise Specific";
	default:
	    return "Unknown Type";
    }
}

char *
uptime_string(timeticks, buf)
    register u_long timeticks;
    char *buf;
{
    int	seconds, minutes, hours, days;

    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (days == 0){
	sprintf(buf, "%d:%02d:%02d", hours, minutes, seconds);
    } else if (days == 1) {
	sprintf(buf, "%d day, %d:%02d:%02d", days, hours, minutes, seconds);
    } else {
	sprintf(buf, "%d days, %d:%02d:%02d", days, hours, minutes, seconds);
    }
    return buf;
}

struct snmp_pdu *
snmp_clone_pdu2(pdu, command)
    struct snmp_pdu *pdu;
    int command;
{
    struct variable_list *var, *newvar;
    struct snmp_pdu *newpdu;

    /* clone the pdu */
    newpdu = (struct snmp_pdu *)malloc(sizeof(struct snmp_pdu));
#ifdef SVR4
    memmove((char *)newpdu, (char *)pdu, sizeof(struct snmp_pdu));
#else
    bcopy((char *)pdu, (char *)newpdu, sizeof(struct snmp_pdu));
#endif
    newpdu->variables = 0;
    newpdu->command = command;
    newpdu->reqid = pdu->reqid;
    newpdu->errstat = SNMP_DEFAULT_ERRSTAT;
    newpdu->errindex = SNMP_DEFAULT_ERRINDEX;
    var = pdu->variables;

    newpdu->variables = newvar = (struct variable_list *)malloc(sizeof(struct variable_list));
#ifdef SVR4
    memmove((char *)newvar, (char *)var, sizeof(struct variable_list));
#else
    bcopy((char *)var, (char *)newvar, sizeof(struct variable_list));
#endif
    if (var->name != NULL){
	newvar->name = (oid *)malloc(var->name_length * sizeof(oid));
#ifdef SVR4
	memmove((char *)newvar->name, (char *)var->name, var->name_length * sizeof(oid));
#else
	bcopy((char *)var->name, (char *)newvar->name, var->name_length * sizeof(oid));
#endif
    }
    if (var->val.string != NULL){
	newvar->val.string = (u_char *)malloc(var->val_len);
#ifdef SVR4
	memmove((char *)newvar->val.string, (char *)var->val.string, var->val_len);
#else
	bcopy((char *)var->val.string, (char *)newvar->val.string, var->val_len);
#endif
    }
    newvar->next_variable = 0;

    while(var->next_variable){
	var = var->next_variable;
	newvar->next_variable = (struct variable_list *)malloc(sizeof(struct variable_list));
	newvar = newvar->next_variable;
#ifdef SVR4
	memmove((char *)newvar, (char *)var, sizeof(struct variable_list));
#else
	bcopy((char *)var, (char *)newvar, sizeof(struct variable_list));
#endif
	if (var->name != NULL){
	    newvar->name = (oid *)malloc(var->name_length * sizeof(oid));
#ifdef SVR4
	    memmove((char *)newvar->name, (char *)var->name, var->name_length * sizeof(oid));
#else
	    bcopy((char *)var->name, (char *)newvar->name, var->name_length * sizeof(oid));
#endif
	}
	if (var->val.string != NULL){
	    newvar->val.string = (u_char *)malloc(var->val_len);
#ifdef SVR4
	    memmove((char *)newvar->val.string, (char *)var->val.string, var->val_len);
#else
	    bcopy((char *)var->val.string, (char *)newvar->val.string, var->val_len);
#endif
	}
	newvar->next_variable = 0;
    }
    return newpdu;
}

static oid risingAlarm[] = {1, 3, 6, 1, 6, 3, 2, 1, 1, 3, 1};
static oid fallingAlarm[] = {1, 3, 6, 1, 6, 3, 2, 1, 1, 3, 2};
static oid unavailableAlarm[] = {1, 3, 6, 1, 6, 3, 2, 1, 1, 3, 3};

event_input(vp)	
    struct variable_list *vp;
{
    int eventid;
    oid variable[MAX_NAME_LEN];
    int variablelen;
    u_long destip;
    int sampletype;
    int value;
    int threshold;

    oid *op;

    vp = vp->next_variable;	/* skip sysUptime */
    if (vp->val_len != sizeof(risingAlarm)
#ifdef SVR4
	|| !memcmp((char *)vp->val.objid, (char *)risingAlarm,
		 sizeof(risingAlarm)))
#else
	|| !bcmp((char *)vp->val.objid, (char *)risingAlarm,
		 sizeof(risingAlarm)))
#endif
	eventid = 1;
    else if (vp->val_len != sizeof(risingAlarm)
#ifdef SVR4
	|| !memcmp((char *)vp->val.objid, (char *)fallingAlarm,
		 sizeof(fallingAlarm)))
#else
	|| !bcmp((char *)vp->val.objid, (char *)fallingAlarm,
		 sizeof(fallingAlarm)))
#endif
	eventid = 2;
    else if (vp->val_len != sizeof(risingAlarm)
#ifdef SVR4
	|| !memcmp((char *)vp->val.objid, (char *)unavailableAlarm,
		 sizeof(unavailableAlarm)))
#else
	|| !bcmp((char *)vp->val.objid, (char *)unavailableAlarm,
		 sizeof(unavailableAlarm)))
#endif
	eventid = 3;
    else
	printf("unknown event\n");

    vp = vp->next_variable;
#ifdef SVR4
    memmove((char *)variable, (char *)vp->val.objid, vp->val_len * sizeof(oid));
#else
    bcopy((char *)vp->val.objid, (char *)variable, vp->val_len * sizeof(oid));
#endif
    variablelen = vp->val_len;
    op = vp->name + 22;
    destip = 0;
    destip |= (*op++) << 24;
    destip |= (*op++) << 16;
    destip |= (*op++) << 8;
    destip |= *op++;

    vp = vp->next_variable;
    sampletype = *vp->val.integer;
    
    vp = vp->next_variable;
    value= *vp->val.integer;
    
    vp = vp->next_variable;
    threshold = *vp->val.integer;
    
    printf("%d: 0x%02X %d %d %d\n", eventid, destip, sampletype, value, threshold);
    
}


int snmp_input(op, session, reqid, pdu, magic)
    int op;
    struct snmp_session *session;
    int reqid;
    struct snmp_pdu *pdu;
    void *magic;
{
    struct variable_list *vars;
    char buf[64];
    struct snmp_pdu *reply;
    struct tm *tm;
    time_t timer;

    if (op == RECEIVED_MESSAGE){
	if (pdu->command == TRP_REQ_MSG){
	    if (Print){
		time (&timer);
		tm = localtime (&timer);
		printf("%.4d-%.2d-%.2d %.2d:%.2d:%.2d %s: %s Trap (%d) Uptime: %s\n",
		       tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
		       tm->tm_hour, tm->tm_min, tm->tm_sec,
		       inet_ntoa(pdu->agent_addr.sin_addr),
		       trap_description(pdu->trap_type), pdu->specific_type,
		       uptime_string(pdu->time, buf));
		for(vars = pdu->variables; vars; vars = vars->next_variable) {
		    printf ("                    ");
		    print_variable(vars->name, vars->name_length, vars);
		}
	    }
	    if (Syslog){
		syslog(LOG_WARNING, "%s: %s Trap (%d) Uptime: %s\n",
		       inet_ntoa(pdu->agent_addr.sin_addr),
		       trap_description(pdu->trap_type), pdu->specific_type,
		       uptime_string(pdu->time, buf));
	    }
	} else if (pdu->command == TRP2_REQ_MSG
		   || pdu->command == INFORM_REQ_MSG){
	    if (Print){
		printf("-------------------------------  Notification  -------------------------------\n");
		for(vars = pdu->variables; vars; vars = vars->next_variable)
		    print_variable(vars->name, vars->name_length, vars);
	    }
	    if (Event) {
		event_input(pdu->variables);
	    }
	    if (pdu->command == INFORM_REQ_MSG){
		if (!(reply = snmp_clone_pdu2(pdu, GET_RSP_MSG))){
		    printf("Couldn't clone PDU for response\n");
		    return;
		}
		reply->errstat = 0;
		reply->errindex = 0;
		reply->address = pdu->address;
		if (!snmp_send(session, reply)){
		    printf("Couldn't respond to inform pdu\n");
		}
	    }
	}
    } else if (op == TIMED_OUT){
	printf("Timeout: This shouldn't happen!\n");
    }
}

#define NUM_NETWORKS    32   /* max number of interfaces to check */

#ifndef IFF_LOOPBACK
#define IFF_LOOPBACK 0
#endif
#define LOOPBACK    0x7f000001
u_long
get_myaddr(){
    int sd;
    struct ifconf ifc;
    struct ifreq conf[NUM_NETWORKS], *ifrp, ifreq;
    struct sockaddr_in *in_addr;
    int count;
    int interfaces;             /* number of interfaces returned by ioctl */

    if ((sd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
        return 0;
    ifc.ifc_len = sizeof(conf);
    ifc.ifc_buf = (caddr_t)conf;
    if (ioctl(sd, SIOCGIFCONF, (char *)&ifc) < 0){
        close(sd);
        return 0;
    }
    ifrp = ifc.ifc_req;
    interfaces = ifc.ifc_len / sizeof(struct ifreq);
    for(count = 0; count < interfaces; count++, ifrp++){
        ifreq = *ifrp;
        if (ioctl(sd, SIOCGIFFLAGS, (char *)&ifreq) < 0)
            continue;
        in_addr = (struct sockaddr_in *)&ifrp->ifr_addr;
        if ((ifreq.ifr_flags & IFF_UP)
            && (ifreq.ifr_flags & IFF_RUNNING)
            && !(ifreq.ifr_flags & IFF_LOOPBACK)
            && in_addr->sin_addr.s_addr != LOOPBACK){
                close(sd);
                return in_addr->sin_addr.s_addr;
            }
    }
    close(sd);
    return 0;
}


main(argc, argv)
    int	    argc;
    char    *argv[];
{
    struct snmp_session session, *ss;
    int	arg;
    int count, numfds, block;
    fd_set fdset;
    struct timeval timeout, *tvp;
    int version = 2;
    u_long myaddr;
    oid src[MAX_NAME_LEN], dst[MAX_NAME_LEN], context[MAX_NAME_LEN];
    int srclen, dstlen, contextlen;
    int local_port = 0, port_flag = 0;
    char *config_file = NULL;
    struct config_module *dp;
    int sd;
    struct sockaddr_in me;
    char ctmp[300];

    setvbuf (stdout, NULL, _IOLBF, BUFSIZ);
    init_syslog();
    init_mib();
    /*
     * usage: snmptrapd [-v 1] [-q] [-P #] [-p] [-s] [-d]
     */
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
	        case 'c':
		    /* config file name */
		    if (++arg >= argc) {
			fprintf(stderr,"-c: no config file name\n");
			break;
		    }
		    config_file = argv[arg];
		    break;
		case 'd':
		    snmp_dump_packet++;
		    break;
		case 'q':
		    quick_print++;
		    break;
                case 'P':
                    port_flag++;
                    local_port = atoi(argv[++arg]);
                    break;
		case 'p':
		    Print++;
		    break;
		case 'e':
		    Event++;
		    break;
		case 's':
		    Syslog++;
		    break;
                case 'v':
                    version = atoi(argv[++arg]);
                    if (version < 1 || version > 2){
                        fprintf(stderr, "Invalid version\n");

                        fprintf(stderr,"Usage: snmptrapd [-v 1] [-q] [-P #] [-p] [-s] [-e] [-d]\n");
                        exit(1);
                    }
                    break;
		default:
		    fprintf(stderr,"invalid option: -%c\n", argv[arg][1]);
		    fprintf(stderr,"Usage: snmptrapd [-v 1] [-q] [-P #] [-p] [-s] [-e] [-d]\n");
		    break;
	    }
	    continue;
	}
    }

    myaddr = get_myaddr();
    srclen = dstlen = contextlen = MAX_NAME_LEN;
    ms_party_init(myaddr, src, &srclen, dst, &dstlen,
		  context, &contextlen);

    if (version == 2){
            sprintf(ctmp,"%s/party.conf",SNMPLIBPATH);
	    if (read_party_database(ctmp) > 0){
		fprintf(stderr,
			"Couldn't read party database from %s\n",ctmp);
		exit(0);
	    }
            sprintf(ctmp,"%s/context.conf",SNMPLIBPATH);
	    if (read_context_database(ctmp) > 0){
		fprintf(stderr,
			"Couldn't read context database from %s\n",ctmp);
		exit(0);
	    }
            sprintf(ctmp,"%s/acl.conf",SNMPLIBPATH);
	    if (read_acl_database(ctmp) > 0){
		fprintf(stderr,
			"Couldn't read access control database from %s\n",ctmp);
		exit(0);
	    }
    }

#ifdef SVR4
    memset((char *)&session, NULL, sizeof(struct snmp_session));
#else
    bzero((char *)&session, sizeof(struct snmp_session));
#endif
    session.peername = NULL;
    if (version == 1){
        session.version = SNMP_VERSION_1;
    } else if (version == 2){
        session.version = SNMP_VERSION_2;
    }
    session.srcPartyLen = 0;
    session.dstPartyLen = 0;
    session.retries = SNMP_DEFAULT_RETRIES;
    session.timeout = SNMP_DEFAULT_TIMEOUT;
    session.authenticator = NULL;
    session.callback = snmp_input;
    session.callback_magic = NULL;
    if (port_flag)
        session.local_port = local_port;
    else
	session.local_port = SNMP_TRAP_PORT;
    ss = snmp_open(&session);
    if (ss == NULL){
	fprintf(stderr,"Couldn't open snmp\n");
	exit(1);
    }

    while(1){
	numfds = 0;
	FD_ZERO(&fdset);
	numfds = sd + 1;
	FD_SET(sd, &fdset);
	block = 0;
	tvp = &timeout;
	timerclear(tvp);
	tvp->tv_sec = 5;
	snmp_select_info(&numfds, &fdset, tvp, &block);
	if (block == 1)
	    tvp = NULL;	/* block without timeout */
	count = select(numfds, &fdset, 0, 0, tvp);
	gettimeofday(&Now, 0);
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
		    perror("select");
		}
		return -1;
	    default:
		printf("select returned %d\n", count);
		return -1;
	}
    }
}

init_syslog(){
/*
 * These definitions handle 4.2 systems without additional syslog facilities.
 */
#ifndef LOG_CONS
#define LOG_CONS	0	/* Don't bother if not defined... */
#endif
#ifndef LOG_LOCAL0
#define LOG_LOCAL0	0
#endif
    /*
     * All messages will be logged to the local0 facility and will be sent to
     * the console if syslog doesn't work.
     */
    openlog("snmptrapd", LOG_CONS, LOG_LOCAL0);
    syslog(LOG_INFO, "Starting snmptrapd");
}
