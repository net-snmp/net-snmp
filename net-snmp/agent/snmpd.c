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

#include <sys/types.h>
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
#include <sys/socket.h>
#include <errno.h>
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
#if STDC_HEADERS
#include <string.h>
#endif

#include "snmp.h"
#include "asn1.h"
#include "snmp_impl.h"
#include "system.h"
#include "snmp_api.h"
#include "m2m.h"
#include "party.h"
#include "alarm.h"
#include "view.h"
#include "context.h"
#include "acl.h"

extern int  errno;
int	snmp_dump_packet = 0;
int log_addresses = 0;

struct addrCache {
    u_long addr;
    int status;
#define UNUSED	0
#define USED	1
#define OLD	2
};

#define ADDRCACHE 10

static struct addrCache addrCache[ADDRCACHE];
static int lastAddrAge = 0;


#ifndef FD_SET
#include <sys/param.h>
typedef long    fd_mask;
#define NFDBITS (sizeof(fd_mask) * NBBY)        /* bits per mask */

#define FD_SET(n, p)    ((p)->fds_bits[(n)/NFDBITS] |= (1 << ((n) % NFDBITS)))
#define FD_CLR(n, p)    ((p)->fds_bits[(n)/NFDBITS] &= ~(1 << ((n) % NFDBITS)))
#define FD_ISSET(n, p)  ((p)->fds_bits[(n)/NFDBITS] & (1 << ((n) % NFDBITS)))
#define FD_ZERO(p)      bzero((char *)(p), sizeof(*(p)))

#endif

/*
 * In: My ip address, View subtree
 * Initializes a noAuth/noPriv party pair, a context, 2 acl entries, and
 * a view subtree. (Are two acl entries really needed?)
 * The view subtree is included by default and has no Mask.
 * Out: returns 0 if OK, 1 if conflict with a pre-installed
 * party/context/acl/view, -1 if an error occurred.
 */
agent_party_init(myaddr, dest_port, view)
    u_long myaddr;
    u_short dest_port;
    char *view;
{
    u_long addr;
    u_short port;
    oid partyid1[64];
    int partyidlen1;
    oid partyid2[64];
    int partyidlen2;
    oid contextid[64];
    int contextidlen;
    struct partyEntry *pp1, *pp2, *rp;
    struct contextEntry *cxp, *rxp;
    int viewIndex;
    oid viewSubtree[64];
    int viewSubtreeLen;
    struct viewEntry *vwp;
    struct aclEntry *ap;
    int oneIndex, twoIndex, cxindex;

    
    /*
     * Check for existence of the party, context, acl, and view and
     * exit if any of them exist.  We must create the parties to get the
     * partyIndexes for acl creation, so we delete these parties if we
     * fail anywhere else.
     */
    /* This would be better written as follows:
       We currently check for the existence of each of the
       src/dst/context/acl/view entries before creating anything.
       The problem is that in order to check for the existence of the
       acl entry, we need to create the src/dst/context to get their
       indexes.  So we create them with the proviso that we delete them
       if checks for other src/dst/context/view/acl fail.  [BUG:  we don't
       delete context and view if acl fails or context if view fails].
       Observation:  Because each index for the acl table is taken from
       a newly-created and therefore unique src/dst/context index, there
       is no reason to check for the existence of such an acl entry.
       Therefore, there is no reason to create the party entries until
       *after* we have checked everything.  This greatly simplifies this code.
       In addition, nobody cares what the view index is, so there is no need
       to check for the view's existence (just choose something that isn't
       in use.

       Suggestion:
       check src
       check dst
       check context
       if any used, fail 1
       create src, dst, context
       create acl(src.index, dst.index, context.index) and its brother
       find an unused view index (preferably one)
       create viewEntry(viewIndex, viewSubtree)
       context.viewIndex = viewIndex
     */
    partyidlen1 = 64;
    if (!read_objid(".1.3.6.1.6.3.3.1.3.128.2.35.55.1",
		    partyid1, &partyidlen1)){
	fprintf(stderr, "Bad object identifier: %s\n",
		".1.3.6.1.6.3.3.1.3.128.2.35.55.1");
	return -1;
    }
    partyid1[9] =  (myaddr & 0xFF000000) >> 24;
    partyid1[10] = (myaddr & 0x00FF0000) >> 16;
    partyid1[11] = (myaddr & 0x0000FF00) >> 8;
    partyid1[12] = (myaddr & 0x000000FF);
    partyid1[13] = 1;
    pp1 = party_getEntry(partyid1, partyidlen1);
    if (pp1){
	return 1;
    }
    pp1 = party_createEntry(partyid1, partyidlen1);
    oneIndex = pp1->partyIndex;

    partyidlen2 = 64;
    if (!read_objid(".1.3.6.1.6.3.3.1.3.128.2.35.55.1",
		    partyid2, &partyidlen2)){
	fprintf(stderr, "Bad object identifier: %s\n",
		".1.3.6.1.6.3.3.1.3.128.2.35.55.1");
	party_destroyEntry(partyid1, partyidlen1);
	return -1;
    }
    partyid2[9] =  (myaddr & 0xFF000000) >> 24;
    partyid2[10] = (myaddr & 0x00FF0000) >> 16;
    partyid2[11] = (myaddr & 0x0000FF00) >> 8;
    partyid2[12] = (myaddr & 0x000000FF);
    partyid2[13] = 2;
    pp2 = party_getEntry(partyid2, partyidlen2);
    if (pp2){
	party_destroyEntry(partyid1, partyidlen1);
	return 1;
    }
    pp2 = party_createEntry(partyid2, partyidlen2);
    twoIndex = pp2->partyIndex;

    contextidlen = 64;
    if (!read_objid(".1.3.6.1.6.3.3.1.4.128.2.35.55.1",
		    contextid, &contextidlen)){
	fprintf(stderr, "Bad object identifier: %s\n",
		".1.3.6.1.6.3.3.1.4.128.2.35.55.1");
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return -1;
    }
    contextid[9] =  (myaddr & 0xFF000000) >> 24;
    contextid[10] = (myaddr & 0x00FF0000) >> 16;
    contextid[11] = (myaddr & 0x0000FF00) >> 8;
    contextid[12] = (myaddr & 0x000000FF);
    contextid[13] = 1;
    cxp = context_getEntry(contextid, contextidlen);
    if (cxp){
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return 1;
    }

    viewIndex = 1;
    viewSubtreeLen = 64;
    if (!read_objid(view, viewSubtree, &viewSubtreeLen)){
	fprintf(stderr, "Bad object identifier: %s\n", view);
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return -1;
    }
    vwp = view_getEntry(viewIndex, viewSubtree, viewSubtreeLen);
    if (vwp){
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return 1;
    }

    ap = acl_getEntry(oneIndex, twoIndex, 1);
    if (ap){
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return 1;
    }
    ap = acl_getEntry(twoIndex, oneIndex, 1);
    if (ap){
	party_destroyEntry(partyid1, partyidlen1);
	party_destroyEntry(partyid2, partyidlen2);
	return 1;
    }

    rp = pp1->reserved;
    strcpy(pp1->partyName, "noAuthAgent");
    pp1->partyTDomain = rp->partyTDomain = DOMAINSNMPUDP;
    addr = htonl(myaddr);
    port = htons(dest_port);
    bcopy((char *)&addr, pp1->partyTAddress, sizeof(addr));
    bcopy((char *)&port, pp1->partyTAddress + 4, sizeof(port));
    bcopy(pp1->partyTAddress, rp->partyTAddress, 6);
    pp1->partyTAddressLen = rp->partyTAddressLen = 6;
    pp1->partyAuthProtocol = rp->partyAuthProtocol = NOAUTH;
    pp1->partyAuthClock = rp->partyAuthClock = 0;
    pp1->tv.tv_sec = pp1->partyAuthClock;
    pp1->partyAuthPublicLen = 0;
    pp1->partyAuthLifetime = rp->partyAuthLifetime = 0;
    pp1->partyPrivProtocol = rp->partyPrivProtocol = NOPRIV;
    pp1->partyPrivPublicLen = 0;
    pp1->partyMaxMessageSize = rp->partyMaxMessageSize = 1500;
    pp1->partyLocal = 1; /* TRUE */
    pp1->partyAuthPrivateLen = rp->partyAuthPrivateLen = 0;
    pp1->partyPrivPrivateLen = rp->partyPrivPrivateLen = 0;
    pp1->partyStorageType = 2; /* volatile */
    pp1->partyStatus = rp->partyStatus = PARTYACTIVE;
#define PARTYCOMPLETE_MASK              65535
    /* all collumns - from party_vars.c XXX */
    pp1->partyBitMask = rp->partyBitMask = PARTYCOMPLETE_MASK;

    rp = pp2->reserved;
    strcpy(pp2->partyName, "noAuthMS");
    pp2->partyTDomain = rp->partyTDomain = DOMAINSNMPUDP;
    bzero(pp2->partyTAddress, 6);
    bcopy(pp2->partyTAddress, rp->partyTAddress, 6);
    pp2->partyTAddressLen = rp->partyTAddressLen = 6;
    pp2->partyAuthProtocol = rp->partyAuthProtocol = NOAUTH;
    pp2->partyAuthClock = rp->partyAuthClock = 0;
    pp2->tv.tv_sec = pp2->partyAuthClock;
    pp2->partyAuthPublicLen = 0;
    pp2->partyAuthLifetime = rp->partyAuthLifetime = 0;
    pp2->partyPrivProtocol = rp->partyPrivProtocol = NOPRIV;
    pp2->partyPrivPublicLen = 0;
    pp2->partyMaxMessageSize = rp->partyMaxMessageSize = 484; /* ??? */
    pp2->partyLocal = 2; /* FALSE */
    pp2->partyAuthPrivateLen = rp->partyAuthPrivateLen = 0;
    pp2->partyPrivPrivateLen = rp->partyPrivPrivateLen = 0;
    pp2->partyStorageType = 2; /* volatile */
    pp2->partyStatus = rp->partyStatus = PARTYACTIVE;
    pp2->partyBitMask = rp->partyBitMask = PARTYCOMPLETE_MASK;
 
    cxp = context_createEntry(contextid, contextidlen);
    rxp = cxp->reserved;
    strcpy(cxp->contextName, "noAuthContext");
    cxp->contextLocal = 1; /* TRUE */
    cxp->contextViewIndex = 1;
    cxp->contextLocalEntityLen = 0;
    cxp->contextLocalTime = CURRENTTIME;
    cxp->contextProxyContextLen = 0;
    cxp->contextStorageType = 2;
    cxp->contextStatus = rxp->contextStatus = CONTEXTACTIVE;
#define CONTEXTCOMPLETE_MASK              0x03FF
    /* all collumns - from context_vars.c XXX */
    cxp->contextBitMask = rxp->contextBitMask = CONTEXTCOMPLETE_MASK;
    cxindex = cxp->contextIndex;

    vwp = view_createEntry(viewIndex, viewSubtree, viewSubtreeLen);
    vwp->viewType = VIEWINCLUDED;
    vwp->viewMaskLen = 0;
    vwp->viewStorageType = 2; /* volatile */
    vwp->viewStatus = VIEWACTIVE;
#define VIEWCOMPLETE_MASK              0x3F
    /* all collumns - from view_vars.c XXX */
    vwp->viewBitMask = VIEWCOMPLETE_MASK;
    vwp->reserved->viewBitMask = vwp->viewBitMask;

    viewSubtreeLen = 64;
    if (!read_objid(".2.6.6", viewSubtree, &viewSubtreeLen)){
	fprintf(stderr, "Bad object identifier: .2.6.6\n");
	return -1;
    }
    vwp = view_createEntry(viewIndex, viewSubtree, viewSubtreeLen);
    vwp->viewType = VIEWINCLUDED;
    vwp->viewMaskLen = 0;
    vwp->viewStorageType = 2; /* volatile */
    vwp->viewStatus = VIEWACTIVE;
    vwp->viewBitMask = VIEWCOMPLETE_MASK;
    vwp->reserved->viewBitMask = vwp->viewBitMask;

    ap = acl_createEntry(oneIndex, twoIndex, cxindex);
    ap->aclPriveleges = 132;
    ap->aclStorageType = 2; /* volatile */
    ap->aclStatus = ACLACTIVE;
#define ACLCOMPLETE_MASK              0x3F
    /* all collumns - from acl_vars.c XXX */
    ap->aclBitMask = ACLCOMPLETE_MASK;
    ap->reserved->aclBitMask = ap->aclBitMask;

    ap = acl_createEntry(twoIndex, oneIndex, cxindex);
    /* To play around with SETs with a minimum of hassle, set this to 43
       and noAuth/noPriv parties will be able to set in this default view.
       Remember to turn it back off when you're done! */
    ap->aclPriveleges = 35;
    ap->aclStorageType = 2; /* volatile */
    ap->aclStatus = ACLACTIVE;
    ap->aclBitMask = ACLCOMPLETE_MASK;
    ap->reserved->aclBitMask = ap->aclBitMask;

    return 0; /* SUCCESS */
}

char *reverse_bytes(buf,num)
  char *buf;
  int num;
{
  static char outbuf[100];
  int i;
  
  for(i=num-1;i>=0;i--)
    outbuf[i] = *buf++;
  return(outbuf);
}

char **argvrestartp;
char *argvrestart;
char *argvrestartname;

extern char *VersionInfo;

void usage(prog)
char *prog;
{
  printf("\nUsage:  %s [-h] [-v] [-f] [-a] [-d] [-q] [-p NUM] [-L] [-l LOGFILE]\n",prog);
  printf("\n\tVersion:  %s\n",VersionInfo);
  printf("\tAuthor:   hardaker@ece.ucdavis.edu\n");
  printf("\n-h\t\tThis usage message.\n");
  printf("-v\t\tVersion information.\n");
  printf("-f\t\tDon't fork from the shell.\n");
  printf("-a\t\tLog addresses.\n");
  printf("-d\t\tDump sent and received UDP SNMP packets\n");
  printf("-q\t\tPrint information in a more parsable format (quick-print)\n");
  printf("-p NUM\t\tRun on port NUM instead of the default:  161\n");
  printf("-L\t\tPrint warnings/messages to stdout/err rather than a logfile\n");
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

main(argc, argv)
    int	    argc;
    char    *argv[];
{
    int	arg,i;
    int sd, sdlist[32], portlist[32], sdlen = 0, index;
    struct sockaddr_in	me;
    int port_flag = 0, ret;
    u_short dest_port = 161;
    struct partyEntry *pp;
    u_long myaddr;
    int on=1;
    int dont_fork=0;
    char logfile[300], miscfile[300];
    char *cptr, **argvptr;

    logfile[0] = 0;
#ifdef LOGFILE
    strcpy(logfile,LOGFILE);
#endif

    /*
     * usage: snmpd
     */
    for(arg = 1; arg < argc; arg++){
	if (argv[arg][0] == '-'){
	    switch(argv[arg][1]){
		case 'd':
		    snmp_dump_packet++;
		    break;
		case 'q':
		    quick_print++;
		    break;
                case 'p':
                    port_flag++;
                    dest_port = atoi(argv[++arg]);
                    break;
		case 'a':
		    log_addresses++;
		    break;
		case 'f':
		    dont_fork=1;
		    break;
                case 'l':
                    strcpy(logfile,argv[++arg]);
                    break;
                case 'L':
                    logfile[0] = 0;
                    break;
                case 'h':
                    usage(argv[0]);
                    break;
                case 'v':
                    printf("\nUcd-snmp version:  %s\n",VersionInfo);
                    printf("Author:            hardaker@ece.ucdavis.edu\n\n");
                    exit (0);
                case '-':
                  switch(argv[arg][2]){
                    case 'v': 
                      printf("\nUcd-snmp version:  %s\n",VersionInfo);
                      printf("Author:            hardaker@ece.ucdavis.edu\n\n");
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
    }
    /* initialize a argv set to the current for restarting the agent */
    argvrestartp = (char **) malloc((argc+2) * sizeof (char *));
    argvptr = argvrestartp;
    for(i=0, ret = 1; i < argc; i++) {
      ret += strlen(argv[i])+1;
    }
    argvrestart = (char *) malloc((ret));
    argvrestartname = (char *) malloc(strlen(argv[0]));
    strcpy(argvrestartname,argv[0]);
    for(cptr = argvrestart,i = 0; i < argc; i++) {
      strcpy(cptr,argv[i]);
      *(argvptr++) = cptr;
      cptr += strlen(argv[i]) + 1;
    }
    *cptr = NULL;
    *argvptr = NULL;

    /* open the logfile if necessary */
    if (logfile[0]) {
      close(1);
      open(logfile,O_WRONLY|O_CREAT|O_TRUNC,0644);
      close(2);
      dup(1);
      close(0);
    }
    setvbuf (stdout, NULL, _IOLBF, BUFSIZ);
    if (!dont_fork && fork() != 0)   /* detach from shell */
      exit(0);
    init_snmp();
    init_mib();
    sprintf(miscfile,"%s/party.conf",SNMPLIBPATH);
    if (read_party_database(miscfile) > 0){
	fprintf(stderr, "Couldn't read party database from %s\n",miscfile);
	exit(0);
    }
    sprintf(miscfile,"%s/context.conf",SNMPLIBPATH);
    if (read_context_database(miscfile) > 0){
	fprintf(stderr, "Couldn't read context database from %s\n",miscfile);
	exit(0);
    }
    sprintf(miscfile,"%s/acl.conf",SNMPLIBPATH);
    if (read_acl_database(miscfile) > 0){
	fprintf(stderr, "Couldn't read acl database from %s\n",miscfile);
	exit(0);
    }
    sprintf(miscfile,"%s/view.conf",SNMPLIBPATH);
    if (read_view_database(miscfile) > 0){
	fprintf(stderr, "Couldn't read view database from %s\n",miscfile);
	exit(0);
    }
    
    myaddr = get_myaddr();
    /* XXX mib-2 subtree only??? */
    if (ret = agent_party_init(myaddr, dest_port, ".iso.org.dod.internet")){
	if (ret == 1){
	    fprintf(stderr, "Conflict found with initial noAuth/noPriv parties... continuing\n");
	} else if (ret == -1){
	    fprintf(stderr, "Error installing initial noAuth/noPriv parties, exiting\n");
	    exit(1);
	} else {
	    fprintf(stderr, "Unknown error, exiting\n");
	    exit(2);
	}
    }

    printf("Opening port(s): "); 
    fflush(stdout);
    party_scanInit();
    for(pp = party_scanNext(); pp; pp = party_scanNext()){
#if WORDS_BIGENDIAN
        if ((pp->partyTDomain != DOMAINSNMPUDP)
	    || bcmp((char *)&myaddr, pp->partyTAddress, 4))
          continue;	/* don't listen for non-local parties */
#else
	if ((pp->partyTDomain != DOMAINSNMPUDP)
	    || bcmp(reverse_bytes((char *)&myaddr,sizeof(long)),
                    pp->partyTAddress, 4))
          continue;	/* don't listen for non-local parties */
#endif
	
	dest_port = 0;
#if WORDS_BIGENDIAN
	bcopy(pp->partyTAddress + 4, &dest_port, 2);
#else
	bcopy(reverse_bytes(pp->partyTAddress + 4,2), &dest_port, 2);
#endif
	for(index = 0; index < sdlen; index++)
	    if (dest_port == portlist[index])
		break;
	if (index < sdlen)  /* found a hit before the end of the list */
	    continue;
	printf("%u ", dest_port); 
	fflush(stdout);
	/* Set up connections */
	sd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sd < 0){
	    perror("socket");
	    return 1;
	}
	me.sin_family = AF_INET;
	me.sin_addr.s_addr = INADDR_ANY;
	/* already in network byte order (I think) */
	me.sin_port = htons(dest_port);
	if (bind(sd, (struct sockaddr *)&me, sizeof(me)) != 0){
          fprintf(stderr,"bind/%d: ",me.sin_port);
          perror(NULL);
	    return 2;
	}
	sdlist[sdlen] = sd;
	portlist[sdlen] = dest_port;
        fcntl(sd,F_SETFD,1);           /* close on exec */
	if (++sdlen == 32){
	    printf("No more sockets... ignoring rest of file\n");
	    break;
	}	
    }
    printf("\n");
    fflush(stdout);
    bzero((char *)addrCache, sizeof(addrCache));
    receive(sdlist, sdlen);
    return 0;
}

receive(sdlist, sdlen)
    int sdlist[];
    int sdlen;
{
    int numfds, index;
    fd_set fdset;
    struct timeval  timeout, *tvp = &timeout;
    struct timeval  sched, *svp = &sched, now, *nvp = &now;
    int count, block;
int counter = 0;


    gettimeofday(nvp, (struct timezone *) NULL);
    if (nvp->tv_usec < 500000L){
	svp->tv_usec = nvp->tv_usec + 500000L;
	svp->tv_sec = nvp->tv_sec;
    } else {
	svp->tv_usec = nvp->tv_usec - 500000L;
	svp->tv_sec = nvp->tv_sec + 1;
    }
    while(1){
#if 0
	if (counter++ == 8000)
	    exit(0);
#endif
	tvp =  &timeout;
	tvp->tv_sec = 0;
	tvp->tv_usec = 500000L;

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
		    snmp_read_packet(sdlist[index]);
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
	}
        gettimeofday(nvp, (struct timezone *) NULL);
	if (nvp->tv_sec > svp->tv_sec
	    || (nvp->tv_sec == svp->tv_sec && nvp->tv_usec > svp->tv_usec)){
	    alarmTimer(nvp);
	    eventTimer(nvp);
	    if (nvp->tv_usec < 500000L){
		svp->tv_usec = nvp->tv_usec + 500000L;
		svp->tv_sec = nvp->tv_sec;
	    } else {
		svp->tv_usec = nvp->tv_usec - 500000L;
		svp->tv_sec = nvp->tv_sec + 1;
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
	}
    }
}

snmp_read_packet(sd)
    int sd;
{
    struct sockaddr_in	from;
    int length, out_length, fromlength;
    u_char  packet[1500], outpacket[1500];

    fromlength = sizeof from;
    length = recvfrom(sd, (char *) packet, 1500, 0, (struct sockaddr *)&from,
		      &fromlength);
    if (length == -1)
	perror("recvfrom");
    if (snmp_dump_packet){
	printf("recieved %d bytes from %s:\n", length,
	       inet_ntoa(from.sin_addr));
	xdump(packet, length, "");
	printf("\n\n");
        fflush(stdout);
    } else if (log_addresses){
	int count;
	
      for(count = 0; count < ADDRCACHE; count++){
          if (addrCache[count].status > UNUSED /* used or old */
		&& from.sin_addr.s_addr == addrCache[count].addr)
		break;
	}
      if (count >= ADDRCACHE){
          time_t now;
          struct tm *tm;
          time (&now);
          tm = localtime (&now);
          printf("%.4d-%.2d-%.2d %.2d:%.2d:%.2d Recieved SNMP packet(s) from %s\n",
                 tm->tm_year+1900, tm->tm_mon+1, tm->tm_mday,
                 tm->tm_hour, tm->tm_min, tm->tm_sec,
		   inet_ntoa(from.sin_addr));
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
    }
    out_length = 1500;
    if (snmp_agent_parse(packet, length, outpacket, &out_length,
			 from.sin_addr.s_addr)){
	if (snmp_dump_packet){
	    printf("sent %d bytes to %s:\n", out_length,
		   inet_ntoa(from.sin_addr));
	    xdump(outpacket, out_length, "");
	    printf("\n\n");
            fflush(stdout);
	}
	if (sendto(sd, (char *)outpacket, out_length, 0,
		   (struct sockaddr *)&from,
	    sizeof(from)) < 0){
		perror("sendto");
		return 0;
	}

    }
    return 1;
}

/* deals with replies from remote alarm variables, and from inform pdus */
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
	if (pdu->command == GET_RSP_MSG) {
	    if (state->type == EVENT_GET_REQ) {
		/* this is just the ack to our inform pdu */
		return 1;
	    }
	    return alarmGetResponse(pdu, state, op, session);
	}
    }
    else if (op == TIMED_OUT) {
	if (state->type == ALARM_GET_REQ) {
	    return alarmGetResponse(pdu, state, op, session);
	}
    }
    return 1;
}
