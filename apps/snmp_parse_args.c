#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#include <unistd.h>
#include <ctype.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#include <netdb.h>
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include "asn1.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "party.h"
#include "context.h"
#include "view.h"
#include "acl.h"
#include "snmp_parse_args.h"

void
snmp_parse_args_usage(outf)
  FILE *outf;
{
  fprintf(outf, "[-v 1|2|2h] [-h] [-d] [-q] [-p P] [-t T] [-r R] [-c S D] hostname <community|srcParty dstParty context>");
}

void
snmp_parse_args_descriptions(outf)
  FILE *outf;
{
  fprintf(outf, "  -v 1|2|2h\tspecifies snmp version to transmit.\n");
  fprintf(outf, "  -h\t\tthis help message.\n");
  fprintf(outf, "  -d\t\tdump input/output packets.\n");
  fprintf(outf, "  -q\t\tquick print output for easier parsing ability.\n");
  fprintf(outf, "  -p P\t\tuse port P instead of the default port.\n");
  fprintf(outf, "  -t T\t\tset the request timeout to T.\n");
  fprintf(outf, "  -r R\t\tset the number of retries to R.\n");
  fprintf(outf, "  -c S D\tset the source/destination clocks for v2h requests.\n");
}


int
snmp_parse_args(argc, argv, session)
  int argc;
  char *argv[];
  struct snmp_session *session;
{
  static char *hostname = NULL;
  static char *community = NULL;
  int arg;
  static oid src[MAX_NAME_LEN], dst[MAX_NAME_LEN], context[MAX_NAME_LEN];
  int clock_flag = 0;
  u_long      srcclock = 0, dstclock = 0;
  struct partyEntry *pp;
  struct contextEntry *cxp;
  char ctmp[300];
  in_addr_t destAddr;
  struct hostent *hp;

  /* defaults */
  memset(session, 0, sizeof(struct snmp_session));
  session->remote_port = SNMP_PORT;
  session->timeout = SNMP_DEFAULT_TIMEOUT;
  session->retries = SNMP_DEFAULT_RETRIES;
  session->authenticator = NULL;
  session->peername = NULL;

  for(arg = 1; arg < argc && argv[arg][0] == '-'; arg++){
    switch(argv[arg][1]){
      case 'd':
        snmp_set_dump_packet(1);
        break;
      case 'q':
        snmp_set_quick_print(1);
        break;
      case 'p':
        session->remote_port = atoi(argv[++arg]);
        break;
      case 't':
        session->timeout = atoi(argv[++arg]) * 1000000L;
        break;
      case 'r':
        session->retries = atoi(argv[++arg]);
        break;
      case 'c':
        clock_flag++;
        srcclock = atoi(argv[++arg]);
        dstclock = atoi(argv[++arg]);
        break;
      case 'v':
        if (!strcmp(argv[++arg],"1")) {
          session->version = SNMP_VERSION_1;
        } else if (!strcasecmp(argv[arg],"2h")) {
          session->version = SNMP_VERSION_2_HISTORIC;
        } else if (!strcmp(argv[arg],"2")) {
          session->version = SNMP_VERSION_2;
        } else {
          fprintf(stderr,"Invalid version specified:  %s", argv[arg]);
          usage();
          exit(1);
        }
        break;
      case 'h':
        usage();
        exit(1);
        break;
          
      default:
        /* printf("invalid option: -%c\n", argv[arg][1]); */
        break;
    }
  }
  if (arg == argc) {
    fprintf(stderr,"No hostname specified.\n");
    usage();
    exit(1);
  }
  session->peername = argv[arg++];     /* hostname */
  if (session->version == SNMP_VERSION_1 ||
      session->version == SNMP_VERSION_2) {
    /* v1 and v2 communities */
    session->community = (unsigned char *) argv[arg];
    session->community_len = strlen((char *)argv[arg]);
    arg++;
  } else {
    /* v2 historic party configuration */
    if (arg == argc) {
      printf("Neither a source party nor noAuth was specified.\n");
      usage();
      exit(1);
    }

    session->srcParty = src;
    session->dstParty = dst;
    session->context = context;

    if (!strcasecmp(argv[arg], "noauth")){
      if ((destAddr = inet_addr(session->peername)) == -1){
        hp = gethostbyname(session->peername);
        if (hp == NULL){
          fprintf(stderr, "unknown host: %s\n", session->peername);
          exit(1);
        } else {
          memmove(&destAddr, hp->h_addr, hp->h_length);
        }
      }
      session->srcPartyLen = session->dstPartyLen =
        session->contextLen = MAX_NAME_LEN;
      ms_party_init(destAddr, session->srcParty, &(session->srcPartyLen),
                    session->dstParty, &(session->dstPartyLen),
                    session->context, &(session->contextLen));
      arg++;
    } else {
      sprintf(ctmp,"%s/party.conf",SNMPLIBPATH);
      if (read_party_database(ctmp) != 0){
        fprintf(stderr,
                "Couldn't read party database from %s\n",ctmp);
        exit(1);
      }
      sprintf(ctmp,"%s/context.conf",SNMPLIBPATH);
      if (read_context_database(ctmp) != 0){
        fprintf(stderr,
                "Couldn't read context database from %s\n",ctmp);
        exit(1);
      }
      sprintf(ctmp,"%s/acl.conf",SNMPLIBPATH);
      if (read_acl_database(ctmp) != 0){
        fprintf(stderr,
                "Couldn't read access control database from %s\n",ctmp);
        exit(1);
      }

      /* source party */
      
      party_scanInit();
      session->srcPartyLen = MAX_NAME_LEN;
      for(pp = party_scanNext(); pp; pp = party_scanNext()){
        if (!strcasecmp(pp->partyName, argv[arg])){
          session->srcPartyLen = pp->partyIdentityLen;
          memmove(session->srcParty, pp->partyIdentity,
                  session->srcPartyLen * sizeof(oid));
          break;
        }
      }
      if (!pp){
        session->srcPartyLen = MAX_NAME_LEN;
        if (!read_objid(argv[arg], session->srcParty, &(session->srcPartyLen))){
          printf("Invalid source party: %s\n", argv[arg]);
          session->srcPartyLen = 0;
          usage();
          exit(1);
        }
      }
      arg++;

      if (arg == argc) {
        printf("No destination party specified.\n");
        usage();
        exit(1);
      }

      /* destination party */
      
      session->dstPartyLen = MAX_NAME_LEN;
      party_scanInit();
      for(pp = party_scanNext(); pp; pp = party_scanNext()){
        if (!strcasecmp(pp->partyName, argv[arg])){
          session->dstPartyLen = pp->partyIdentityLen;
          memmove(session->dstParty, pp->partyIdentity,
                  session->dstPartyLen * sizeof(oid));
          break;
        }
      }
      if (!pp){
        if (!read_objid(argv[arg], session->dstParty, &(session->dstPartyLen))){
          printf("Invalid destination party: %s\n", argv[arg]);
          session->dstPartyLen = 0;
          usage();
          exit(1);
        }
      }
      arg++;

      /* context */

      if (arg == argc) {
        printf("No context specified.\n");
        usage();
        exit(1);
      }

      session->contextLen = MAX_NAME_LEN;
      context_scanInit();
      for(cxp = context_scanNext(); cxp; cxp = context_scanNext()){
        if (!strcasecmp(cxp->contextName, argv[arg])){
          session->contextLen = cxp->contextIdentityLen;
          memmove(session->context, cxp->contextIdentity,
                  session->contextLen * sizeof(oid));
          break;
        }
      }
      if (!cxp){
        if (!read_objid(argv[arg], session->context, &(session->contextLen))){
          printf("Invalid context: %s\n", argv[arg]);
          session->contextLen = 0;
          usage();
          exit(1);
        }
      }
      arg++;

      if (clock_flag){
        pp = party_getEntry(session->srcParty, session->srcPartyLen);
        if (pp){
            pp->partyAuthClock = srcclock;
            gettimeofday(&pp->tv, (struct timezone *)0);
            pp->tv.tv_sec -= pp->partyAuthClock;
        }
        pp = party_getEntry(session->dstParty, session->dstPartyLen);
        if (pp){
            pp->partyAuthClock = dstclock;
            gettimeofday(&pp->tv, (struct timezone *)0);
            pp->tv.tv_sec -= pp->partyAuthClock;
        }
      }
    }
  }
  return arg;
}

     
   
  
    
