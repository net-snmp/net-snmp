/*
 * snmp_parse_args.c
 */

#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>
#include <stdio.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <ctype.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
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
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif
#if HAVE_NETDB_H
#include <netdb.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <getopt.h>

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "scapi.h"
#include "keytools.h"

#include "snmp_parse_args.h"
#include "snmp_logging.h"
#include "version.h"
#include "system.h"
#include "parse.h"
#include "read_config.h"
#include "snmp_debug.h"
#include "snmpv3.h"
#include "default_store.h"

int random_access = 0;

#define USM_AUTH_PROTO_MD5_LEN 10
static oid usmHMACMD5AuthProtocol[]  = { 1,3,6,1,6,3,10,1,1,2 };
#define USM_AUTH_PROTO_SHA_LEN 10
static oid usmHMACSHA1AuthProtocol[] = { 1,3,6,1,6,3,10,1,1,3 };
#define USM_PRIV_PROTO_DES_LEN 10
static oid usmDESPrivProtocol[]      = { 1,3,6,1,6,3,10,1,2,2 };

void
snmp_parse_args_usage(FILE *outf)
{
  fprintf(outf, "[options...] <hostname> {<community>}");
}

void
snmp_parse_args_descriptions(FILE *outf)
{
  fprintf(outf,"UCD-snmp version: %s\n", VersionInfo);
  fprintf(outf, "  -h\t\tthis help message.\n");
  fprintf(outf, "  -H\t\tDisplay configuration file directives understood.\n");
  fprintf(outf, "  -V\t\tdisplay version number.\n");
  fprintf(outf, "  -v 1|2c|3\tspecifies snmp version to use.\n");
  fprintf(outf, "SNMP Version 1 or 2c specific\n");
  fprintf(outf, "  -c <c>\tset the community name (v1 or v2c)\n");
  fprintf(outf, "SNMP Version 3 specific\n");
  fprintf(outf, "  -Z <B,T>\tset the destination engine boots/time for v3 requests.\n");
  fprintf(outf, "  -e <E>\tsecurity engine ID (e.g., 800000020109840301).\n");
  fprintf(outf, "  -E <E>\tcontext engine ID (e.g., 800000020109840301).\n");
  fprintf(outf, "  -n <N>\tcontext name (e.g., bridge1).\n");
  fprintf(outf, "  -u <U>\tsecurity name (e.g., bert).\n");
  fprintf(outf, "  -l <L>\tsecurity level (noAuthNoPriv|authNoPriv|authPriv).\n");
  fprintf(outf, "  -a <A>\tauthentication protocol (MD5|SHA)\n");
  fprintf(outf, "  -A <P>\tauthentication protocol pass phrase.\n");
  fprintf(outf, "  -x <X>\tprivacy protocol (DES).\n");
  fprintf(outf, "  -X <P>\tprivacy protocol pass phrase\n");
  fprintf(outf, "General communication options\n");
  fprintf(outf, "  -p <P>\tuse port P instead of the default port.\n");
  fprintf(outf, "  -T <LAYER>\tuse LAYER for the network layer.\n");
  fprintf(outf, "\t\t\t(UDP or TCP).\n");
  fprintf(outf, "  -t <T>\tset the request timeout to T.\n");
  fprintf(outf, "  -r <R>\tset the number of retries to R.\n");
  fprintf(outf, "Debugging\n");
  fprintf(outf, "  -d\t\tdump input/output packets.\n");
  fprintf(outf, "  -D all | <TOKEN[,TOKEN,...]> \tturn on debugging output for the specified TOKENs.\n");
  fprintf(outf, "General options\n");
  fprintf(outf, "  -m all | <MIBS>\tuse MIBS list instead of the default mib list.\n");
  fprintf(outf, "  -M <MIBDIRS>\tuse MIBDIRS as the location to look for mibs.\n");
  fprintf(outf, "  -P <MIBOPTS>\tToggle various defaults controlling mib parsing:\n");
  snmp_mib_toggle_options_usage("\t\t  ", outf);
  fprintf(outf, "  -O <OUTOPTS>\tToggle various defaults controlling output display:\n");
  snmp_out_toggle_options_usage("\t\t  ", outf);
  fprintf(outf, "  -I <INOPTS>\tToggle various defaults controlling input parsing:\n");
  snmp_in_toggle_options_usage("\t\t  ", outf);
  fflush(outf);
}

#define BUF_SIZE 512

int
snmp_parse_args(int argc, 
		char *const *argv, 
		struct snmp_session *session, const char *localOpts,
		void(* proc)(int, char *const *, int))
{
  int arg;
  char *cp;
  char *Apsz = NULL;
  char *Xpsz = NULL;
  char *Cpsz = NULL;
  u_char buf[BUF_SIZE];
  int bsize;
  int tmp_port;
  char Opts[BUF_SIZE];

  /* initialize session to default values */
  snmp_sess_init( session );
  strcpy(Opts, "VhHm:M:O:I:P:D:dv:p:r:t:c:Z:e:E:n:u:l:x:X:a:A:T:");
#ifndef DEPRECATED_CLI_OPTIONS
  strcat(Opts, "fsSqR");
#endif
  if (localOpts) strcat(Opts, localOpts);

  /* get the options */
  DEBUGMSGTL(("snmp_parse_args","starting: %d/%d\n", optind, argc));
  for(arg=0; arg < argc; arg++) {
      DEBUGMSGTL(("snmp_parse_args"," arg %d = %s\n", arg, argv[arg]));
  }
      
  optind = 1;
  while ((arg = getopt(argc, argv, Opts)) != EOF) {
    DEBUGMSGTL(("snmp_parse_args","handling (#%d): %c\n", optind, arg));
    switch(arg){
      case 'V':
        fprintf(stderr,"UCD-snmp version: %s\n", VersionInfo);
        return(-2);

      case 'h':
        return(-1);
        break;

      case 'H':
        init_snmp("snmpapp");
        fprintf(stderr, "Configuration directives understood:\n");
        read_config_print_usage("  ");
        return(-2);

      case 'm':
        setenv("MIBS", optarg, 1);
        break;

      case 'M':
        setenv("MIBDIRS", optarg, 1);
        break;

#ifndef DEPRECATED_CLI_OPTIONS
      case 'f':
	fprintf(stderr, "Warning: -f option is deprecated - use -Of\n");
	snmp_set_full_objid(1);
	break;

      case 's':
	fprintf(stderr, "Warning: -s option is deprecated - use -Os\n");
	snmp_set_suffix_only(1);
	break;

      case 'S':
	fprintf(stderr, "Warning: -S option is deprecated - use -OS\n");
	snmp_set_suffix_only(2);
	break;

      case 'q':
	fprintf(stderr, "Warning: -q option is deprecated - use -Oq\n");
	snmp_set_quick_print(1);
	break;

      case 'R':
	fprintf(stderr, "Warning: -R option is deprecated - use -IR\n");
        snmp_set_random_access(1);
        break;
#endif /* DEPRECATED_CLI_OPTIONS */

      case 'O':
        cp = snmp_out_toggle_options(optarg);
        if (cp != NULL) {
          fprintf(stderr,"Unknown output option passed to -O: %c.\n", *cp);
          return(-1);
        }
        break;

      case 'I':
        cp = snmp_in_toggle_options(optarg);
        if (cp != NULL) {
          fprintf(stderr,"Unknown input option passed to -I: %c.\n", *cp);
          return(-1);
        }
        break;

      case 'P':
        cp = snmp_mib_toggle_options(optarg);
        if (cp != NULL) {
          fprintf(stderr,"Unknown parsing option passed to -P: %c.\n", *cp);
          return(-1);
        }
        break;

      case 'D':
        debug_register_tokens(optarg);
        snmp_set_do_debugging(1);
        break;

      case 'd':
        snmp_set_dump_packet(1);
        break;

      case 'v':
        if (!strcmp(optarg,"1")) {
          session->version = SNMP_VERSION_1;
        } else if (!strcasecmp(optarg,"2c")) {
          session->version = SNMP_VERSION_2c;
        } else if (!strcasecmp(optarg,"3")) {
          session->version = SNMP_VERSION_3;
        } else {
          fprintf(stderr,"Invalid version specified after -v flag: %s\n", optarg);
          return(-1);
        }
        break;

      case 'p':
        tmp_port = atoi(optarg);
        if ((tmp_port < 1) || (tmp_port > 65535)) {
          fprintf(stderr,"Invalid port number after -p flag.\n");
          return(-1);
        }
        session->remote_port = (u_short)tmp_port;
        break;

      case 't':
        session->timeout = atoi(optarg) * 1000000L;
        if (session->timeout < 0 || !isdigit(optarg[0])) {
          fprintf(stderr,"Invalid timeout in seconds after -t flag.\n");
          return(-1);
        }
        break;

      case 'r':
        session->retries = atoi(optarg);
        if (session->retries < 0 || !isdigit(optarg[0])) {
          fprintf(stderr,"Invalid number of retries after -r flag.\n");
          return(-1);
        }
        break;

      case 'T':
          if (strcasecmp(optarg,"TCP") == 0) {
              session->flags |= SNMP_FLAGS_STREAM_SOCKET;
          } else if (strcasecmp(optarg,"UDP") == 0) {
              /* default, do nothing */
          } else {
              fprintf(stderr,"Unknown transport \"%s\" after -T flag.\n", optarg);
              return(-1);
          }
          break;

      case 'c':
	Cpsz = optarg;
	break;

      case 'Z':
        session->engineBoots = strtoul(optarg, NULL, 10);
        if (session->engineBoots == 0 || !isdigit(optarg[0])) {
          fprintf(stderr,"Need engine boots value after -Z flag.\n");
          return(-1);
        }
        cp = strchr(optarg,',');
        if (cp && *(++cp) && isdigit(*cp))
          session->engineTime = strtoul(cp, NULL, 10);
		/* Handle previous '-Z boot time' syntax */
	else if ((optind<argc) && isdigit(argv[optind][0]))
	  session->engineTime = strtoul(argv[optind], NULL, 10);
        else {
          fprintf(stderr,"Need engine time value after -Z flag.\n");
          return(-1);
        }
        break;

      case 'e':
	if ((bsize = hex_to_binary(optarg,buf)) <= 0) {
          fprintf(stderr,"Bad engine ID value after -e flag. \n");
          return(-1);
	}
	session->securityEngineID = (u_char *)malloc(bsize);
	memcpy(session->securityEngineID, buf, bsize);
	session->securityEngineIDLen = bsize;
        break;

      case 'E':
	if ((bsize = hex_to_binary(optarg,buf)) <= 0) {
          fprintf(stderr,"Bad engine ID value after -E flag. \n");
          return(-1);
	}
	session->contextEngineID = (u_char *)malloc(bsize);
	memcpy(session->contextEngineID, buf, bsize);
	session->contextEngineIDLen = bsize;
        break;

      case 'n':
	session->contextName = strdup(optarg);
	session->contextNameLen = strlen(optarg);
        break;

      case 'u':
	session->securityName = strdup(optarg);
	session->securityNameLen = strlen(optarg);
        break;

      case 'l':
        if (!strcasecmp(optarg,"noAuthNoPriv") || !strcmp(optarg,"1") ||
            !strcasecmp(optarg,"nanp")) {
          session->securityLevel = SNMP_SEC_LEVEL_NOAUTH;
        } else if (!strcasecmp(optarg,"authNoPriv") || !strcmp(optarg,"2") ||
            !strcasecmp(optarg,"anp")) {
          session->securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
        } else if (!strcasecmp(optarg,"authPriv") || !strcmp(optarg,"3") ||
            !strcasecmp(optarg,"ap")) {
          session->securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
        } else {
          fprintf(stderr,"Invalid security level specified after -l flag: %s\n", optarg);
          return(-1);
        }

        break;

      case 'a':
        if (!strcasecmp(optarg,"MD5")) {
          session->securityAuthProto = usmHMACMD5AuthProtocol;
          session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
        } else if (!strcasecmp(optarg,"SHA")) {
          session->securityAuthProto = usmHMACSHA1AuthProtocol;
          session->securityAuthProtoLen = USM_AUTH_PROTO_SHA_LEN;
        } else {
          fprintf(stderr,"Invalid authentication protocol specified after -a flag: %s\n", optarg);
          return(-1);
        }
        break;

      case 'x':
        if (!strcasecmp(optarg,"DES")) {
          session->securityPrivProto = usmDESPrivProtocol;
          session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
        } else {
          fprintf(stderr,"Invalid privacy protocol specified after -x flag: %s\n", optarg);
          return(-1);
        }
        break;

      case 'A':
	Apsz = optarg;
	break;

      case 'X':
        Xpsz = optarg;
        break;

      case '?':
        return(-1);
        break;

      default:
	proc(argc, argv, arg);
	break;
    }
  }
  DEBUGMSGTL(("snmp_parse_args","finished: %d/%d\n", optind, argc));

  /* read in MIB database and initialize the snmp library*/
  init_snmp("snmpapp");

  if (session->version == SNMP_DEFAULT_VERSION) {
    session->version = ds_get_int(DS_LIBRARY_ID, DS_LIB_SNMPVERSION);
  }

  /* make master key from pass phrases */
  if (Apsz) {
      session->securityAuthKeyLen = USM_AUTH_KU_LEN;
      if (session->securityAuthProto == NULL) {
          /* get .conf set default */
          session->securityAuthProto =
              get_default_authtype(&session->securityAuthProtoLen);
      }
      if (session->securityAuthProto == NULL) {
          /* assume MD5 */
          session->securityAuthProto = usmHMACMD5AuthProtocol;
          session->securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
      }
      if (generate_Ku(session->securityAuthProto,
                      session->securityAuthProtoLen,
                      (u_char *)Apsz, strlen(Apsz),
                      session->securityAuthKey,
                      &session->securityAuthKeyLen) != SNMPERR_SUCCESS) {
          snmp_perror(argv[0]);
          fprintf(stderr,"Error generating Ku from authentication pass phrase. \n");
          return(-2);
      }
  }
  if (Xpsz) {
      session->securityPrivKeyLen = USM_PRIV_KU_LEN;
      if (session->securityPrivProto == NULL) {
          /* get .conf set default */
          session->securityPrivProto =
              get_default_privtype(&session->securityPrivProtoLen);
      }
      if (session->securityPrivProto == NULL) {
          /* assume DES */
          session->securityPrivProto = usmDESPrivProtocol;
          session->securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
      }
      if (generate_Ku(session->securityAuthProto,
                      session->securityAuthProtoLen,
                      (u_char *)Xpsz, strlen(Xpsz),
                      session->securityPrivKey,
                      &session->securityPrivKeyLen) != SNMPERR_SUCCESS) {
          snmp_perror(argv[0]);
          fprintf(stderr,"Error generating Ku from privacy pass phrase. \n");
          return(-2);
      }
  }
  /* get the hostname */
  if (optind == argc) {
    fprintf(stderr,"No hostname specified.\n");
    return(-1);
  }
  session->peername = argv[optind++];     /* hostname */

  /* get community */
  if ((session->version == SNMP_VERSION_1) ||
      (session->version == SNMP_VERSION_2c)) {
    /* v1 and v2c - so get community string */
    if (!Cpsz) {
      if ((Cpsz = ds_get_string(DS_LIBRARY_ID, DS_LIB_COMMUNITY)) != NULL)
	;
      else if (optind == argc) {
        fprintf(stderr,"No community name specified.\n");
        return(-1);
      }
      else
	Cpsz = argv[optind++];
    }
    session->community = (unsigned char *)Cpsz;
    session->community_len = strlen(Cpsz);
  }
  return optind;
}
