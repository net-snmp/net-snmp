/*
 * snmppass.c - send snmp SET requests to a network entity to change the
 * remote "password".
 *
 * Currently, we only support v3 USM localized keys.
 *
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
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#include <stdio.h>
#include <ctype.h>
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
#else
#include <netdb.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_KMT_H
#	include <kmt.h>
#endif
#ifdef HAVE_KMT_ALGS_H
#	include <kmt_algs.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp_client.h"
#include "mib.h"
#include "snmp.h"
#include "system.h"
#include "snmp_parse_args.h"
#include "int64.h"
#include "tools.h"
#include "keytools.h"

void main __P((int, char **));

void
usage __P((void))
{
  fprintf(stderr,"Usage:\n  snmppass ");
  snmp_parse_args_usage(stderr);
  fprintf(stderr," [-N new_passphrase] [-o]\n\n");
  snmp_parse_args_descriptions(stderr);
  fprintf(stderr, "snmppass options:\n");
  fprintf(stderr, "  -N NEWPASS:\tuse NEWPASS as the new passphrase.\n");
  fprintf(stderr, "  -o\t\tUse the ownKeyChange objects.\n");
}

#define                   KEY_CHANGE_LEN    12

/* setup_oid appends to the oid the index for the engineid/user */
void
setup_oid(oid *it, int *len, u_char *id, int idlen, u_char *user) {
  int i;
  char buf[1024];

  it[12] = idlen;
  for(i=13; i < 13+idlen; i++)
    it[i] = id[i-13];
  it[13+idlen] = strlen(user);
  for(i=14+idlen; i < 14+idlen+strlen(user); i++)
    it[i] = user[i-14-idlen];
  *len = 14+idlen+strlen(user);
  sprint_objid(buf, it, *len);
  fprintf(stderr, "buf: %s\n", buf);
}

void
main(argc, argv)
    int   argc;
    char  *argv[];
{
    struct snmp_session   session, *ss;
    struct snmp_pdu      *pdu, *response;
    struct variable_list *vars;

    int                   arg;
    int                   count;
    int                   current_name    = 0;
    int                   current_type    = 0;
    int                   current_value   = 0;
    char                 *names[128];
    char                  types[128];
    char                 *values[128];
    oid                   name[MAX_NAME_LEN];
    int                   name_length;
    int                   status;
    int                   rval;
    int                   doauthkey       = 1,
                          doprivkey       = 1;
                         
    oid                   authKeyOid[MAX_OID_LEN]    = {1,3,6,1,6,3,12,1,2,2,1,6},
                          ownAuthKeyOid[MAX_OID_LEN] = {1,3,6,1,6,3,12,1,2,2,1,7},
                          privKeyOid[MAX_OID_LEN]    = {1,3,6,1,6,3,12,1,2,2,1,9},
                          ownPrivKeyOid[MAX_OID_LEN] = {1,3,6,1,6,3,12,1,2,2,1,10};
                           
    oid                  *authKeyChange   = authKeyOid,
                         *privKeyChange   = privKeyOid;

    u_int                 oldKu_len       = SNMP_MAXBUF_SMALL,
                          newKu_len       = SNMP_MAXBUF_SMALL,
                          oldkul_len      = SNMP_MAXBUF_SMALL,
                          newkul_len      = SNMP_MAXBUF_SMALL,
                          keychange_len   = SNMP_MAXBUF_SMALL;

    u_char               *newpass         = NULL,
                         *oldpass         = NULL,
                          oldKu[SNMP_MAXBUF_SMALL],
                          newKu[SNMP_MAXBUF_SMALL],
                          oldkul[SNMP_MAXBUF_SMALL],
                          newkul[SNMP_MAXBUF_SMALL],
                          keychange[SNMP_MAXBUF_SMALL];
                         
    /* get the common command line arguments */
    arg = snmp_parse_args(argc, argv, &session);

    for(; arg < argc; arg++) {

      if (*argv[arg] != '-') {
        fprintf(stderr, "not an argument: %s\n", argv[arg]);
        usage();
        exit(1);
      }

      switch(argv[arg][1]) {
        case 'N':
          if (argv[arg][2] != 0)
            newpass = &argv[arg][2];
          else
            newpass = argv[++arg];
          break;

        case 'o':
          authKeyChange   = ownAuthKeyOid,
          privKeyChange   = ownPrivKeyOid;
          break;

        default:
          fprintf(stderr, "Unknown switch: %c\n", *argv[arg]);
          usage();
          exit(1);
      }
    }
    
    if ( newpass == NULL || strlen(newpass) < USM_LENGTH_P_MIN ) {
      fprintf(stderr, "New passphrase must be greater than %d characters in length.\n",
              USM_LENGTH_P_MIN);
      exit(1);
    }

    SOCK_STARTUP;

    /* open an SNMP session */
    /*   Note:  this wil obtain the engineID needed below */
    snmp_synch_setup(&session);
    ss = snmp_open(&session);
    if (ss == NULL){
      snmp_perror("snmpset");
      exit(1);
    }

    if (session.version != SNMP_VERSION_3) {
      /* forcing engineID discovery above... */
      fprintf(stderr,"You must use snmpv3 to utilitize this utility.\n");
      exit(1);
    }

    /* the old Ku is in the session, but we need the new one */
    rval = generate_Ku(session.securityAuthProto, session.securityAuthProtoLen,
                       newpass, strlen(newpass),
                       newKu, &newKu_len);

    if (rval != SNMPERR_SUCCESS) {
      fprintf(stderr, "generating the new Ku failed\n");
      exit(1);
    }

    /* generate the two Kul's */
    rval = generate_kul(session.securityAuthProto, session.securityAuthProtoLen,
			session.contextEngineID, session.contextEngineIDLen,
			session.securityAuthKey, session.securityAuthKeyLen,
			oldkul, &oldkul_len);

    if (rval != SNMPERR_SUCCESS) {
      fprintf(stderr, "generating the old Kul failed\n");
      exit(1);
    }

    rval = generate_kul(session.securityAuthProto, session.securityAuthProtoLen,
			session.contextEngineID, session.contextEngineIDLen,
			newKu, newKu_len,
			newkul, &newkul_len);

    if (rval != SNMPERR_SUCCESS) {
      fprintf(stderr, "generating the new Kul failed\n");
      exit(1);
    }

    /* create the keychange string */
    rval = encode_keychange(session.securityAuthProto, session.securityAuthProtoLen,
                            oldkul, oldkul_len,
                            newkul, newkul_len,
                            keychange, &keychange_len);

    if (rval != SNMPERR_SUCCESS) {
      fprintf(stderr, "encoding the keychange failed\n");
      exit(1);
    }

    /* create PDU for SET request and add object names and values to request */
    pdu = snmp_pdu_create(SNMP_MSG_SET);

    if (doauthkey) {
      name_length = KEY_CHANGE_LEN;
      setup_oid(authKeyChange, &name_length,
                session.contextEngineID, session.contextEngineIDLen,
                session.securityName);
      snmp_pdu_add_variable(pdu, authKeyChange, name_length,
                            ASN_OCTET_STR, keychange, keychange_len);
    }
    if (doprivkey) {
      name_length = KEY_CHANGE_LEN;
      setup_oid(privKeyChange, &name_length,
                session.contextEngineID, session.contextEngineIDLen,
                session.securityName);
      snmp_pdu_add_variable(pdu, privKeyChange, name_length,
                            ASN_OCTET_STR, keychange, keychange_len);
    }

    /* do the request */
retry:
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
        fprintf(stderr, "SNMPv3 Key(s) successfully changed.\n");
      } else {
        fprintf(stderr, "Error in packet.\nReason: %s\n",
                snmp_errstring(response->errstat));
      }
    } else if (status == STAT_TIMEOUT){
      fprintf(stderr,"Timeout: No Response from %s\n", session.peername);
      snmp_close(ss);
      SOCK_CLEANUP;
      exit(1);
    } else {    /* status == STAT_ERROR */
      snmp_perror("snmpset");
      snmp_close(ss);
      SOCK_CLEANUP;
      exit(1);
    }

    if (response)
      snmp_free_pdu(response);
    snmp_close(ss);
    SOCK_CLEANUP;
    exit (0);
}
