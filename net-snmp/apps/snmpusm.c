/*
 * snmpusm.c - send snmp SET requests to a network entity to change the
 *             usm user database
 *
 * XXX get engineID dynamicly.
 * XXX read passwords from prompts
 * XXX customize responses with user names, etc.
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
#include "snmp-tc.h"

void main __P((int, char **));

#define CMD_PASSWD_NAME    "passwd"
#define CMD_PASSWD         1
#define CMD_CREATE_NAME    "create"
#define CMD_CREATE         2
#define CMD_DELETE_NAME    "delete"
#define CMD_DELETE         3
#define CMD_CLONEFROM_NAME "cloneFrom"
#define CMD_CLONEFROM      4

#define CMD_NUM    4

static char *successNotes[CMD_NUM] = {
  "SNMPv3 Key(s) successfully changed.",
  "User successfully created.",
  "User successfully deleted.",
  "User successfully cloned."
};

#define                   USM_OID_LEN    12

static oid  authKeyOid[MAX_OID_LEN]          = {1,3,6,1,6,3,12,1,2,2,1,6},
            ownAuthKeyOid[MAX_OID_LEN]       = {1,3,6,1,6,3,12,1,2,2,1,7},
            privKeyOid[MAX_OID_LEN]          = {1,3,6,1,6,3,12,1,2,2,1,9},
            ownPrivKeyOid[MAX_OID_LEN]       = {1,3,6,1,6,3,12,1,2,2,1,10},
            usmUserCloneFrom[MAX_OID_LEN]    = {1,3,6,1,6,3,12,1,2,2,1,4},
            usmUserSecurityName[MAX_OID_LEN] = {1,3,6,1,6,3,12,1,2,2,1,3},
            usmUserStatus[MAX_OID_LEN]       = {1,3,6,1,6,3,12,1,2,2,1,13}
;
                           

void
usage __P((void))
{
  fprintf(stderr,"Usage:\n  snmpusm ");
  snmp_parse_args_usage(stderr);
  fprintf(stderr," COMMAND\n\n");
  snmp_parse_args_descriptions(stderr);
  fprintf(stderr, "\nsnmpusm commands:\n");
  fprintf(stderr, "  create    USER [CLONEFROM]\n");
  fprintf(stderr, "  delete    USER\n");
  fprintf(stderr, "  cloneFrom USER FROM\n");
  fprintf(stderr, "  passwd    [-O old_passphrase] [-N new_passphrase] [-o] [-a] [-x]\n");
  fprintf(stderr, "\t\t-N NEWPASS:\tuse NEWPASS as the new passphrase.\n");
  fprintf(stderr, "\t\t-O OLDPASS:\tuse OLDPASS as the old passphrase.\n");
  fprintf(stderr, "\t\t-o\t\tUse the ownKeyChange objects.\n");
  fprintf(stderr, "\t\t-x\t\tChange the privacy key.\n");
  fprintf(stderr, "\t\t-a\t\tChange the authentication key.\n");
}

/* setup_oid appends to the oid the index for the engineid/user */
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
  DEBUGP("buf: %s\n", buf);
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
    int                   name_length = USM_OID_LEN;
    int                   name_length2 = USM_OID_LEN;
    int                   status;
    int                   rval;
    int                   doauthkey       = 0,
                          doprivkey       = 0,
                          command;
    long                  longvar;
                         
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

    SOCK_STARTUP;

    /* open an SNMP session */
    /*   Note:  this wil obtain the engineID needed below */
    snmp_synch_setup(&session);
    ss = snmp_open(&session);
    if (ss == NULL){
      snmp_perror("snmpset");
      exit(1);
    }

    /* create PDU for SET request and add object names and values to request */
    pdu = snmp_pdu_create(SNMP_MSG_SET);

    if (arg >= argc) {
      fprintf(stderr, "Please specify a opreation to perform.\n");
      usage();
      exit(1);
    }

    if (strcmp(argv[arg], CMD_PASSWD_NAME) == 0) {

      /*
       * passwd: change a users password.
       *
       * XXX:  Uses the auth type of the calling user, a MD5 user can't
       *       change a SHA user's key.
       */
      command = CMD_PASSWD;
      for(arg++; arg < argc; arg++) {

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

          case 'O':
            if (argv[arg][2] != 0)
              oldpass = &argv[arg][2];
            else
              oldpass = argv[++arg];
            break;

          case 'o':
            authKeyChange   = ownAuthKeyOid;
            privKeyChange   = ownPrivKeyOid;
            break;

          case 'a':
            doauthkey = 1;
            break;

          case 'x':
            doprivkey = 1;
            break;

          default:
            fprintf(stderr, "Unknown switch: %c\n", *argv[arg]);
            usage();
            exit(1);
        }
      }

      if (doprivkey == 0 && doauthkey == 0)
        doprivkey = doauthkey = 1;
    
      if ( newpass == NULL || strlen(newpass) < USM_LENGTH_P_MIN ) {
        fprintf(stderr, "New passphrase must be greater than %d characters in length.\n",
                USM_LENGTH_P_MIN);
        exit(1);
      }

      if ( oldpass == NULL || strlen(oldpass) < USM_LENGTH_P_MIN ) {
        fprintf(stderr, "Old passphrase must be greater than %d characters in length.\n",
                USM_LENGTH_P_MIN);
        exit(1);
      }

      /* the old Ku is in the session, but we need the new one */
      rval = generate_Ku(session.securityAuthProto,
                         session.securityAuthProtoLen,
                         newpass, strlen(newpass),
                         newKu, &newKu_len);

      if (rval != SNMPERR_SUCCESS) {
        fprintf(stderr, "generating the old Ku failed\n");
        exit(1);
      }

      /* the old Ku is in the session, but we need the new one */
      rval = generate_Ku(session.securityAuthProto,
                         session.securityAuthProtoLen,
                         oldpass, strlen(oldpass),
                         oldKu, &oldKu_len);
    
      if (rval != SNMPERR_SUCCESS) {
        fprintf(stderr, "generating the new Ku failed\n");
        exit(1);
      }

      /* generate the two Kul's */
      rval = generate_kul(session.securityAuthProto,
                          session.securityAuthProtoLen,
                          session.contextEngineID, session.contextEngineIDLen,
                          oldKu, oldKu_len, oldkul, &oldkul_len);

      if (rval != SNMPERR_SUCCESS) {
        fprintf(stderr, "generating the old Kul failed\n");
        exit(1);
      }

      rval = generate_kul(session.securityAuthProto,
                          session.securityAuthProtoLen,
                          session.contextEngineID, session.contextEngineIDLen,
                          newKu, newKu_len,
                          newkul, &newkul_len);

      if (rval != SNMPERR_SUCCESS) {
        fprintf(stderr, "generating the new Kul failed\n");
        exit(1);
      }

      /* create the keychange string */
      rval = encode_keychange(session.securityAuthProto,
                              session.securityAuthProtoLen,
                              oldkul, oldkul_len,
                              newkul, newkul_len,
                              keychange, &keychange_len);

      if (rval != SNMPERR_SUCCESS) {
        fprintf(stderr, "encoding the keychange failed\n");
        usage();
        exit(1);
      }


      /* add the keychange string to the outgoing packet */
      if (doauthkey) {
        setup_oid(authKeyChange, &name_length,
                  session.contextEngineID, session.contextEngineIDLen,
                  session.securityName);
        snmp_pdu_add_variable(pdu, authKeyChange, name_length,
                              ASN_OCTET_STR, keychange, keychange_len);
      }
      if (doprivkey) {
        setup_oid(privKeyChange, &name_length,
                  session.contextEngineID, session.contextEngineIDLen,
                  session.securityName);
        snmp_pdu_add_variable(pdu, privKeyChange, name_length,
                              ASN_OCTET_STR, keychange, keychange_len);
      }

    } else if (strcmp(argv[arg], CMD_CREATE_NAME) == 0) {
      /*
       * create:  create a user
       *
       * create USER [CLONEFROM]
       */
      if (++arg >= argc) {
        fprintf(stderr,"You must specify the user name to create\n");
        usage();
        exit(1);
      }
      
      command = CMD_CREATE;
      setup_oid(usmUserStatus, &name_length,
                session.contextEngineID, session.contextEngineIDLen,
                argv[arg]);
      longvar = RS_CREATEANDGO;
      snmp_pdu_add_variable(pdu, usmUserStatus, name_length,
                            ASN_INTEGER, (u_char *) &longvar, sizeof(longvar));

      if (++arg < argc) {
        /* clone the new user from another user as well */
        setup_oid(usmUserCloneFrom, &name_length,
                  session.contextEngineID, session.contextEngineIDLen,
                  argv[arg-1]);
        setup_oid(usmUserSecurityName, &name_length2,
                  session.contextEngineID, session.contextEngineIDLen,
                  argv[arg]);
        snmp_pdu_add_variable(pdu, usmUserCloneFrom, name_length,
                              ASN_OBJECT_ID, (u_char *) usmUserSecurityName,
                              sizeof(oid)*name_length2);
      }

    } else if (strcmp(argv[arg], CMD_CLONEFROM_NAME) == 0) {
      /*
       * create:  clone a user from another
       *
       * cloneFrom USER FROM
       */
      if (++arg >= argc) {
        fprintf(stderr,"You must specify the user name to operate on\n");
        usage();
        exit(1);
      }
      
      command = CMD_CLONEFROM;
      setup_oid(usmUserCloneFrom, &name_length,
                session.contextEngineID, session.contextEngineIDLen,
                argv[arg]);

      if (++arg >= argc) {
        fprintf(stderr,"You must specify the user name to clone from\n");
        usage();
        exit(1);
      }

      setup_oid(usmUserSecurityName, &name_length2,
                session.contextEngineID, session.contextEngineIDLen,
                argv[arg]);
      snmp_pdu_add_variable(pdu, usmUserCloneFrom, name_length,
                            ASN_OBJECT_ID, (u_char *) usmUserSecurityName,
                            sizeof(oid)*name_length2);

    } else if (strcmp(argv[arg], CMD_DELETE_NAME) == 0) {
      /*
       * delete:  delete a user
       *
       * delete USER
       */
      if (++arg >= argc) {
        fprintf(stderr,"You must specify the user name to delete\n");
        exit(1);
      }
      
      command = CMD_DELETE;
      setup_oid(usmUserStatus, &name_length,
                session.contextEngineID, session.contextEngineIDLen,
                argv[arg]);
      longvar = RS_DESTROY;
      snmp_pdu_add_variable(pdu, usmUserStatus, name_length,
                            ASN_INTEGER, (u_char *) &longvar, sizeof(longvar));
    }

    /* do the request */
    status = snmp_synch_response(ss, pdu, &response);
    if (status == STAT_SUCCESS){
      if (response->errstat == SNMP_ERR_NOERROR){
        fprintf(stderr, "%s\n", successNotes[command-1]);
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
