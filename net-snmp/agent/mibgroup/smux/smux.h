/*
 * Smux module authored by Rohit Dube.
 * Rewritten by Nick Amato <naamato@merit.net>.
 */

#define NOTINIT  0
#define INIT     1

#define SMUXOK      0
#define SMUXNOTOK   -1

#define SMUXPORT 199

#define SMUXMAXPKTSIZE 1500
#define SMUXMAXSTRLEN  256
#define SMUXMAXPEERS   10

#define SMUX_OPEN 	(ASN_APPLICATION | ASN_CONSTRUCTOR | 0)
#define SMUX_CLOSE      (ASN_APPLICATION | ASN_PRIMITIVE | 1)
#define SMUX_RREQ       (ASN_APPLICATION | ASN_CONSTRUCTOR | 2)
#define SMUX_RRSP       (ASN_APPLICATION | ASN_PRIMITIVE | 3)
#define SMUX_SOUT       (ASN_APPLICATION | ASN_PRIMITIVE | 4)

#define SMUX_GET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0)
#define SMUX_GETNEXT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)
#define SMUX_GETRSP     (ASN_CONTEXT | ASN_CONSTRUCTOR | 2)
#define SMUX_SET	(ASN_CONTEXT | ASN_CONSTRUCTOR | 3)

#define SMUXC_GOINGDOWN                    0
#define SMUXC_UNSUPPORTEDVERSION           1
#define SMUXC_PACKETFORMAT                 2
#define SMUXC_PROTOCOLERROR                3
#define SMUXC_INTERNALERROR                4
#define SMUXC_AUTHENTICATIONFAILURE        5

#define SMUX_MAX_PEERS          10
#define SMUX_MAX_PRIORITY       2147483647

#define SMUX_REGOP_DELETE       0
#define SMUX_REGOP_REGISTER     1

/* 
 * Authorized peers read from the config file
 */
typedef struct _smux_peer_auth {
	oid sa_oid[MAX_OID_LEN];        /* name of peer         	*/
	int sa_oid_len;                 /* length of peer name  	*/
	char sa_passwd[SMUXMAXSTRLEN];  /* configured passwd    	*/
	int sa_active_fd;		/* the peer using this auth 	*/
} smux_peer_auth;

/*
 * Registrations
 */
typedef struct _smux_reg {
	oid sr_name[MAX_OID_LEN];       /* name of subtree              */
	int sr_name_len;                /* length of subtree name       */
	int sr_priority;                /* priority of registration     */
	int sr_fd;                      /* descriptor of owner          */
	struct _smux_reg *sr_next;      /* next one                     */
} smux_reg;

extern int init_smux __P((void));
extern int smux_accept __P((int));
extern u_char *smux_snmp_process __P((int, oid *, int *, int *, u_char *, int));
extern int smux_process __P((int));
extern void smux_parse_peer_auth __P((char *, char *));
extern void smux_free_peer_auth __P((void));

config_parse_dot_conf("smuxpeer", smux_parse_peer_auth, smux_free_peer_auth);
