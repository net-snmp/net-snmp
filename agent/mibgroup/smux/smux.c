/*
 * Smux module authored by Rohit Dube.
 * Rewritten by Nick Amato <naamato@merit.net>.
 */

#include <config.h>
#include <sys/types.h>
#include <ctype.h>

#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_ERR_H
#include <err.h>
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
#include <errno.h>
#include <netdb.h>

#include <sys/stat.h>
#include <sys/socket.h>
#if HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif

#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include "../../../snmplib/system.h"
#include "asn1.h"
#include "mibincl.h"
#include "mib.h"
#include "read_config.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "smux.h"
#include "var_struct.h"
#include "util_funcs.h"
#include "mibdefs.h"

long smux_long;
u_long smux_ulong;
struct sockaddr_in smux_sa;
struct counter64 smux_counter64;
oid smux_objid[MAX_OID_LEN];
u_char smux_str[SMUXMAXSTRLEN];

extern int sdlist[];
extern int sdlen;
extern int (*sd_handlers[])(int);

static struct timeval smux_rcv_timeout;
static u_long smux_reqid;

int 		init_smux (void);
static u_char	*smux_open_process (int, u_char *, int *, int *);
static u_char	*smux_rreq_process (int, u_char *, int *);
static u_char	*smux_close_process (int, u_char *, int *);
static u_char	*smux_parse (u_char *, oid *, int *, int *, u_char *);
static u_char	*smux_parse_var (u_char *, int *, oid *, int *, int *, u_char *);
static void 	smux_send_close (int, int);
static void 	smux_list_detach (smux_reg **, smux_reg **);
static void 	smux_replace_active (smux_reg *, smux_reg *);
static void 	smux_peer_cleanup (int);
static int 	smux_auth_peer (oid *, int, char *, int);
static int 	smux_build (u_char, u_long, oid *,
                            int *, u_char, u_char *, int, u_char *, int *);
static 		int smux_list_add (smux_reg **, smux_reg *);
static 		int smux_send_rrsp (int, int);
static 		smux_reg *smux_find_replacement (oid *, int);
u_char 		*var_smux (struct variable *, oid *, int *, int, int *,
                           WriteMethod **write_method);
int 		var_smux_write (int, u_char *, u_char, int, u_char *, oid *, int);

static smux_reg *ActiveRegs;		/* Active registrations 		*/
static smux_reg *PassiveRegs;		/* Currently unused registrations 	*/

static smux_peer_auth *Auths[SMUX_MAX_PEERS];	/* Configured peers */
static int nauths, npeers = 0;

struct variable2 smux_variables[] = {
  /* bogus entry, as in pass.c */
  {MIBINDEX, ASN_INTEGER, RWRITE, var_smux, 0, {MIBINDEX}},
};

void
smux_parse_peer_auth( char *token, char *cptr)
{
	smux_peer_auth *aptr;

	if ((aptr = (smux_peer_auth *)calloc(1, sizeof(smux_peer_auth))) == NULL) {
		perror("smux_parse_peer_auth: malloc");
		return;
	}
	aptr->sa_active_fd = -1;
	if (!cptr) {
		/* null passwords OK */
		Auths[nauths++] = aptr;
        	DEBUGMSGTL(("smux_conf", "null password\n"));
		return;
	}

	if(*cptr == '.')
		cptr++;

	if (!isdigit(*cptr)) {
		config_perror("second token is not an OID");
		free((char *)aptr);
		return;
	}
	/* oid */
	aptr->sa_oid_len = parse_miboid(cptr, aptr->sa_oid);

        DEBUGMSGTL(("smux_conf", "parsing registration for: %s\n", cptr));

	while (isdigit(*cptr) || *cptr == '.')
		 cptr++;
	cptr = skip_white(cptr);

        /* password */
        if (cptr)
          strcpy(aptr->sa_passwd, cptr);
        
	Auths[nauths++] = aptr;
}

void
smux_free_peer_auth(void)
{
	int i;

	for(i = 0; i < nauths; i++) {
		free(Auths[i]);
		Auths[i] = NULL;
	}
}

int 
init_smux(void)
{

	struct sockaddr_in lo_socket;
	int smux_sd;
	int one = 1;

        snmpd_register_config_handler("smuxpeer", smux_parse_peer_auth,
                                      smux_free_peer_auth,
                                      "OID-IDENTITY PASSWORD");

	/* Reqid */
	smux_reqid = 0;

	/* Receive timeout */
	smux_rcv_timeout.tv_sec = 0;
	smux_rcv_timeout.tv_usec = 500000;
	
	/* Get ready to listen on the SMUX port*/
	memset (&lo_socket,(0), sizeof (lo_socket));
	lo_socket.sin_family = AF_INET;
	lo_socket.sin_port = htons((u_short) SMUXPORT);

	if ((smux_sd = socket (AF_INET, SOCK_STREAM, 0)) <  0) {
		perror("[init_smux] socket failed\n");
		return SMUXNOTOK;
	}
	if (bind (smux_sd, (struct sockaddr *) &lo_socket, 
	    sizeof (lo_socket)) < 0) {
		perror("[init_smux] bind failed\n");
		close(smux_sd);
		return SMUXNOTOK;
	}

	if (setsockopt (smux_sd, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, 
			sizeof (one)) < 0) {
		perror("[init_smux] setsockopt(SO_KEEPALIVE) failed\n");
		close(smux_sd);
		return SMUXNOTOK;
	}
	if(listen(smux_sd, SOMAXCONN) == -1) {
		perror("[init_smux] listen failed\n");
		close(smux_sd);
		return SMUXNOTOK;
	}
	sdlist[sdlen] = smux_sd;
	sd_handlers[sdlen++] = smux_accept;

	fprintf(stderr, "sdlen in smux_init: %d\n", sdlen);
	fprintf(stderr, "[smux_init] done; smux_sd is %d, smux_port is %d\n", smux_sd,
		 lo_socket.sin_port);

	return SMUXOK;
}

u_char *
var_smux(struct variable *vp,
	oid *name,
	int *length,
	int exact,
	int *var_len,
	WriteMethod **write_method)
{
	u_char *valptr, val_type;
	smux_reg *rptr;

	*write_method = NULL;

	/* search the active registration list */
	for (rptr = ActiveRegs; rptr; rptr = rptr->sr_next) {
		if (!compare_tree(name, *length, rptr->sr_name,
		    rptr->sr_name_len))
			break;
	}
	if (rptr == NULL)
		return NULL;
	else if (exact && (*length <= rptr->sr_name_len))
		return NULL;

	*write_method = var_smux_write; 
	valptr = smux_snmp_process(exact, name, length,
	    var_len, &val_type, rptr->sr_fd);

	if ((compare_tree(name, *length, rptr->sr_name,
	    rptr->sr_name_len)) != 0) {
		/* the peer has returned a value outside
		 * of the registered tree
		 */
		return NULL;
	} else {
		/* set the type and return the value */
		vp->type = val_type;
		return valptr;
	}
}

int 
var_smux_write(
	int action,
	u_char *var_val,
	u_char var_val_type,
	int var_val_len,
	u_char *statP,
	oid *name,
	int name_len)
{
	smux_reg *rptr;
	u_char buf[SMUXMAXPKTSIZE], *ptr, sout[6], type;
	int len, reterr;
	u_long reqid, errsts, erridx;

	len = SMUXMAXPKTSIZE;

	/* XXX find the descriptor again */
	for (rptr = ActiveRegs; rptr; rptr = rptr->sr_next) {
		if(!compare_tree(name, name_len, rptr->sr_name,
		     rptr->sr_name_len))
			break;
	}
	if (action == COMMIT) {
		if ((smux_build((u_char)SMUX_SET, smux_reqid, name,
		    &name_len, var_val_type, statP, var_val_len,
		     buf, &len)) == 0) {
			DEBUGMSGTL (("smux","[var_smux_write] smux build failed\n"));
			return SNMP_ERR_GENERR;	/* ? */
		}
	}
	if (send(rptr->sr_fd, buf, len, 0) < 0) {
		DEBUGMSGTL (("smux","[var_smux_write] send failed\n"));
		return SNMP_ERR_GENERR; /* ? */
	}
	if ((len = recv(rptr->sr_fd, buf, SMUXMAXPKTSIZE, 0)) <= 0) {
		DEBUGMSGTL (("smux","[var_smux_write] recv failed or timed out\n"));
		smux_peer_cleanup(rptr->sr_fd);
		return SNMP_ERR_GENERR; /* ? */
	}
	ptr = buf;
	ptr = asn_parse_int(ptr, &len, &type, &reqid, sizeof(reqid));
	if ((ptr == NULL) || type != ASN_INTEGER) 
		return SNMP_ERR_GENERR;
	ptr = asn_parse_int(ptr, &len, &type, &errsts, sizeof(errsts));
	if ((ptr == NULL) || type != ASN_INTEGER) 
		return SNMP_ERR_GENERR;
	ptr = asn_parse_int(ptr, &len, &type, &erridx, sizeof(erridx));
	if ((ptr == NULL) || type != ASN_INTEGER) 
		return SNMP_ERR_GENERR;

	ptr = sout;
	len = 6;
	if ((ptr = asn_build_sequence(ptr, &len,
	    (u_char)SMUX_SOUT, 2)) == NULL)
		return SNMP_ERR_GENERR;
	*(ptr++) = (u_char)1;

	if((errsts == 0) && (erridx == 0)) {
		*ptr = (u_char)0;
		reterr = SNMP_ERR_NOERROR;
	} else {
		*ptr = (u_char)1;
		reterr = SNMP_ERR_COMMITFAILED;
	}
	if ((send(rptr->sr_fd, sout, 6, 0)) < 0) {
		DEBUGMSGTL (("smux","[var_smux_write] send sout failed\n"));
		return SNMP_ERR_GENERR;
	}
	return reterr;
}

int
smux_accept(int sd)
{
	u_char data[SMUXMAXPKTSIZE], *ptr, type;
	struct sockaddr_in in_socket;
	struct timeval tv;
	int fail, fd, len;

	len = sizeof(struct sockaddr_in);
	/* this may be too high */
	tv.tv_sec = 5;
	tv.tv_usec = 0;

	/* connection request */
	DEBUGMSGTL (("smux","[smux_accept] Calling accept()\n"));
	errno = 0;
	if((fd = accept(sd, (struct sockaddr *)&in_socket, &len)) < 0) {
		perror("[smux_accept] accept failed\n");
		return SMUXNOTOK;
	} else {
		fprintf(stderr, "[smux_accept] accepted fd %d - errno %d\n", fd, errno);
		if (npeers + 1 == SMUXMAXPEERS) {
			DEBUGMSGTL (("smux","[smux_accept] denied peer on fd %d, limit reached", fd));
			close(sd);
			return SMUXNOTOK;
		}
		/* now block for an OpenPDU */
		if ((len = recv(fd, data, SMUXMAXPKTSIZE, 0)) <= 0) {
			DEBUGMSGTL (("smux","[smux_accept] peer on fd %d died or timed out\n", fd));
			close(fd);
			return SMUXNOTOK;
		}
		/* try to authorize him */
		ptr = data;
		if ((ptr = asn_parse_header(ptr, &len, &type)) == NULL) {
			smux_send_close(fd, SMUXC_PACKETFORMAT);
			close(fd);
			DEBUGMSGTL (("smux","[smux_accept] peer on %d sent bad open"));
			return SMUXNOTOK;
		} else if (type != (u_char)SMUX_OPEN) {
			smux_send_close(fd, SMUXC_PROTOCOLERROR);
			close(fd);
			DEBUGMSGTL (("smux","[smux_accept] peer on %d did not send open: (%d)\n", type));
			return SMUXNOTOK;
		}
		ptr = smux_open_process(fd, ptr, &len, &fail);
		if (fail) {
			smux_send_close(fd, SMUXC_AUTHENTICATIONFAILURE);
			close(fd);
			DEBUGMSGTL (("smux","[smux_accept] peer on %d failed authentication\n", fd));
			return SMUXNOTOK;
		}

		/* he's OK */
#ifdef SO_RCVTIMEO
		if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (void *)&tv, sizeof(tv)) < 0) {
			DEBUGMSGTL (("smux","[smux_accept] setsockopt(SO_RCVTIMEO) failed fd %d\n", fd));
                        perror("smux/setsockopt");
                }
#endif

		npeers++;
		sdlist[sdlen] = fd;
		sd_handlers[sdlen++] = smux_process;

		DEBUGMSGTL (("smux","[smux_accept] fd %d, sdlen %d\n", fd, sdlen));
	}

	return SMUXOK;
}

int
smux_process(int fd)
{
	int error, len, length;
	u_char data[SMUXMAXPKTSIZE], *ptr, type;

	length = recv(fd, data, SMUXMAXPKTSIZE, 0);
	if (length <= 0) {
		/* the peer went away, close this descriptor 
		 * and delete it from the list
		 */
		DEBUGMSGTL (("smux","[smux_process] peer on fd %d died or timed out\n", fd));
		smux_peer_cleanup(fd);
		return SMUXNOTOK; /* return value ignored */
	}

	DEBUGMSGTL (("smux","[smux_process] Processing %d bytes\n", length));

	error = SMUXOK;

	ptr = data;
	len = length;
	while (ptr != NULL && ptr < data + length) {
		len = length;
		ptr = asn_parse_header(ptr, &len, &type);
		DEBUGMSGTL (("smux","[smux_process] type is %d\n", (int) type));
		switch (type) {
		case SMUX_OPEN:
			smux_send_close(fd, SMUXC_PROTOCOLERROR);
			DEBUGMSGTL (("smux","[smux_process] peer on fd %d sent duplicate open?\n", fd));
			smux_peer_cleanup(fd);
			break;
		case SMUX_CLOSE:
			ptr = smux_close_process(fd, ptr, &len);
			smux_peer_cleanup(fd);
			break;
		case SMUX_RREQ:
			ptr = smux_rreq_process(fd, ptr, &len);
			break;
		case SMUX_RRSP:
			error = SMUXNOTOK;
			ptr = NULL;
			smux_send_close(fd, SMUXC_PROTOCOLERROR);
			smux_peer_cleanup(fd);
			DEBUGMSGTL (("smux","[smux_process] peer on fd %d sent RRSP!\n", fd));
			break;
		case SMUX_SOUT:
			error = SMUXNOTOK;
			ptr = NULL;
			smux_send_close(fd, SMUXC_PROTOCOLERROR);
			smux_peer_cleanup(fd);
			DEBUGMSGTL (("smux","This shouldn't have happened!\n"));
			break;
		default:
			smux_send_close(fd, SMUXC_PACKETFORMAT);
			smux_peer_cleanup(fd);
                        DEBUGMSGTL (("smux","[smux_process] Wrong type %d\n", (int)type));
			error = SMUXNOTOK;
			break;
		}
	}
	return error; /* return value ignored */
}

static u_char *
smux_open_process(int fd, u_char *ptr, int *len, int *fail)
{
	u_char type;
	u_long version;
	oid oid_name[MAX_OID_LEN];
	u_char string[SMUXMAXSTRLEN];
	int i, oid_name_len, string_len;

	if ((ptr = asn_parse_int(ptr, len, &type, &version, 
	    sizeof(version))) == NULL) {
		DEBUGMSGTL (("smux","[smux_open_process] version parse failed\n"));
		*fail = TRUE;
		return((ptr += *len));
	}
	DEBUGP("[smux_open_process] version %d, len %d, type %d\n", 
		version, *len, (int)type);

	oid_name_len = MAX_OID_LEN;
	if ((ptr = asn_parse_objid(ptr, len, &type, oid_name,
	    &oid_name_len)) == NULL) {
		DEBUGMSGTL (("smux","[smux_open_process] oid parse failed\n"));
		*fail = TRUE;
		return((ptr += *len));
	}

        if (snmp_get_do_debugging()) {
          DEBUGMSGTL (("smux","[smux_open_process] smux peer:")); 
          for (i=0; i<oid_name_len; i++) 
            DEBUGMSG (("smux",".%d", oid_name[i]));
          DEBUGMSG (("smux"," \n"));
          DEBUGMSGTL (("smux","[smux_open_process] len %d, type %d\n", *len, (int)type));
        }

	string_len = SMUXMAXSTRLEN;
	if ((ptr = asn_parse_string(ptr, len, &type, string,
	    &string_len)) == NULL) {
		DEBUGMSGTL (("smux","[smux_open_process] descr parse failed\n"));
		*fail = TRUE;
		return((ptr += *len));
	}

        if (snmp_get_do_debugging()) {
          DEBUGMSGTL (("smux","[smux_open_process] smux peer descr:")); 
          for (i=0; i<string_len; i++) 
            DEBUGMSG (("smux","%c", string[i]));
          DEBUGMSG (("smux"," \n"));
          DEBUGMSGTL (("smux","[smux_open_process] len %d, type %d\n", *len, (int)type));
        }

	string_len = SMUXMAXSTRLEN;
	if ((ptr = asn_parse_string(ptr, len, &type, string,
	    &string_len)) == NULL) {
		DEBUGMSGTL (("smux","[smux_open_process] passwd parse failed\n"));
		*fail = TRUE;
		return((ptr += *len));
	}

        if (snmp_get_do_debugging()) {
          DEBUGMSGTL (("smux","[smux_open_process] smux peer passwd:")); 
          for (i=0; i<string_len; i++) 
            DEBUGMSG (("smux","%c", string[i]));
          DEBUGMSG (("smux"," \n"));
          DEBUGMSGTL (("smux","[smux_open_process] len %d, type %d\n", *len, (int)type));
        }
	string[string_len] = '\0';
	if(!smux_auth_peer(oid_name, oid_name_len, string, fd)) {
		if(snmp_get_do_debugging()) {
		    DEBUGMSGTL (("smux","[smux_open_process] peer authentication failed for oid\n"));
		    for (i = 0; i < oid_name_len; i++) 
			DEBUGMSG (("smux","\t.%d", oid_name[i]));
		    DEBUGMSG (("smux"," password %s\n", string));
		}
		*fail = TRUE;
		return ptr;
	}
	*fail = FALSE;
	return ptr;
}

static void
smux_send_close(int fd, int reason)
{
    u_char outpacket[3], *ptr;

    ptr = outpacket;

    *(ptr++) = (u_char)SMUX_CLOSE;
    *(ptr++) = (u_char)1;
    *ptr = (u_char)(reason & 0xFF);

    if(snmp_get_do_debugging()) 
	DEBUGMSGTL (("smux","[smux_close] sending close to fd %d, reason %d\n", fd, reason));

    /* send a response back */ 
    if (send (fd, outpacket, 3, 0) < 0) {
	perror("[smux_send_close] send failed\n");
    }
}
        

static int
smux_auth_peer(oid *name, int namelen, char *passwd, int fd)
{
	int i;

	for (i = 0; i < nauths; i++) {
		if (snmp_oid_compare(Auths[i]->sa_oid, Auths[i]->sa_oid_len,
		    name, namelen) == 0) {
			if(!(strcmp(Auths[i]->sa_passwd, passwd)) &&
			    (Auths[i]->sa_active_fd == -1)) {
				/* matched, mark the auth */
				Auths[i]->sa_active_fd = fd;
				return 1;
			}
			else
				return 0;
		}
	}
	/* did not match oid and passwd */
	return 0;
}


/* 
 * XXX - Bells and Whistles:
 * Need to catch signal when snmpd goes down and send close pdu to gated 
 */
static u_char *
smux_close_process(int fd, u_char *ptr, int *len)
{
	long down = 0;
	int length = *len;

	/* This is the integer part of the close pdu */
	while (length--) {
		down = (down << 8) | (long)*ptr;
		ptr++;
	}

	DEBUGMSGTL (("smux","[smux_close_process] close from peer on fd %d reason %d\n", fd, down));
	smux_peer_cleanup(fd);

	return NULL;
}

static u_char *
smux_rreq_process(int sd, u_char *ptr, int *len)
{
	u_long priority;
	u_long operation;
	oid oid_name[MAX_OID_LEN];
	int oid_name_len, i, result;
	u_char type;
        char c_oid[SPRINT_MAX_LEN];
	smux_reg *rptr, *nrptr;

	oid_name_len = MAX_OID_LEN;
	ptr = asn_parse_objid(ptr, len, &type, oid_name, &oid_name_len); 

        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, oid_name, oid_name_len);
          DEBUGMSGTL (("smux","[smux_rreq_process] smux subtree: %s\n", c_oid)); 
        }
	if ((ptr = asn_parse_int(ptr, len, &type, &priority, 
	    sizeof(priority))) == NULL) {
		DEBUGMSGTL (("smux","[smux_rreq_process] priority parse failed\n"));
		return NULL;
	}
	DEBUGMSGTL (("smux","[smux_rreq_process] priority %d\n", priority));

	if ((ptr = asn_parse_int(ptr, len, &type, &operation, 
	    sizeof(operation))) == NULL) {
		DEBUGMSGTL (("smux","[smux_rreq_process] operation parse failed\n"));
		return NULL;
	}
	DEBUGMSGTL (("smux","[smux_rreq_process] operation %d\n", operation));

	if(operation == SMUX_REGOP_DELETE) {
		/* search the active list for this registration */
		for (rptr = ActiveRegs; rptr; rptr = rptr->sr_next) {
			if ((rptr->sr_fd == sd) && !(snmp_oid_compare(rptr->sr_name,
			    rptr->sr_name_len, oid_name, oid_name_len)) &&
			    (rptr->sr_priority == priority)) {
				/* unregister the mib */
				unregister_mib(rptr->sr_name, rptr->sr_name_len);
				/* find a replacement */
				if ((nrptr = smux_find_replacement(rptr->sr_name,
				    rptr->sr_name_len)) == NULL) {
					/* no replacement found */
					smux_list_detach(&ActiveRegs, &nrptr);
					free(nrptr);
				} else {
					/* found one */
					smux_replace_active(rptr, nrptr);
				}
				return ptr;
			}
		}
		/* search the passive list for this registration */
		for (rptr = PassiveRegs; rptr; rptr = rptr->sr_next) {
			if ((rptr->sr_fd == sd) && !(snmp_oid_compare(rptr->sr_name,
			    rptr->sr_name_len, oid_name, oid_name_len)) &&
			    (rptr->sr_priority == priority)) {
				smux_list_detach(&PassiveRegs, &nrptr);
				free(nrptr);
			}
		}
		/* this peer cannot unregister the tree, it does not
		 * belong to him.  XXX for now, ignore it.
		 */
		return ptr;
	}

	if (operation == SMUX_REGOP_REGISTER) {
		if (priority < -1) {
			DEBUGMSGTL (("smux","[smux_rreq_process] peer fd %d invalid priority", sd, priority));
			return NULL;
		}
		if((nrptr = malloc(sizeof(smux_reg))) == NULL) {
			perror("[smux_rreq_process] malloc");
			return NULL;
		}
		nrptr->sr_priority = priority;
		nrptr->sr_name_len = oid_name_len;
		nrptr->sr_fd = sd;
		for(i = 0; i < oid_name_len; i++)
			nrptr->sr_name[i] = oid_name[i];

		/* See if this tree matches or scopes any of the
		 * active trees.
		 */
		for (rptr = ActiveRegs; rptr; rptr = rptr->sr_next) {
			result = snmp_oid_compare(oid_name, oid_name_len, rptr->sr_name,
			    rptr->sr_name_len);
			if (result == 0) {
				if ((oid_name_len == rptr->sr_name_len)) {
					if ((nrptr->sr_priority == -1)) {
						nrptr->sr_priority = rptr->sr_priority;
						do {
							nrptr->sr_priority++;
						} while(smux_list_add(&PassiveRegs, nrptr));
						goto done;
					}
					else if (nrptr->sr_priority < rptr->sr_priority) {
						/* Better priority.  There are no better
						 * priorities for this tree in the passive list,
						 * so replace the current active tree.
						 */
						smux_replace_active(rptr, nrptr);
						goto done;
					} else {
						/* Equal or worse priority */
						do {
							nrptr->sr_priority++;
						} while (smux_list_add(&PassiveRegs, nrptr) == -1);
						goto done;
					}
				} else if (oid_name_len < rptr->sr_name_len) {
					/* This tree scopes a current active
					 * tree.  Replace the current active tree.
					 */
					smux_replace_active(rptr, nrptr);
					goto done;
				} else { /* oid_name_len > rptr->sr_name_len */
					/* This tree is scoped by a current
					 * active tree.  
					 */
					do {
						nrptr->sr_priority++;
					} while (smux_list_add(&PassiveRegs, nrptr) == -1);
					goto done;
				}
			}
		}
		/* We didn't find it in the active list.  Add it at
		 * the requested priority.
		 */
		if (nrptr->sr_priority == -1)
			nrptr->sr_priority = 0;
		smux_list_add(&ActiveRegs, nrptr);
		register_mib("smux", (struct variable *)
		    smux_variables, sizeof(struct variable2),
		    1, nrptr->sr_name, nrptr->sr_name_len);
done:
		if (smux_send_rrsp(sd, nrptr->sr_priority)) 
			DEBUGMSGTL (("smux","[smux_rreq_process]  send failed\n"));
		return ptr;
	}

	DEBUGMSGTL (("smux","[smux_rreq_process] unknown operation\n"));
	return NULL;
}

static void
smux_replace_active(smux_reg *actptr, smux_reg *pasptr)
{
	smux_list_detach(&ActiveRegs, &actptr);
	unregister_mib(actptr->sr_name, actptr->sr_name_len);

	smux_list_detach(&PassiveRegs, &pasptr);
	(void)smux_list_add(&ActiveRegs, pasptr);

	register_mib("smux", (struct variable *)smux_variables,
	    sizeof(struct variable2), 1, pasptr->sr_name,
	    pasptr->sr_name_len);
	free(actptr);
}

static void
smux_list_detach(smux_reg **head, smux_reg **m_remove)
{
	smux_reg *rptr, *rptr2;

	if (*head == NULL) {
		DEBUGMSGTL (("smux","[smux_list_detach] Ouch!"));
		return;
	}
	if (*head == *m_remove) {
		*m_remove = *head;
		*head = (*head)->sr_next;
		return;
	}
	for (rptr = *head, rptr2 = rptr->sr_next; rptr2;
	    rptr2 = rptr2->sr_next, rptr = rptr->sr_next) {
		if(rptr2 == *m_remove) {
			*m_remove = rptr2;
			rptr->sr_next = rptr2->sr_next;
			return;
		}
	}
}

/*
 * Attempt to add a registration (in order) to a list.  If the
 * add fails (because of an existing registration with equal
 * priority) return -1.
 */
static int
smux_list_add(smux_reg **head, smux_reg *add)
{
	smux_reg *rptr;
	int result;

	if(*head == NULL) {
		*head = add;
		(*head)->sr_next = NULL;
		return 0;
	}
	for (rptr = *head; rptr->sr_next; rptr = rptr->sr_next) {
		result = snmp_oid_compare(add->sr_name, add->sr_name_len,
		    rptr->sr_name, rptr->sr_name_len);
		if ((result == 0) && (add->sr_priority == rptr->sr_priority)) {
			/* same tree, same pri, nope */
			return -1;
		} else if (result < 0) {
			/* this can only happen if we go before the head */
			add->sr_next = *head;
			*head = add;
			return 0;
		} else if ((snmp_oid_compare(add->sr_name, add->sr_name_len,
		    rptr->sr_next->sr_name, rptr->sr_next->sr_name_len)) < 0) {
			/* insert here */
			add->sr_next = rptr->sr_next;
			rptr->sr_next = add;
			return 0;
		}
	}
	/* compare the last one */
	if ((snmp_oid_compare(add->sr_name, add->sr_name_len, rptr->sr_name,
	    rptr->sr_name_len) == 0) && add->sr_priority == rptr->sr_priority)
		return -1;
	else {
		rptr->sr_next = add;
		add->sr_next = NULL;
	}
	return 0;
}

/*
 * Find a replacement for this registration.  In order
 * of preference:
 *
 * 	- Least difference in subtree length
 *	- Best (lowest) priority
 *
 * For example, if we need to replace .1.3.6.1.69, 
 * we would pick .1.3.6.1.69.1 instead of .1.3.6.69.1.1
 *
 */
static smux_reg *
smux_find_replacement(oid *name, int name_len)
{
	smux_reg *rptr, *bestptr;
	int bestlen, difflen;

	bestlen = SMUX_MAX_PRIORITY;
	bestptr = NULL;

	for (rptr = PassiveRegs; rptr; rptr = rptr->sr_next) {
		if (!compare_tree(rptr->sr_name, rptr->sr_name_len,
		    name, name_len)) {
			if ((difflen = rptr->sr_name_len - name_len)
			    < bestlen) {
				bestlen = difflen;
				bestptr = rptr;
			} else if ((difflen == bestlen) &&
			    (rptr->sr_priority < bestptr->sr_priority)) 
				bestptr = rptr;
		}
	}
	return bestptr;
}

u_char *
smux_snmp_process(int exact,
	oid *objid,
	int *len,
	int *return_len,
	u_char *return_type,
	int sd)
{
	u_char packet[SMUXMAXPKTSIZE], *ptr, result[SMUXMAXPKTSIZE];
	int length = SMUXMAXPKTSIZE;
	u_char type;
        char c_oid[SPRINT_MAX_LEN];
	
	/* 
	 * Send the query to the peer
	 */
	smux_reqid++;

	if (exact)
		type = SMUX_GET;
	else
		type = SMUX_GETNEXT;

	if (smux_build(type, smux_reqid, objid, len, 0, NULL, 
	    *len, packet, &length) != SMUXOK) {
		printf("[smux_snmp_process]: smux_build failed\n");
		return NULL;
	}
        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, objid, *len);
          DEBUGMSGTL (("smux","[smux_snmp_process] oid from build: %s\n",c_oid));
        }

	if (send(sd, packet, length, 0) < 0) {
		perror("[smux_snmp_process] send failed\n");
	}

	DEBUGP("[smux_snmp_process] Sent %d request to peer; %d bytes\n", 
		(int)type, length);
	/* 
	 * receive 
	 * XXX the RCVTIMEO could return a short result.
	 */
	length = recv(sd, result, SMUXMAXPKTSIZE, 0);
	if (length < 0) {
		perror("[smux_snmp_process] recv failed\n");
		smux_peer_cleanup(sd);
		return NULL;
	}

	DEBUGMSGTL (("smux","[smux_snmp_process] Recived %d bytes from gated\n", length));

	/* Interpret reply */
	if ((ptr = smux_parse(result, objid, len, return_len, return_type)) == NULL) {
		smux_send_close(sd, SMUXC_PACKETFORMAT);
		return NULL;
	}

	return ptr;
}

static u_char *
smux_parse(u_char *rsp,
	oid *objid,
	int *oidlen,
	int *return_len,
	u_char *return_type)
{
	int length = SMUXMAXPKTSIZE; 
	u_char *ptr, type;
	u_long reqid, errstat, errindex;

	ptr = rsp;

	/*
	 * Return pointer to the snmp/smux return value.
	 * return_len should contain the number of bytes in the value
	 * returned above.
	 * objid is the next object, with len for GETNEXT.
	 * objid and len are not changed for GET
	 */ 
	ptr = asn_parse_header(ptr, &length, &type);
	if (ptr == NULL || type != SNMP_MSG_RESPONSE)
		return NULL;

	if ((ptr = asn_parse_int(ptr, &length, &type, &reqid,
	    sizeof(reqid))) == NULL) {
		DEBUGMSGTL (("smux","[smux_parse] parse of reqid failed\n"));
		return NULL;
	}
	if ((ptr = asn_parse_int(ptr, &length, &type, &errstat,
	    sizeof(errstat))) == NULL) {
		DEBUGMSGTL (("smux","[smux_parse] parse of error status failed\n"));
		return NULL;
	}
	if ((ptr = asn_parse_int(ptr, &length, &type, &errindex,
	    sizeof(errindex))) == NULL) {
		DEBUGMSGTL (("smux","[smux_parse] parse of error index failed\n"));
		return NULL;
	}

	/* XXX How to send something intelligent back in case of an error */
	DEBUGMSGTL (("smux","[smux_parse] Message type %d, reqid %d, errstat %d, \n\terrindex %d\n", (int)type, reqid, errstat, errindex));
	if (ptr == NULL || errstat != SNMP_ERR_NOERROR)
		return NULL;

	/* stuff to return */
	return (smux_parse_var(ptr, &length, objid, oidlen, return_len, return_type));
}


static u_char *
smux_parse_var(u_char *varbind,
	int *varbindlength,
	oid *objid,
	int *oidlen,
	int *varlength,
	u_char *vartype)
{
	oid var_name[MAX_OID_LEN];
	int var_name_len;
	int var_val_len;
	u_char *var_val;
	int str_len, objid_len;
	int len;
	u_char *ptr;
	u_char type;
        char c_oid[SPRINT_MAX_LEN];
        
	ptr = varbind;
	len = *varbindlength;

        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, objid, *oidlen);
          DEBUGMSGTL (("smux","[smux_parse_var] before any processing: %s\n", c_oid));
        }

	ptr = asn_parse_header(ptr, &len, &type);
	if (ptr == NULL || type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
		printf ("[smux_parse_var] Panic: type %d\n", (int)type);
		return NULL;
	}

	/* get hold of the objid and the asn1 coded value */
	var_name_len = MAX_OID_LEN;
	ptr = snmp_parse_var_op(ptr, var_name, &var_name_len, vartype,
				&var_val_len, &var_val, &len);

	*oidlen = var_name_len;
	memcpy( objid,var_name, var_name_len * sizeof(oid));

        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, objid, *oidlen);
          DEBUGMSGTL (("smux","[smux_parse_var] returning oid : %s\n", c_oid));
        }
	/* XXX */
	len = SMUXMAXPKTSIZE;
        DEBUGP("[smux_parse_var] Asn coded len of var %d, type %d\n", 
		var_val_len, (int)*vartype);

	switch((short)*vartype){
	case ASN_INTEGER:
		*varlength = sizeof(long);
		asn_parse_int(var_val, &len, vartype,
			      (long *)&smux_long, *varlength);
		return (u_char *)&smux_long;
		break;
	    case ASN_COUNTER:
	    case ASN_GAUGE:
	    case ASN_TIMETICKS:
	    case ASN_UINTEGER:
		*varlength = sizeof(u_long);
		asn_parse_unsigned_int(var_val, &len, vartype,
			      (u_long *)&smux_ulong, *varlength);
		return (u_char *)&smux_ulong;
		break;
	    case ASN_COUNTER64:
		*varlength = sizeof(smux_counter64);
		asn_parse_unsigned_int64(var_val, &len, vartype,
					 (struct counter64 *)&smux_counter64,
					 *varlength);
		return (u_char *)&smux_counter64;
		break;
	    case ASN_IPADDRESS:
		*varlength = 4;
		/* 
		 * XXX - skip tag and length. We already know this is an ip 
		 * address
		 */
		memcpy((u_char *)&(smux_sa.sin_addr.s_addr), var_val+2,
		      *varlength);
		return (u_char *)&(smux_sa.sin_addr.s_addr);
		break;
	    case ASN_OCTET_STR:
		/* XXX */
		if (len == 0)
			return NULL;
		str_len = SMUXMAXSTRLEN;
		asn_parse_string(var_val, &len, vartype,
				 smux_str, &str_len);
		*varlength = str_len;
		return smux_str;
		break;
	    case ASN_OPAQUE:
	    case ASN_NSAP:
	    case ASN_OBJECT_ID:
		objid_len = MAX_OID_LEN;
		asn_parse_objid(var_val, &len, vartype, 
				smux_objid, &objid_len);
		*varlength = objid_len;
		return (u_char *)smux_objid;
		break;
            case SNMP_NOSUCHOBJECT:
            case SNMP_NOSUCHINSTANCE:
            case SNMP_ENDOFMIBVIEW:
	    case ASN_NULL:
	    	return NULL;
		break;
	    case ASN_BIT_STR:
		/* XXX */
		if (len == 0)
			return NULL;
		str_len = SMUXMAXSTRLEN;
		asn_parse_bitstring(var_val, &len, vartype,
				 smux_str, &str_len);
		*varlength = str_len;
		return (u_char *)smux_str;
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", *vartype);
		return NULL;
		break;
	}
}

/* XXX This is a bad hack - do not want to muck with ucd code */
static int
smux_build(u_char type,
	u_long reqid,
	oid *objid,
	int *oidlen,
	u_char val_type,
	u_char *val,
	int val_len,
	u_char *packet,
	int *length)
{
	u_char *ptr, *save1, *save2;
	int len;
	long errstat = 0;
	long errindex = 0;

	/* leave space for Seq and length */
	save1 = packet;
	ptr = packet + 4;
	len = *length - 4;
	
	/* build reqid */
	ptr = asn_build_int(ptr, &len, 
	      (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	      &reqid, sizeof(reqid));

	/* build err stat */
	ptr = asn_build_int(ptr, &len, 
	      (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	      &errstat, sizeof(errstat));

	/* build err index */
	ptr = asn_build_int(ptr, &len, 
	      (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
	      &errindex, sizeof(errindex));

	save2 = ptr;
	ptr += 4;
	len -= 4;

	if (type != SMUX_SET) {
		val_type = ASN_NULL;
		val_len = 0;
	}

	/* build var list : snmp_build_var_op not liked by gated XXX */
	ptr = snmp_build_var_op(ptr, objid, oidlen, val_type, val_len,
	    val, &len);

	len = ptr - save1;
	asn_build_sequence(save1, &len, type,
	    (ptr - save1 - 4));

	len = ptr - save2;
	asn_build_sequence(save2, &len,
	    (ASN_SEQUENCE | ASN_CONSTRUCTOR), (ptr - save2 - 4));

	*length = ptr - packet;

	return SMUXOK;
}

static void
smux_peer_cleanup(int sd)
{
	smux_reg *nrptr, *rptr, *rptr2;
	int nfound, i;

	nfound = 0;

	/* close the descriptor */
	close(sd);

	/* delete all of the passive registrations that this peer owns */
	for (rptr = PassiveRegs; rptr; rptr = nrptr) {
		nrptr = rptr->sr_next;
		if (rptr->sr_fd == sd) {
			smux_list_detach(&PassiveRegs, &rptr);
			free(rptr);
		}
		rptr = nrptr;
	}
	/* find replacements for all of the active registrations found */
	for (rptr = ActiveRegs; rptr; rptr = rptr2) {
		rptr2 = rptr->sr_next;
		if (rptr->sr_fd == sd) {
			smux_list_detach(&ActiveRegs, &rptr);
			unregister_mib(rptr->sr_name, rptr->sr_name_len);
			if ((nrptr = smux_find_replacement(rptr->sr_name,
			     rptr->sr_name_len)) != NULL) {
				smux_list_detach(&PassiveRegs, &nrptr);
				smux_list_add(&ActiveRegs, nrptr);
				register_mib("smux", (struct variable *)
				    smux_variables, sizeof(struct variable2), 
				    1, nrptr->sr_name, nrptr->sr_name_len);
			}
			free(rptr);
		}
	}
	/* XXX stop paying attention to his socket */
	for (i = 0; i < sdlen; i++) {
		if (sdlist[i] == sd) {
			for (; i < (sdlen-1); i++) {
				sdlist[i] = sdlist[i+1];
				sd_handlers[i] = sd_handlers[i+1];
			}
		}
	}
	sdlen--;

	/* decrement the peer count */
	npeers--;

	/* make his auth available again */
	for (i = 0; i < nauths; i++) {
		if (Auths[i]->sa_active_fd == sd) {
			Auths[i]->sa_active_fd = -1;
		}
	}
}

int 
smux_send_rrsp(int sd, int pri)
{
	u_char outdata[6], *ptr;
	int i, mask;

	ptr = outdata;
	/* "mask is 0xFF000000 on a big-endian machine" */
	mask = 0xFF;

	*(ptr++) = (u_char) SMUX_RRSP;
	*ptr = (u_char) 4;

	for(i = 0; i < 4; i++, mask >>= 8)
		*(++ptr) = (u_char)(pri & mask);

	if((send(sd, outdata, 6, 0)) < 0)
		return SMUXNOTOK;
	else
		return SMUXOK;
}

