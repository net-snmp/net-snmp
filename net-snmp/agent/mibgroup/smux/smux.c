/* $Id$ */

/*
 * Smux module authored by Rohit Dube.
 */

#include <config.h>

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

#if HAVE_SGTTY_H
#include <sgtty.h>
#endif

#ifndef FD_COPY
#define FD_COPY(f, t)   memcpy(t, f, sizeof(*(f)))
#endif

#include "../../../snmplib/system.h"
#include "asn1.h"
#include "mib.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "smux.h"

long smux_long;
u_long smux_ulong;
struct sockaddr_in smux_sa;
struct counter64 smux_counter64;
oid smux_objid[MAX_OID_LEN];
u_char smux_str[SMUXMAXSTRLEN];
u_char smux_type;

static int smux_mibs[SMUXMIBS];
static int nfds;
static fd_set sfds, rfds, ifds;
static u_short smux_port;
static int smux_sd;
static int gated_sd;
static struct timeval smux_rcv_timeout;

static u_long smux_reqid;

static u_char rrsp_can[] = {0x43, 0x01, 0x00};

static u_char debug_can[] = {
0xa0, 0x1a, 0x02, 0x01,
0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30,  0x0f, 0x30, 0x0d, 0x06, 0x09, 
0x2b, 0x06, 0x01, 
0x02, 0x01, 0x17, 0x01, 0x01, 0x00, 0x05, 0x00
};


u_char *smux_snmp_process __P((int, oid *, int *, int *));
int init_smux __P((void));

static u_char *smux_open_process __P((u_char *, int *));
static u_char *smux_rreq_process __P((int, u_char *, int *));
static u_char *smux_sout_process __P((u_char *, int *));
static u_char *smux_close_process __P((int, u_char *, int *));
static u_char *smux_parse __P((u_char *, oid *, int *, int *));
static u_char *smux_parse_var __P((u_char *, int *, oid *, int *, int *));
static int smux_build __P((u_char, u_long, oid *, int *, u_char *, int *));
static void print_fdbits __P((fd_set *));

int 
init_smux __P((void))
{
	struct sockaddr_in lo_socket;
	int one = 1;

	/* init the fdsets */
	nfds = 0;
	FD_ZERO(&sfds);
	FD_ZERO(&rfds);
	FD_ZERO(&ifds);

	/* Gated hasn't registered yet */
	/* TODO: init the register structure */

	/* Reqid */
	smux_reqid = 0;

	/* Receive timeout */
	smux_rcv_timeout.tv_sec = 0;
	smux_rcv_timeout.tv_usec = 500000;
	
	/* what is the smux port */
	smux_port =  htons((u_short) SMUXPORT);

	/* Get ready to listen on the SMUX port*/
	memset (&lo_socket,(0), sizeof (lo_socket));
	lo_socket.sin_family = AF_INET;
	lo_socket.sin_port = smux_port;

	if ((smux_sd = socket (AF_INET, SOCK_STREAM, 0)) <  0) {
		perror("[init_smux] socket failed");
		return SMUXNOTOK;
	}

	if (bind (smux_sd, (struct sockaddr *) &lo_socket, 
	    sizeof (lo_socket)) < 0) {
		perror("[init_smux] bind failed");
		close(smux_sd);
		return SMUXNOTOK;
	}

	if (setsockopt (smux_sd, SOL_SOCKET, SO_KEEPALIVE, (char *)&one, 
			sizeof (one)) < 0) {
		perror("[init_smux] setsockopt failed");
		close(smux_sd);
		return SMUXNOTOK;
	}

	listen(smux_sd, SOMAXCONN);

	ioctl(smux_sd, FIOCLEX, NULL);

	if (smux_sd >= nfds)
		nfds = smux_sd + 1;
	FD_SET(smux_sd, &ifds);

	printf ("[smux_init] done; smux_sd is %d, smux_port is %d\n", smux_sd,
		 htons(smux_port));

	return SMUXOK;
}


void
smux_select(tvp)
	struct timeval *tvp;
{
	int fd;
	struct sockaddr_in in_socket;
	int count;
	int len;

	/* Copy the next to current */
	FD_COPY(&ifds, &rfds);

	/* 
	 * Select on the current.
	 * If there is a connection waiting on smux_fd, accept the connection
	 * and record the fd in next. This will be looked at in the next 
	 * round. For the the other current fds showing activity, run thru
	 * the packets and see what needs to be done with them.
	 */

	count = select(nfds, &rfds, 0, 0, tvp);
	DEBUGP ("count is %d\n", count);
	if (count > 0) {
		if (smux_sd > 0 && FD_ISSET(smux_sd, &rfds)) {
			/* connection request from gated */
                        DEBUGP ("Calling Accept\n");
			fd = accept(smux_sd, (struct sockaddr *)&in_socket,
				    &len);
			if (fd < 0) {
				perror("[smux_select] accept failed");
				/* XXX what other action should be taken here */
			}
			else {
				ioctl(fd, FIOCLEX, NULL);
				if (fd >= nfds)
					nfds = fd + 1;
	
				FD_SET(fd, &ifds);
				FD_SET(fd, &sfds);
	
				/* 
				 * XXX
				 * The FreeBSD (4.4BSD?) RCVTIMEO is reset
				 * everytime some data is received. It is 
				 * therefore * really an inacativity timer. 
				 * Implications?
				 */
				setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, 
					   (char *)&smux_rcv_timeout, 
					   sizeof(smux_rcv_timeout));
	
				gated_sd = fd;
				
				printf ("accepted fd %d, nfds, %d\n", fd, nfds);
			}
		}
		
		/* 
		 * The for loop would be useful if multiple smux conections 
		 * were * expected. For now, we handle gated only.
		 */
		/*
		for (i=0; i<nfds; i++) {
			if (FD_ISSET(i, &rfds) && FD_ISSET(i, &sfds)) {
				smux_process(i);
			}
		}
		*/
		if (FD_ISSET(gated_sd, &rfds) && FD_ISSET(gated_sd, &sfds)) {
			smux_process(gated_sd);
		}
	}
}


int
smux_process(fd)
	int fd;
{
	int len, length;
	u_char data[SMUXMAXPKTSIZE], *ptr;
	u_char type;
	int error;

	length = recv(fd, data, SMUXMAXPKTSIZE, 0);
	if (length < 0) {
		perror("[smux_process] recv failed");
		return SMUXNOTOK;
	}

	DEBUGP ("[smux_process] Processing %d bytes\n", length);

	error = SMUXOK;

	ptr = data;
	len = length;
	while (ptr != NULL && ptr < data + length) {
		len = length;
		ptr = asn_parse_header(ptr, &len, &type);
		DEBUGP ("[smux_process] type is %d\n", (int) type);
		switch (type) {
		case SMUX_OPEN:
			ptr = smux_open_process(ptr, &len);
			break;
		case SMUX_CLOSE:
			ptr = smux_close_process(fd, ptr, &len);
			break;
		case SMUX_RREQ:
			ptr = smux_rreq_process(fd, ptr, &len);
			break;
		case SMUX_RRSP:
			error = SMUXNOTOK;
			ptr = NULL;
			printf ("SMUX RRSP!\n");
			break;
		case SMUX_SOUT:
			ptr = smux_sout_process(ptr, &len);
			DEBUGP("This shouldn't have happened!\n");
			break;
		default:
                        DEBUGP("[smux_process] Wrong type %d\n", (int)type);
			error = SMUXNOTOK;
			break;
		}
	}

	return error;
}

/*
 * XXX Don't really care about which subtrees have been registered by gated.
 * The decision to register a gated-subtree is static (compile time) and the
 * decision to send a query to gated is made by just looking at the gated
 * descriptor.
 */
static u_char *
smux_open_process(ptr, len)
	u_char *ptr;
	int *len;
{
	u_char type;
	u_long version;
	oid oid_name[MAX_OID_LEN];
	int oid_name_len;
	u_char descr[SMUXMAXSTRLEN];
	int descr_len;
        int i;

	ptr = asn_parse_int(ptr, len, &type, &version, 
				      sizeof(version));
	DEBUGP("[smux_open_process] version %d, len %d, type %d\n", 
		version, *len, (int)type);

	oid_name_len = MAX_OID_LEN;
	ptr = asn_parse_objid(ptr, len, &type, oid_name, &oid_name_len); 
				 

        if (snmp_get_do_debugging()) {
          DEBUGP("[smux_open_process] smux peer:"); 
          for (i=0; i<oid_name_len; i++) 
            DEBUGP(".%d", oid_name[i]);
          DEBUGP (" \n");
          DEBUGP("[smux_open_process] len %d, type %d\n", *len, (int)type);
        }
    
	
	descr_len = SMUXMAXSTRLEN;
	ptr = asn_parse_string(ptr, len, &type, descr, &descr_len);

        if (snmp_get_do_debugging()) {
          DEBUGP("[smux_open_process] smux peer descr:"); 
          for (i=0; i<descr_len; i++) 
            DEBUGP("%c", descr[i]);
          DEBUGP (" \n");
          DEBUGP ("[smux_open_process] len %d, type %d\n", *len, (int)type);
        }
        
	descr_len = SMUXMAXSTRLEN;
	ptr = asn_parse_string(ptr, len, &type, descr, &descr_len);

        if (snmp_get_do_debugging()) {
          DEBUGP("[smux_open_process] smux peer passwd:"); 
          for (i=0; i<descr_len; i++) 
            DEBUGP("%c", descr[i]);
          DEBUGP (" \n");
          DEBUGP("[smux_open_process] len %d, type %d\n", *len, (int)type);
        }

	return ptr;
}


/* 
 * XXX - Bells and Whistles:
 * Need to catch signal when snmpd goes down and send close pdu to gated 
 */
static u_char *
smux_close_process(fd, ptr, len)
	int fd;
	u_char *ptr;
	int *len;
{
	long down = 0;
	int length = *len;

	/* This is the integer part of the close pdu */
	while (length--) {
		down = (down << 8) | (long)*ptr;
		ptr++;
	}

	printf("Gated gone - message %ld\n", down);

	FD_CLR(fd, &ifds);
	FD_CLR(fd, &sfds);
	close(fd);

	return NULL;
}

static u_char *
smux_rreq_process(sd, ptr, len)
	int sd;
	u_char *ptr;
	int *len;
{
	u_long priority;
	u_long operation;
	oid oid_name[MAX_OID_LEN];
	int oid_name_len;
	u_char type;
        char c_oid[MAX_NAME_LEN];

	oid_name_len = MAX_OID_LEN;
	ptr = asn_parse_objid(ptr, len, &type, oid_name, &oid_name_len); 

        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, oid_name, oid_name_len);
          DEBUGP("[smux_rreq_process] smux subtree: %s\n", c_oid); 
        }

	ptr = asn_parse_int(ptr, len, &type, &priority, 
				      sizeof(priority));
	DEBUGP("[smux_rreq_process] priority %d\n", priority);

	ptr = asn_parse_int(ptr, len, &type, &operation, 
				      sizeof(operation));
	DEBUGP("[smux_rreq_process] operation %d\n", operation);

	/* TODO: Register */

	/* send a response back */
	if (send (sd, rrsp_can, sizeof(rrsp_can), 0) < 0) {
		perror("[smux_rreq_process] send failed");
	}
	
	return ptr;
}

static u_char *
smux_sout_process(ptr, len)
	u_char *ptr;
	int *len;
{
        DEBUGP("[smux_sout_process] will be implemented later\n");
	return NULL;
}


u_char *
smux_snmp_process(exact, objid, len, return_len)
	int exact;
	oid *objid;
	int *len;
	int *return_len;
{
	u_char  packet[SMUXMAXPKTSIZE]; 
	u_char  result[SMUXMAXPKTSIZE];
	int length = SMUXMAXPKTSIZE;
	u_char type;
        char c_oid[MAX_NAME_LEN];
	
	/* 
	 * XXX Check if Gated is currently handling this oid.
	 * If so, form the SNMP PDU and Send it.
	 * Block for the reply.
	 * XXX Time out if required.
	 * On getting the reply, decode it and send the resulting objid and
	 * the return value back up.
	 */

	/* gated not running */
	if (gated_sd < 0) 
		return NULL;

	smux_reqid++;

	if (exact)
		type = SMUX_GET;
	else
		type = SMUX_GETNEXT;

	if (smux_build(type, smux_reqid, objid, len, packet, &length) 
	    != SMUXOK) {
		printf("[smux_snmp_process]: smux_build failed\n");
		return NULL;
	}
        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, objid, *len);
          DEBUGP("[smux_snmp_process] oid from build: %s\n",c_oid);
        }

	/* 
	 * XXX, send  and receive use gated_sd. This is ok for now.
	 * if ever there are two SMUX peers, th fd will have to be passed
	 * to smux_snmp_process.
	 */
	if (send(gated_sd, packet, length, 0) < 0) {
		perror("[smux_snmp_process] send failed");
	}

	DEBUGP("[smux_snmp_process] Sent %d request to Gated; %d bytes\n", 
		(int)type, length);
	/* 
	 * receive 
	 * XXX the RCVTIMEO could return a short result.
	 */
	length = recv(gated_sd, result, SMUXMAXPKTSIZE, 0);
	if (length < 0) {
		perror("[smux_snmp_process] recv failed");
		return NULL;
	}

	DEBUGP("[smux_snmp_process] Recived %d bytes from gated\n", length);

	/* Interpret Gateds reply */
	return (smux_parse(result, objid, len, return_len));
	


}


/* XXX need to do sanity checking */
static u_char *
smux_parse(rsp, objid, oidlen, return_len)
	u_char *rsp;
	oid *objid;
	int *oidlen;
	int *return_len;
{
	int length = SMUXMAXPKTSIZE; 
	u_char *ptr = rsp;
	u_char type;
	u_long reqid, errstat, errindex;

	/*
	 * Return pointer to the snmp/smux return value.
	 * return_len should contain the number of bytes in the value
	 * returned above.
	 * objid is the next object, with len for GETNEXT.
	 * objid and len are not changed for GET (assuming gated is working
	 * correctly).
	 */ 
	
	ptr = asn_parse_header(ptr, &length, &type);
	if (ptr == NULL || type != SNMP_MSG_RESPONSE)
		return NULL;

	ptr = asn_parse_int(ptr, &length, &type, &reqid, sizeof(reqid));
	ptr = asn_parse_int(ptr, &length, &type, &errstat, sizeof(errstat));
	ptr = asn_parse_int(ptr, &length, &type, &errindex, sizeof(errindex));


	/* XXX How to send something intelligent back in case of an error */
	DEBUGP("[smux_parse] Message type %d, reqid %d, errstat %d, \n\terrindex %d\n", (int)type, reqid, errstat, errindex);
	if (ptr == NULL || errstat != SNMP_ERR_NOERROR)
		return NULL;

	/* stuff to return */
	return (smux_parse_var(ptr, &length, objid, oidlen, return_len));

}


static u_char *
smux_parse_var(varbind, varbindlength, objid, oidlen, varlength)
	u_char *varbind;
	int *varbindlength;
	oid *objid;
	int *oidlen;
	int *varlength;
{
	oid var_name[MAX_OID_LEN];
	int var_name_len;
	u_char var_val_type;
	int var_val_len;
	u_char *var_val;
	int str_len, objid_len;
	int len;
	u_char *ptr;
	u_char type;
        char c_oid[MAX_NAME_LEN];
        
	ptr = varbind;
	len = *varbindlength;

        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, objid, *oidlen);
          DEBUGP("[smux_parse_var] before any processing: %s\n", c_oid);
        }

	ptr = asn_parse_header(ptr, &len, &type);
	if (ptr == NULL || type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)) {
		printf ("[smux_parse_var] Panic: type %d\n", (int)type);
		return NULL;
	}
		

	/* get hold of the objid and the asn1 coded value */
	var_name_len = MAX_OID_LEN;
	ptr = snmp_parse_var_op(ptr, var_name, &var_name_len, &var_val_type, 
				&var_val_len, &var_val, &len);

	smux_type = var_val_type;


	*oidlen = var_name_len;
	memcpy( objid,var_name, var_name_len * sizeof(oid));

        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, objid, *oidlen);
          DEBUGP("[smux_parse_var] returning oid : %s\n", c_oid);
        }
	/* XXX */
	len = SMUXMAXPKTSIZE;
        DEBUGP("[smux_parse_var] Asn coded len of var %d, type %d\n", 
		var_val_len, (int)var_val_type);

	switch((short)var_val_type){
	case ASN_INTEGER:
		*varlength = sizeof(long);
		asn_parse_int(var_val, &len, &var_val_type,
			      (long *)&smux_long, *varlength);
		return (u_char *)&smux_long;
		break;
	    case ASN_COUNTER:
	    case ASN_GAUGE:
	    case ASN_TIMETICKS:
	    case ASN_UINTEGER:
		*varlength = sizeof(u_long);
		asn_parse_unsigned_int(var_val, &len, &var_val_type,
			      (u_long *)&smux_ulong, *varlength);
		return (u_char *)&smux_ulong;
		break;
	    case ASN_COUNTER64:
		*varlength = sizeof(smux_counter64);
		asn_parse_unsigned_int64(var_val, &len, &var_val_type,
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
		asn_parse_string(var_val, &len, &var_val_type,
				 smux_str, &str_len);
		*varlength = str_len;
		return smux_str;
		break;
	    case ASN_OPAQUE:
	    case ASN_NSAP:
	    case ASN_OBJECT_ID:
		objid_len = MAX_OID_LEN;
		asn_parse_objid(var_val, &len, &var_val_type, 
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
		asn_parse_bitstring(var_val, &len, &var_val_type,
				 smux_str, &str_len);
		*varlength = str_len;
		return (u_char *)smux_str;
		break;
	    default:
		fprintf(stderr, "bad type returned (%x)\n", var_val_type);
		return NULL;
		break;
	}


}
	

/* XXX This is a bad hack - do not want to muck with ucd code */
static int
smux_build(type, reqid, objid, oidlen, packet, length)
	u_char type;
	u_long reqid;
	oid *objid;
	int *oidlen;
	u_char *packet;
	int *length;
{
	u_char *ptr, *save1, *save2, *save3;
	int len, len1, len2, len3;
	long errstat = 0;
	long errindex = 0;

	/* leave space for Seq and length */
	save1 = packet;
	len1 = *length;
	ptr = packet + 2;
	len = *length - 2;
	
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

	/* Leave space for Seq and length */
	save2 = ptr;
	len2 = len;
	ptr = ptr + 2;
	len = len - 2;

	/* build var list : snmp_build_var_op not liked by gated XXX */
	/*
	ptr = snmp_build_var_op(ptr, vars->name, &vars->name_length, 
			       vars->type, vars->val_len, 
			       (u_char *)vars->val.string, &len);
	*/
	save3 = ptr;
	len3 = len;
	ptr = ptr + 2;
	len = len - 2;

	/* build objid */
	ptr = asn_build_objid(ptr, &len, 
	      (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID),
              objid, *oidlen);

	/* build null */
	ptr = asn_build_null(ptr, &len, ASN_NULL);

	/* wrap with seq */
	if (ptr == NULL || ((ptr - save3) > 255)) {
		printf("[smux_build]: Panic save3\n");
		return SMUXNOTOK;
	}
	else {
		/* Fill in sequence and length */
		*save3 = (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR);
		*(save3 + 1) = (u_char)(ptr - save3 - 2);
	}

	if (ptr == NULL || ((ptr - save2) > 255)) {
		printf("[smux_build]: Panic save2\n");
		return SMUXNOTOK;
	}
	else {
		/* Fill in sequence and length */
		*save2 = (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR);
		*(save2 + 1) = (u_char)(ptr - save2 - 2);
	}

	/* build sequence and PDU type */
	if (ptr == NULL || ((ptr - save1) > 255)) {
		printf("[smux_build]: Panic save1\n");
		return SMUXNOTOK;
	}
	else {
		*save1 = type;
		*(save1 + 1) = (u_char)(ptr - save1 - 2);
	}

	*length = ptr - packet;
	return SMUXOK;


}

static void
print_fdbits (fdp)
        fd_set *fdp;
{
        int i;
        int num = howmany(FD_SETSIZE, NFDBITS);

        for (i=0; i<num; i++) {
                printf ("%ld ", fdp->fds_bits[i]);
        }
        printf ("\n");
}
