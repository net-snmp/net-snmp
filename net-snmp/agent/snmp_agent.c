/*
 * Simple Network Management Protocol (RFC 1067).
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

#if defined(unix)
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#ifndef NULL
#define NULL 0
#endif
#endif

#include "snmp.h"
#include "asn1.h"
#include "snmp_impl.h"
#include "acl.h"
#include "party.h"
#include "context.h"

#include "mib.h"

void	snmp_trap();
int	create_identical();
int	parse_var_op_list();
int	snmp_access();

struct pbuf *definitelyGetBuf();

#define NUM_COMMUNITIES	5
char	*communities[NUM_COMMUNITIES] = {
    "public", 
    "private",
    "regional",
    "proxy",
    "core"
};

int
snmp_agent_parse(data, length, out_data, out_length, sourceip)
    register u_char	*data;
    int			length;
    register u_char	*out_data;
    int			*out_length;
    u_long		sourceip;	/* possibly for authentication */
{
    struct packet_info packet, *pi = &packet;
    u_char	    type;
    long	    zero = 0;
    long	    reqid, errstat, errindex, dummyindex;
    register u_char *out_auth, *out_header, *out_reqid;
    u_char	    *startData = data;
    int		    startLength = length;
    int		    header_shift, auth_shift;
    int		    packet_len, len;
    struct partyEntry *tmp;
    oid		    tmpParty[64];
    int		    tmpPartyLen;
    
    len = length;
    (void)asn_parse_header(data, &len, &type);

    if (type == (ASN_SEQUENCE | ASN_CONSTRUCTOR)){
        /* authenticates message and returns length if valid */
	pi->community_len = COMMUNITY_MAX_LEN;
        data = snmp_auth_parse(data, &length,
			       pi->community, &pi->community_len,
                               &pi->version);
    } else if (type == (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)){
        pi->srcPartyLength = sizeof(pi->srcParty)/sizeof(oid);
        pi->dstPartyLength = sizeof(pi->dstParty)/sizeof(oid);
        pi->contextLength = sizeof(pi->context)/sizeof(oid);

        /* authenticates message and returns length if valid */
        data = snmp_secauth_parse(data, &length, pi,
				  pi->srcParty, &pi->srcPartyLength,
				  pi->dstParty, &pi->dstPartyLength,
				  pi->context, &pi->contextLength,
				  FIRST_PASS);
    } else {
        ERROR("unknown auth header type");
        return NULL;
    }

    if (data == NULL){
	ERROR("bad authentication");
	/* send auth fail trap */
	return 0;
    }
    if (pi->version == SNMP_VERSION_1){
	pi->community_id = get_community(pi->community, pi->community_len);
	if (pi->community_id == -1)
	    return NULL;
    } else if (pi->version == SNMP_VERSION_2){
	pi->community_id = 0;
    } else {
	ERROR("Bad Version");
	return NULL;
    }
    data = asn_parse_header(data, &length, &pi->pdutype);
    if (data == NULL){
	ERROR("bad header");
	return 0;
    }
    if (pi->pdutype != GET_REQ_MSG && pi->pdutype != GETNEXT_REQ_MSG
	&& pi->pdutype != SET_REQ_MSG && pi->pdutype != BULK_REQ_MSG){
	return 0;
    }

    if (pi->version == SNMP_VERSION_2){
        /*
         * Swap source and destination party pointers for building the reply
         * packet.
         */
        tmp = pi->srcp;
        pi->srcp = pi->dstp;
        pi->dstp = tmp;
    }

#if 0
    /* these should really be swapped too, but this makes for problems
    ** with the create_identical() routine, which expects them to not
    ** be swapped.
    */
    bcopy(pi->srcParty, tmpParty, pi->srcPartyLength);
    tmpPartyLen = pi->srcPartyLength;
    bcopy(pi->dstParty, pi->srcParty, pi->dstPartyLength);
    pi->srcPartyLength = pi->dstPartyLength;
    bcopy(tmpParty, pi->dstParty, tmpPartyLen);
    pi->dstPartyLength = tmpPartyLen;
#endif
    /*
     * Now create the auth_header for the output packet
     * The final lengths are not known now, so they will have to be recomputed
     * later.
     */
    out_auth = out_data;
    if (pi->version == SNMP_VERSION_1){
	out_header = snmp_auth_build(out_auth, out_length,
				     pi->community, &pi->community_len,
				     &pi->version, 0);
    } else if (pi->version == SNMP_VERSION_2){
	out_header = snmp_secauth_build(out_auth, out_length, pi, 0,
					pi->dstParty, pi->dstPartyLength,
					pi->srcParty, pi->srcPartyLength,
					pi->context, pi->contextLength,
					&packet_len, FIRST_PASS);
    }
    if (out_header == NULL){
	ERROR("snmp_auth_build failed");
	return 0;
    }

    if ((pi->version == SNMP_VERSION_2)
	&& !has_access(pi->pdutype, pi->dstp->partyIndex,
		       pi->srcp->partyIndex, pi->cxp->contextIndex)){
	/* Make sure not to send this response to GetResponse or
	 * Trap packets.  Currently, code above has this handled.
	 */
	errstat = SNMP_ERR_READONLY;
	if (pi->version == SNMP_VERSION_2){
	    errstat = SNMP_ERR_AUTHORIZATIONERROR;
	}
	errindex = 0;
	if (create_identical(startData, out_auth, startLength, errstat,
			     errindex, pi)){
	    *out_length = pi->packet_end - out_auth;
	    return 1;
	}
	return 0;
    }
    data = asn_parse_int(data, &length, &type, &reqid, sizeof(reqid));
    if (data == NULL){
	ERROR("bad parse of reqid");
	return 0;
    }
    data = asn_parse_int(data, &length, &type, &errstat, sizeof(errstat));
    if (data == NULL){
	ERROR("bad parse of errstat");
	return 0;
    }
    data = asn_parse_int(data, &length, &type, &errindex, sizeof(errindex));
    if (data == NULL){
	ERROR("bad parse of errindex");
	return 0;
    }

    /* create the requid, errstatus, errindex for the output packet */
    out_reqid = asn_build_sequence(out_header, out_length,
				 (u_char)GET_RSP_MSG, 0);
    if (out_reqid == NULL){
	ERROR("");
	return 0;
    }

    type = (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER);
    /* return identical request id */
    out_data = asn_build_int(out_reqid, out_length, type, &reqid,
			     sizeof(reqid));
    if (out_data == NULL){
	ERROR("build reqid failed");
	return 0;
    }

    /* assume that error status will be zero */
    out_data = asn_build_int(out_data, out_length, type, &zero, sizeof(zero));
    if (out_data == NULL){
	ERROR("build errstat failed");
	return 0;
    }

    /* assume that error index will be zero */
    out_data = asn_build_int(out_data, out_length, type, &zero, sizeof(zero));
    if (out_data == NULL){
	ERROR("build errindex failed");
	return 0;
    }

    if (pi->pdutype == BULK_REQ_MSG)
	errstat = bulk_var_op_list(data, length, out_data, *out_length,
				    errstat, errindex, &errindex, pi);
    else
	errstat = parse_var_op_list(data, length, out_data, *out_length,
			    &errindex, pi, RESERVE1);
    if (pi->pdutype == SET_REQ_MSG){
	if (errstat == SNMP_ERR_NOERROR)
	    errstat = parse_var_op_list(data, length, out_data, *out_length,
					&errindex, pi, RESERVE2);
        if (errstat == SNMP_ERR_NOERROR){
    	    /*
	     * SETS require 3-4 passes through the var_op_list.  The first two
	     * passes verify that all types, lengths, and values are valid
	     * and may reserve resources and the third does the set and a
	     * fourth executes any actions.  Then the identical GET RESPONSE
	     * packet is returned.
	     * If either of the first two passes returns an error, another
	     * pass is made so that any reserved resources can be freed.
	     */
	      parse_var_op_list(data, length, out_data, *out_length,
				&dummyindex, pi, COMMIT);
	      parse_var_op_list(data, length, out_data, *out_length,
				&dummyindex, pi, ACTION);
	      if (create_identical(startData, out_auth, startLength, 0L, 0L, pi)){
		  *out_length = pi->packet_end - out_auth;
		  return 1;
	      }
	      return 0;
	} else {
	      parse_var_op_list(data, length, out_data, *out_length,
				&dummyindex, pi, FREE);
	}
    }
    switch((short)errstat){
	case SNMP_ERR_NOERROR:
	    /* re-encode the headers with the real lengths */
	    *out_length = pi->packet_end - out_header;
	    out_data = asn_build_sequence(out_header, out_length, GET_RSP_MSG,
					pi->packet_end - out_reqid);
	    if (out_data != out_reqid){
		ERROR("internal error: header");
		return 0;
	    }

	    *out_length = pi->packet_end - out_auth;
	    if (pi->version == SNMP_VERSION_1){
		out_data = snmp_auth_build(out_auth, out_length,
					   pi->community, &pi->community_len,
					   &pi->version,
					   pi->packet_end - out_header);
		if (out_data != out_header){
		    ERROR("internal error");
		    return 0;
		}
	    } else if (pi->version == SNMP_VERSION_2){
		out_data = snmp_secauth_build(out_auth, out_length, pi,
					      pi->packet_end - out_header,
					      pi->dstParty, pi->dstPartyLength,
					      pi->srcParty, pi->srcPartyLength,
					      pi->context, pi->contextLength,
					      &packet_len, LAST_PASS);
	    }

	    /* packet_end is correct for old SNMP.  This dichotomy needs
	       to be fixed. */
	    if (pi->version == SNMP_VERSION_2)
		pi->packet_end = out_auth + packet_len;
	    break;
	case SNMP_ERR_TOOBIG:
	    if (pi->version == SNMP_VERSION_2){
		create_toobig(out_auth, *out_length, reqid, pi);
		break;
	    } /* else FALLTHRU */
	case SNMP_ERR_NOACCESS:
	case SNMP_ERR_WRONGTYPE:
	case SNMP_ERR_WRONGLENGTH:
	case SNMP_ERR_WRONGENCODING:
	case SNMP_ERR_WRONGVALUE:
	case SNMP_ERR_NOCREATION:
	case SNMP_ERR_INCONSISTENTVALUE:
	case SNMP_ERR_RESOURCEUNAVAILABLE:
	case SNMP_ERR_COMMITFAILED:
	case SNMP_ERR_UNDOFAILED:
	case SNMP_ERR_AUTHORIZATIONERROR:
	case SNMP_ERR_NOTWRITABLE:
	case SNMP_ERR_NOSUCHNAME:
	case SNMP_ERR_BADVALUE:
	case SNMP_ERR_READONLY:
	case SNMP_ERR_GENERR:
	    if (create_identical(startData, out_auth, startLength, errstat,
				 errindex, pi)){
		*out_length = pi->packet_end - out_auth;
		return 1;
	    }
	    return 0;
	default:
	    return 0;
    }
    *out_length = pi->packet_end - out_auth;
    return 1;
}

/*
 * Parse_var_op_list goes through the list of variables and retrieves each one,
 * placing it's value in the output packet.  In the case of a set request,
 * if action is RESERVE, the value is just checked for correct type and
 * value, and resources may need to be reserved.  If the action is COMMIT,
 * the variable is set.  If the action is FREE, an error was discovered
 * somewhere in the previous RESERVE pass, so any reserved resources
 * should be FREE'd.
 * If any error occurs, an error code is returned.
 */
int
parse_var_op_list(data, length, out_data, out_length, index, pi, action)
    register u_char	*data;
    int			length;
    register u_char	*out_data;
    int			out_length;
    register long	*index;
    struct packet_info	*pi;
    int			action;
{
    u_char  type;
    oid	    var_name[MAX_NAME_LEN];
    int	    var_name_len, var_val_len;
    u_char  var_val_type, *var_val, statType;
    register u_char *statP;
    int	    statLen;
    u_short acl;
    int	    rw, exact, err;
    int	    (*write_method)();
    u_char  *headerP, *var_list_start;
    int	    dummyLen;
    int	    header_shift;
    u_char  *getStatPtr();
    int	    noSuchObject;

    if (pi->pdutype == SET_REQ_MSG)
	rw = WRITE;
    else
	rw = READ;
    if (pi->pdutype == GETNEXT_REQ_MSG){
	exact = FALSE;
    } else {
	exact = TRUE;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL){
	ERROR("not enough space for varlist");
	return PARSE_ERROR;
    }
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)){
	ERROR("wrong type");
	return PARSE_ERROR;
    }
    headerP = out_data;
    out_data = asn_build_sequence(out_data, &out_length,
				(u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (out_data == NULL){
    	ERROR("not enough space in output packet");
	return BUILD_ERROR;
    }
    var_list_start = out_data;

    *index = 1;
    while((int)length > 0){
	/* parse the name, value pair */
	var_name_len = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, var_name, &var_name_len, &var_val_type,
				 &var_val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return PARSE_ERROR;
	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(var_name, &var_name_len, &statType, &statLen, &acl,
			   exact, &write_method, pi, &noSuchObject);
	if (pi->version != SNMP_VERSION_2 && statP == NULL
	    && (pi->pdutype != SET_REQ_MSG || !write_method)){
ERROR("");
	    return SNMP_ERR_NOSUCHNAME;
	}

	/* Effectively, check if this variable is read-only or read-write
	   (in the MIB sense). */
	if (pi->pdutype == SET_REQ_MSG && pi->version != SNMP_VERSION_2
	    && !snmp_access(acl, pi->community_id, rw)){
ERROR("");
	    return SNMP_ERR_NOSUCHNAME;
	}
	if (pi->pdutype == SET_REQ_MSG && pi->version == SNMP_VERSION_2
	    && !snmp_access(acl, pi->community_id, rw)){
printf("%X %d %d\n", acl, pi->community_id, rw);
ERROR("");
	    return SNMP_ERR_NOTWRITABLE;
	}
	/* Its bogus to check here on getnexts - the whole packet shouldn't
	   be dumped - this should should be the loop in getStatPtr
	   luckily no objects are set unreadable.  This can still be
	   useful for sets to determine which are intrinsically writable */

	if (pi->pdutype == SET_REQ_MSG){
	    if (write_method == NULL){
		if (statP != NULL){
		    /* see if the type and value is consistent with this
		       entity's variable */
		    if (!goodValue(var_val_type, var_val_len, statType,
				   statLen)){
			if (pi->version == SNMP_VERSION_2)
			    return SNMP_ERR_WRONGTYPE; /* poor approximation */
			else
			    return SNMP_ERR_BADVALUE;
		    }
		    /* actually do the set if necessary */
		    if (action == COMMIT)
			setVariable(var_val, var_val_type, var_val_len,
				    statP, statLen);
		} else {
		    if (pi->version == SNMP_VERSION_2)
			return SNMP_ERR_NOCREATION;
		    else
			return SNMP_ERR_NOSUCHNAME;
		}
	    } else {
		err = (*write_method)(action, var_val, var_val_type,
				     var_val_len, statP, var_name,
				     var_name_len);
		if (err != SNMP_ERR_NOERROR){
		    if (pi->version != SNMP_VERSION_2)
			return SNMP_ERR_BADVALUE;
		    else
			return err;
		}
	    }
	} else {
	    /* retrieve the value of the variable and place it into the
	     * outgoing packet */
	    if (statP == NULL){
		statLen = 0;
		if (exact){
		    if (noSuchObject == TRUE){
			statType = SNMP_NOSUCHOBJECT;
		    } else {
			statType = SNMP_NOSUCHINSTANCE;
		    }
		} else {
		    statType = SNMP_ENDOFMIBVIEW;
		}
	    }
            out_data = snmp_build_var_op(out_data, var_name, &var_name_len,
					 statType, statLen, statP,
					 &out_length);
	    if (out_data == NULL){
	        return SNMP_ERR_TOOBIG;
	    }
	}

	(*index)++;
    }
    if (pi->pdutype != SET_REQ_MSG){
	/* save a pointer to the end of the packet */
        pi->packet_end = out_data;

        /* Now rebuild header with the actual lengths */
        dummyLen = pi->packet_end - var_list_start;
        if (asn_build_sequence(headerP, &dummyLen,
			       (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
			       dummyLen) == NULL){
	    return SNMP_ERR_TOOBIG;	/* bogus error ???? */
        }
    }
    *index = 0;
    return SNMP_ERR_NOERROR;
}

struct repeater {
    oid	name[MAX_NAME_LEN];
    int length;
} repeaterList[10];

/*
 * Bulk_var_op_list goes through the list of variables and retrieves each one,
 * placing it's value in the output packet.  In the case of a set request,
 * if action is RESERVE, the value is just checked for correct type and
 * value, and resources may need to be reserved.  If the action is COMMIT,
 * the variable is set.  If the action is FREE, an error was discovered
 * somewhere in the previous RESERVE pass, so any reserved resources
 * should be FREE'd.
 * If any error occurs, an error code is returned.
 */
int
bulk_var_op_list(data, length, out_data, out_length, non_repeaters,
		 max_repetitions, index, pi)
    register u_char	*data;
    int			length;
    register u_char	*out_data;
    int			out_length;
    int			non_repeaters;
    int			max_repetitions;
    register long	*index;
    struct packet_info	*pi;
{
    u_char  type;
    oid	    var_name[MAX_NAME_LEN];
    int	    var_name_len, var_val_len;
    u_char  var_val_type, *var_val, statType;
    register u_char *statP;
    int	    statLen;
    u_short acl;
    int	    (*write_method)();
    u_char  *headerP, *var_list_start;
    int	    dummyLen;
    int	    header_shift;
    u_char  *getStatPtr();
    u_char  *repeaterStart, *out_data_save;
    int	    repeatCount, repeaterLength, indexStart, out_length_save;
    int	    full = FALSE;
    int	    noSuchObject, useful;
    int repeaterIndex, repeaterCount;
    struct repeater *rl;

    if (non_repeaters < 0)
	non_repeaters = 0;
    max_repetitions = *index;
    if (max_repetitions < 0)
	max_repetitions = 0;

    data = asn_parse_header(data, &length, &type);
    if (data == NULL){
	ERROR("not enough space for varlist");
	return PARSE_ERROR;
    }
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)){
	ERROR("wrong type");
	return PARSE_ERROR;
    }
    headerP = out_data;
    out_data = asn_build_sequence(out_data, &out_length,
				(u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (out_data == NULL){
    	ERROR("not enough space in output packet");
	return BUILD_ERROR;
    }
#if 0
    out_data += 4;
    out_length -= 4;
#endif
    var_list_start = out_data;

    out_length -= 32;	/* slop factor */
    *index = 1;
    while((int)length > 0 && non_repeaters > 0){
	/* parse the name, value pair */
	
	var_name_len = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, var_name, &var_name_len, &var_val_type,
				 &var_val_len, &var_val, (int *)&length);
	if (data == NULL)
	    return PARSE_ERROR;
	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(var_name, &var_name_len, &statType, &statLen, &acl,
			   FALSE, &write_method, pi, &noSuchObject);

	if (statP == NULL)
	    statType = SNMP_ENDOFMIBVIEW;

	/* save out_data so this varbind can be removed if it goes over
	   the limit for this packet */

	/* retrieve the value of the variable and place it into the
	 * outgoing packet */
	out_data = snmp_build_var_op(out_data, var_name, &var_name_len,
				     statType, statLen, statP,
				     &out_length);
	if (out_data == NULL){
	    return SNMP_ERR_TOOBIG;	/* ??? */
	}
	(*index)++;
	non_repeaters--;
    }

    repeaterStart = out_data;
    indexStart = *index;	/* index on input packet */

    repeaterCount = 0;
    rl = repeaterList;
    useful = FALSE;
    while((int)length > 0){
	/* parse the name, value pair */
	rl->length = MAX_NAME_LEN;
	data = snmp_parse_var_op(data, rl->name, &rl->length,
				 &var_val_type, &var_val_len, &var_val,
				 (int *)&length);
	if (data == NULL)
	    return PARSE_ERROR;
	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(rl->name, &rl->length, &statType, &statLen,
			   &acl, FALSE, &write_method, pi, &noSuchObject);
	if (statP == NULL)
	    statType = SNMP_ENDOFMIBVIEW;
	else
	    useful = TRUE;

	out_data_save = out_data;
	out_length_save = out_length;
	/* retrieve the value of the variable and place it into the
	 * outgoing packet */
	out_data = snmp_build_var_op(out_data, rl->name, &rl->length,
				     statType, statLen, statP,
				     &out_length);
	if (out_data == NULL){
	    out_data = out_data_save;
	    out_length = out_length_save;
	    full = TRUE;
	}
	(*index)++;
	repeaterCount++;
	rl++;
    }
    repeaterLength = out_data - repeaterStart;
    if (!useful)
	full = TRUE;

    for(repeatCount = 1; repeatCount < max_repetitions; repeatCount++){
	data = repeaterStart;
	length = repeaterLength;
	*index = indexStart;
	repeaterStart = out_data;
	useful = FALSE;
	repeaterIndex = 0;
	rl = repeaterList;
	while((repeaterIndex++ < repeaterCount) > 0 && !full){
	    /* parse the name, value pair */
#if 0
	    var_name_len = MAX_NAME_LEN;
	    data = snmp_parse_var_op(data, var_name, &var_name_len,
				     &var_val_type, &var_val_len, &var_val,
				     (int *)&length);
	    if (data == NULL)
		return PARSE_ERROR;
#endif
	    /* now attempt to retrieve the variable on the local entity */
	    statP = getStatPtr(rl->name, &rl->length, &statType, &statLen,
			       &acl, FALSE, &write_method, pi, &noSuchObject);
	    if (statP == NULL)
		statType = SNMP_ENDOFMIBVIEW;
	    else
		useful = TRUE;

	    out_data_save = out_data;
	    out_length_save = out_length;
	    /* retrieve the value of the variable and place it into the
	     * Outgoing packet */
	    out_data = snmp_build_var_op(out_data, rl->name, &rl->length,
					 statType, statLen, statP,
					 &out_length);
	    if (out_data == NULL){
		out_data = out_data_save;
		out_length = out_length_save;
		full = TRUE;
		repeatCount = max_repetitions;
	    }
	    (*index)++;
	    rl++;
	}
	repeaterLength = out_data - repeaterStart;
	if (!useful)
	    full = TRUE;
    }
    /* save a pointer to the end of the packet */
    pi->packet_end = out_data;
    
    /* Now rebuild header with the actual lengths */
    dummyLen = pi->packet_end - var_list_start;
    if (asn_build_sequence(headerP, &dummyLen, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), dummyLen) == NULL){
	return SNMP_ERR_TOOBIG;	/* bogus error ???? */
    }
    *index = 0;
    return SNMP_ERR_NOERROR;
}

/*
 * create a packet identical to the input packet, except for the error status
 * and the error index which are set according to the input variables.
 * Returns 1 upon success and 0 upon failure.
 */
int
create_identical(snmp_in, snmp_out, snmp_length, errstat, errindex, pi)
    u_char	    	*snmp_in;
    u_char	    	*snmp_out;
    int		    	snmp_length;
    long	    	errstat, errindex;
    struct packet_info 	*pi;
{
    register u_char *data;
    u_char	    type;
    long	    dummy;
    int		    length, messagelen, headerLength;
    register u_char *headerPtr, *reqidPtr, *errstatPtr,
    *errindexPtr, *varListPtr;
    int		    packet_len;
    struct partyEntry *tmp;

    length = snmp_length;
    (void)asn_parse_header(snmp_in, &length, &type);

    length = snmp_length;
    if (type == (ASN_SEQUENCE | ASN_CONSTRUCTOR)){
        /* authenticates message and returns length if valid */
	pi->community_len = COMMUNITY_MAX_LEN;
        headerPtr = snmp_auth_parse(snmp_in, &length,
				    pi->community, &pi->community_len,
				    (long *)&pi->version);
    } else if (type == (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)){
        pi->srcPartyLength = sizeof(pi->srcParty)/sizeof(oid);
        pi->dstPartyLength = sizeof(pi->dstParty)/sizeof(oid);

        /* authenticates message and returns length if valid */
        headerPtr = snmp_secauth_parse(snmp_in, &length, pi,
				       pi->srcParty, &pi->srcPartyLength,
				       pi->dstParty, &pi->dstPartyLength,
				       pi->context, &pi->contextLength, 0);
    } else {
        ERROR("unknown auth header type");
        return NULL;
    }
    if (pi->version == SNMP_VERSION_2){
        /*
         * Swap source and destination party pointers for building the reply
         * packet.
         */
        tmp = pi->srcp;
        pi->srcp = pi->dstp;
        pi->dstp = tmp;
    }

    if (headerPtr == NULL)
	return 0;
    messagelen = length;
    reqidPtr = asn_parse_header(headerPtr, &length, (u_char *)&dummy);
    if (reqidPtr == NULL)
	return 0;
    headerLength = length;
    errstatPtr = asn_parse_int(reqidPtr, &length, &type, (long *)&dummy,
			       sizeof dummy);	/* request id */
    if (errstatPtr == NULL)
	return 0;
    errindexPtr = asn_parse_int(errstatPtr, &length, &type, (long *)&dummy,
				sizeof dummy);	/* error status */
    if (errindexPtr == NULL)
	return 0;
    varListPtr = asn_parse_int(errindexPtr, &length, &type, (long *)&dummy,
			       sizeof dummy);	/* error index */
    if (varListPtr == NULL)
	return 0;

#if 0
    data = asn_build_header(headerPtr, &headerLength, GET_RSP_MSG,
			    headerLength);
    if (data != reqidPtr)
	return 0;
#else
    /* quick fix to solve the problem of different length encoding rules.
     * The entire creat_identical routine should probably be excised from
     * this code as a long-term solution (we should re-encode the error/set
     * reply packet).
     */
    *headerPtr = GET_RSP_MSG;
#endif
    
    length = snmp_length;
    type = (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER);
    data = asn_build_int(errstatPtr, &length, type, &errstat, sizeof errstat);
    if (data != errindexPtr)
	return 0;
    data = asn_build_int(errindexPtr, &length, type, &errindex,
			 sizeof errindex);
    if (data != varListPtr)
	return 0;
    
    dummy = snmp_length;
    if (pi->version == SNMP_VERSION_1){
	data = snmp_auth_build(snmp_out, (int *)&dummy,
			       pi->community, &pi->community_len,
			       (long *)&pi->version, messagelen);
    } else if (pi->version == SNMP_VERSION_2){
	data = snmp_secauth_build(snmp_out, (int *)&dummy, pi, messagelen,
				  pi->dstParty, pi->dstPartyLength,
				  pi->srcParty, pi->srcPartyLength,
				  pi->context, pi->contextLength,
				  &packet_len, 0);
    }
    if (data == NULL){
	ERROR("couldn't read_identical");
	return 0;
    }
    bcopy((char *)headerPtr, data, messagelen);
    if (pi->version == SNMP_VERSION_2){
	dummy = snmp_length;
	data = snmp_secauth_build(snmp_out, (int *)&dummy, pi, messagelen,
				  pi->dstParty, pi->dstPartyLength,
				  pi->srcParty, pi->srcPartyLength,
				  pi->context, pi->contextLength,
				  &packet_len, LAST_PASS);
	if (data == NULL){
	    ERROR("compute digest");
	    return 0;
	}
	pi->packet_end = snmp_out + packet_len;
    } else {
	pi->packet_end = data + messagelen;
    }
    return 1;
}

int
create_toobig(snmp_out, snmp_length, reqid, pi)
    u_char	    	*snmp_out;
    int		    	snmp_length;
    long	    	reqid;
    struct packet_info 	*pi;
{
    register u_char *data;
    u_char	    type;
    int		    errstat = SNMP_ERR_TOOBIG, errindex = 0;
    int		    length;
    register u_char *headerPtr, *reqidPtr;
    int		    packet_len;

    length = snmp_length;
    data = snmp_secauth_build(snmp_out, (int *)&length, pi, 16,
			      pi->dstParty, pi->dstPartyLength,
			      pi->srcParty, pi->srcPartyLength,
			      pi->context, pi->contextLength,
			      &packet_len, 0);
    if (data == NULL)
	return 0;
    headerPtr = data;
    data = asn_build_sequence(data, &length, GET_RSP_MSG, 16);
    if (data == NULL)
	return 0;
    reqidPtr = data;
    type = (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER);
    data = asn_build_int(data, &length, type, &reqid, sizeof reqid);
    if (data == NULL)
	return 0;
    data = asn_build_int(data, &length, type, &errstat, sizeof errstat);
    if (data == NULL)
	return 0;
    data = asn_build_int(data, &length, type, &errindex, sizeof errindex);
    if (data == NULL)
	return 0;
    
    data = asn_build_sequence(data, &length,
			    (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (data == NULL)
	return 0;

    pi->packet_end = data;
    data = asn_build_sequence(headerPtr, &length, GET_RSP_MSG,
			      data - reqidPtr);
    if (data != reqidPtr)
	return 0;

    data = snmp_secauth_build(snmp_out, (int *)&snmp_length, pi,
			      pi->packet_end - headerPtr,
			      pi->dstParty, pi->dstPartyLength,
			      pi->srcParty, pi->srcPartyLength,
			      pi->context, pi->contextLength,
			      &packet_len, LAST_PASS);
    if (data == NULL && data != headerPtr){
	ERROR("compute digest");
	return 0;
    }

    return 1;
}

int
snmp_access(acl, community, rw)
    u_short 	acl;
    int		community;
    int		rw;
{
    /*
     * Each group has 2 bits, the more significant one is for read access,
     * the less significant one is for write access.
     */

    community <<= 1;	/* multiply by two to shift two bits at a time */
    if (rw == READ){
	return (acl & (2 << community));    /* return the correct bit */
    } else {
	return (acl & (1 << community));
    }
}

int
get_community(community, community_len)
    u_char	*community;
    int		community_len;
{
    int	count;

    for(count = 0; count < NUM_COMMUNITIES; count++){
	if ((community_len == strlen(communities[count])
	     && !bcmp(communities[count], (char *)community, community_len)))
	    break;
    }
    if (count == NUM_COMMUNITIES)
	return -1;
    return count + 1;
}

int
goodValue(inType, inLen, actualType, actualLen)
    u_char	inType, actualType;
    int		inLen, actualLen;
{
    if (inLen > actualLen)
	return FALSE;
    return (inType == actualType);
}

setVariable(var_val, var_val_type, var_val_len, statP, statLen)
    u_char  *var_val;
    u_char  var_val_type;
    int	    var_val_len;
    u_char  *statP;
    int	    statLen;
{
    int	    buffersize = 1000;

    switch(var_val_type){
	case ASN_INTEGER:
	    asn_parse_int(var_val, &buffersize, &var_val_type, (long *)statP, statLen);
	    break;
	case COUNTER:
	case GAUGE:
	case TIMETICKS:
	    asn_parse_unsigned_int(var_val, &buffersize, &var_val_type, (u_long *)statP, statLen);
	    break;
	case COUNTER64:
	    asn_parse_unsigned_int64(var_val, &buffersize, &var_val_type,
				     (struct counter64 *)statP, statLen);
	    break;
	case ASN_OCTET_STR:
	case IPADDRESS:
	case OPAQUE:
	case NSAP:
	    asn_parse_string(var_val, &buffersize, &var_val_type, statP, &statLen);
	    break;
	case ASN_OBJECT_ID:
	    asn_parse_objid(var_val, &buffersize, &var_val_type, (oid *)statP, &statLen);
	    break;
	case ASN_BIT_STR:
	    asn_parse_bitstring(var_val, &buffersize, &var_val_type, statP, &statLen);
	    break;
    }
}


