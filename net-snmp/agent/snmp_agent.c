/*
 * snmp_agent.c
 *
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

#include <config.h>

#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
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
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

/* FIX...
#ifdef HAVE_KMT_H
#       include <kmt.h>
#endif
#ifdef HAVE_KMT_ALGS_H
#       include <kmt_algs.h>
#endif
*/


#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp.h"
#include "acl.h"
#include "party.h"
#include "context.h"
#include "mib.h"
#include "snmp_vars.h"
#include "snmp_client.h"
#include "snmpv3.h"
#include "lcd_time.h"
#include "snmpusm.h"
#include "snmpd.h"
#include "mibgroup/struct.h"
#include "mibgroup/util_funcs.h"
#include "snmp_agent.h"
#include "var_struct.h"
#include "read_config.h"
#include "mib_module_config.h"
#if USING_MIBII_VACM_VARS_MODULE
#include "mibgroup/mibII/vacm_vars.h"
#endif
#include "tools.h"
#include "debug.h"


/*
 * Globals.
 */
#define ERROR_STAT_LENGTH 10

struct repeater {
    oid	name[MAX_NAME_LEN];
    int length;
} repeaterList[10];


/*
 * Prototypes.
 */
static int create_identical __P((u_char *, u_char *, int, long, long, struct packet_info *, struct snmp_pdu *));
static int parse_var_op_list __P((u_char *, int, u_char *, int, long *, struct packet_info *, int));
static int snmp_vars_inc;
static int bulk_var_op_list __P((u_char *, int, u_char *, int, int, int, long *, struct packet_info *));
static int create_toobig __P((u_char *, int, long, struct packet_info *));
static int goodValue __P((u_char, int, u_char, int));
static void setVariable __P((u_char *, u_char, int, u_char *, int));
static void dump_var __P((oid *, int, int, void *, int));




static void
dump_var (var_name, var_name_len, statType, statP, statLen)
    oid		*var_name;
    int		 var_name_len;
    int		 statType;
    void	*statP;
    int		 statLen;
{
    char		 buf[SNMP_MAXBUF_MEDIUM];
    struct variable_list temp_var;

    temp_var.type	 = statType;
    temp_var.val.string	 = statP;
    temp_var.val_len	 = statLen;
    sprint_variable (buf, var_name, var_name_len, &temp_var);

    fprintf (stdout, "    >> %s\n", buf);
}



/*******************************************************************-o-******
 * snmp_agent_parse
 *
 * Parameters:
 *	*data
 *	 length
 *	*out_data
 *	*out_length
 *	 sourceip
 *      
 * Returns:
 *	1	On success, indicating that a return packet has been generated.
 *	0	Otherwise.
 */
int
snmp_agent_parse(data, length, out_data, out_length, sourceip)
    u_char		*data;
    int			 length;
    register u_char	*out_data;
    int			*out_length;
    u_long		 sourceip;	/* possibly for authentication */
{
    struct packet_info	 packet,
			*pi = &packet;
    u_char	   	 type;
    long	    	 zero =	0;
    long	   	 reqid, errstat, errindex, dummyindex;
    register u_char	*out_auth,
			*out_header  = NULL,
			*out_reqid;
    u_char	    	*startData   = data;
    int		    	 startLength = length;
    int		   	 packet_len, len;
    struct partyEntry	*tmp;
    struct snmp_pdu	*pdu = NULL;			/* XXX  okay? */
    u_char         	 v3data[SNMP_MAX_LEN];
    u_char         	*cp;
    long           	 version;
    u_char         	*engineID;
    int            	 engineIDLen;
    static oid      	 unknownSecurityLevel[] = {1,3,6,1,6,3,12,1,1,1};
    static oid      	 notInTimeWindow[]      = {1,3,6,1,6,3,12,1,1,2};
    static oid      	 unknownUserName[]      = {1,3,6,1,6,3,12,1,1,3};
    static oid      	 unknownEngineID[]      = {1,3,6,1,6,3,12,1,1,4};
    static oid      	 wrongDigest[]          = {1,3,6,1,6,3,12,1,1,5};
    static oid      	 decryptionError[]      = {1,3,6,1,6,3,12,1,1,6};
    struct variable_list *vp, *ovp;
    int			 ret_err = 0;
    
EM(-1);


    len = length;
    cp  = asn_parse_header(data, &len, &type);

    pi->source.sin_addr.s_addr = sourceip;


    /*
     * Parse the incoming message.
     */
    if (type == (ASN_SEQUENCE | ASN_CONSTRUCTOR))
    {
        asn_parse_int(cp, &len, &type, &version, sizeof(version));
        DEBUGP("parsing SNMPv%d message\n", (version?version:1));

        if (version == SNMP_VERSION_3)
	{
          pdu      = snmp_pdu_create(SNMP_MSG_RESPONSE);

          if (snmpv3_parse(pdu, data, &length, &data) == -1) {
            ret_err = snmp_get_errno();
            DEBUGP("Parse failed with: %d: %s\n",
				ret_err, snmp_api_errstring(ret_err));
          } 

          pi->version	   = pdu->version;
          pi->sec_level	   = pdu->securityLevel;
          pi->sec_model	   = pdu->securityModel;
          pi->securityName = pdu->securityName;
          pi->packet_end   = data + length;

          if (ret_err) {
	    engineID = snmpv3_generate_engineID(&engineIDLen);/* XXX If NULL? */
            switch(ret_err) {
              case SNMPERR_USM_UNSUPPORTEDSECURITYLEVEL:
                return snmpv3_make_report(out_data, out_length, pdu,
                                              STAT_USMSTATSUNSUPPORTEDSECLEVELS,
                                              unknownSecurityLevel,
                                              ERROR_STAT_LENGTH,
                                              engineID, engineIDLen);
              case SNMPERR_USM_UNKNOWNENGINEID:
                return snmpv3_make_report(out_data, out_length, pdu,
                                              STAT_USMSTATSUNKNOWNENGINEIDS,
                                              unknownEngineID,
                                              ERROR_STAT_LENGTH,
                                              engineID, engineIDLen);
              case SNMPERR_USM_NOTINTIMEWINDOW:
                return snmpv3_make_report(out_data, out_length, pdu,
                                              STAT_USMSTATSNOTINTIMEWINDOWS,
                                              notInTimeWindow,
                                              ERROR_STAT_LENGTH,
                                              engineID, engineIDLen);
              case SNMPERR_USM_UNKNOWNSECURITYNAME:
                return snmpv3_make_report(out_data, out_length, pdu,
                                              STAT_USMSTATSUNKNOWNUSERNAMES,
                                              unknownUserName,
                                              ERROR_STAT_LENGTH,
                                              engineID, engineIDLen);
              case SNMPERR_USM_AUTHENTICATIONFAILURE:
                return snmpv3_make_report(out_data, out_length, pdu,
                                              STAT_USMSTATSWRONGDIGESTS,
                                              wrongDigest,
                                              ERROR_STAT_LENGTH,
                                              engineID, engineIDLen);
              case SNMPERR_USM_DECRYPTIONERROR:
                return snmpv3_make_report(out_data, out_length, pdu,
                                              STAT_USMSTATSDECRYPTIONERRORS,
                                              decryptionError,
                                              ERROR_STAT_LENGTH,
                                              engineID, engineIDLen);
              default:
                ERROR_MSG("parse error");
                free(engineID);
                return 0;
            }
          }  /* endif -- ret_err */

        } else {
          /* authenticates message and returns length if valid
	   */
          pi->community_len = COMMUNITY_MAX_LEN;
          data = snmp_comstr_parse(data, &length,
                                        pi->community, &pi->community_len,
                                        &pi->version);
          switch (pi->version) {
            case SNMP_VERSION_1:
              pi->mp_model  = SNMP_MP_MODEL_SNMPv1;
              pi->sec_model = SNMP_SEC_MODEL_SNMPv1;
              break;
            case SNMP_VERSION_2c:
              pi->mp_model  = SNMP_MP_MODEL_SNMPv2c;
              pi->sec_model = SNMP_SEC_MODEL_SNMPv2c;
              break;
          }
          pi->sec_level = SNMP_SEC_LEVEL_NOAUTH;

        }  /* endif -- message parsing (per message version) */

#ifdef USE_V2PARTY_PROTOCOL
    } else if (type == (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)) {
        DEBUGP("Parsing SNMPv2p message...\n");

        pi->srcPartyLength = sizeof(pi->srcParty)/sizeof(oid);
        pi->dstPartyLength = sizeof(pi->dstParty)/sizeof(oid);
        pi->contextLength  = sizeof(pi->context)/sizeof(oid);

        /* authenticates message and returns length if valid
	 */
        data = snmp_party_parse(data, &length, pi,
				  pi->srcParty, &pi->srcPartyLength,
				  pi->dstParty, &pi->dstPartyLength,
				  pi->context, &pi->contextLength,
				  FIRST_PASS);
#endif /* USE_V2PARTY_PROTOCOL */

    } else {
        snmp_increment_statistic(STAT_SNMPINBADVERSIONS);
        ERROR_MSG("unknown auth header type");
        return 0;

    }  /* endif -- message type identification and parsing */


    if (data == NULL){
	ERROR_MSG("bad authentication");
  	snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
	return 0;
    }

    data = asn_parse_header(data, &length, &pi->pdutype);
    if (data == NULL){
	ERROR_MSG("bad header");
	return 0;
    }



    /*
     * Increment respective PDU count.
     */
    switch (pi->pdutype) {
    case SNMP_MSG_GET:
        snmp_increment_statistic(STAT_SNMPINGETREQUESTS);
	break;
    case SNMP_MSG_GETBULK:
        snmp_increment_statistic(STAT_SNMPINGETREQUESTS);
	break;
    case SNMP_MSG_GETNEXT:
        snmp_increment_statistic(STAT_SNMPINGETNEXTS);
	break;
    case SNMP_MSG_SET:
        snmp_increment_statistic(STAT_SNMPINSETREQUESTS);
	break;
    case SNMP_MSG_RESPONSE:
        snmp_increment_statistic(STAT_SNMPINGETRESPONSES);
	return 0;
    case SNMP_MSG_TRAP:
    case SNMP_MSG_TRAP2:
        snmp_increment_statistic(STAT_SNMPINTRAPS);
	return 0;
    default:
        snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
	return 0;
    }  /* endswitch -- pdutype */


    /* no outgoing variables seen: */
    snmp_vars_inc = 0;



    /*
     * For v2p only: swap source and destination identifiers.
     */
    if (pi->version == SNMP_VERSION_2p){
        /*
         * Swap source and destination party pointers for building the reply
         * packet.
         */
        tmp	 = pi->srcp;
        pi->srcp = pi->dstp;
        pi->dstp = tmp;
    }

#if 0	/* XXX */
    /* these should really be swapped too, but this makes for problems
    ** with the create_identical() routine, which expects them to not
    ** be swapped.
    */
    memcpy(tmpParty, pi->srcParty, pi->srcPartyLength);
    tmpPartyLen = pi->srcPartyLength;

    memcpy(pi->srcParty, pi->dstParty, pi->dstPartyLength);
    pi->srcPartyLength = pi->dstPartyLength;

    memcpy(pi->dstParty, tmpParty, tmpPartyLen);
    pi->dstPartyLength = tmpPartyLen;
#endif



    /*
     * Create the auth_header for the output packet.
     *
     * The final lengths are not known now, so they will have
     * to be recomputed later.
     */
    out_auth = out_data;
    if (pi->version == SNMP_VERSION_1 || pi->version == SNMP_VERSION_2c) {
	out_header = snmp_comstr_build(out_auth, out_length,
				     pi->community, &pi->community_len,
				     &pi->version, 0);

#ifdef USE_V2PARTY_PROTOCOL
    } else if (pi->version == SNMP_VERSION_2p) {
	out_header = snmp_party_build(out_auth, out_length, pi, 0,
					pi->dstParty, pi->dstPartyLength,
					pi->srcParty, pi->srcPartyLength,
					pi->context, pi->contextLength,
					&packet_len, FIRST_PASS);
#endif /* USE_V2PARTY_PROTOCOL */

    } else if (version == SNMP_VERSION_3) {
      out_header = v3data;

    }  /* endif -- create header (per message version) */


    if (out_header == NULL){
	ERROR_MSG("snmp_auth_build failed");
	return 0;
    }

#ifdef USE_V2PARTY_PROTOCOL
    if ((pi->version == SNMP_VERSION_2p)
		&& !has_access(pi->pdutype, pi->dstp->partyIndex,
		       pi->srcp->partyIndex, pi->cxp->contextIndex))
    {
	/* Make sure not to send this response to GetResponse or
	 * Trap packets.  Currently, code above has this handled.  XXX
	 */
	errstat = SNMP_ERR_READONLY;
	if (pi->version == SNMP_VERSION_2p){
	    errstat = SNMP_ERR_AUTHORIZATIONERROR;
	}
	errindex = 0;
	if (create_identical(startData, out_auth, startLength, errstat,
			     errindex, pi, pdu)){
	    *out_length = pi->packet_end - out_auth;
	    return 1;
	}
	return 0;
    }
#endif /* USE_V2PARTY_PROTOCOL */



    /*
     * Retreive the RequestID, errstat, and errindex from the PDU.
     */
    data = asn_parse_int(data, &length, &type, &reqid, sizeof(reqid));
    if (data == NULL){
	ERROR_MSG("bad parse of reqid");
  	snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
	return 0;
    }
    data = asn_parse_int(data, &length, &type, &errstat, sizeof(errstat));
    if (data == NULL){
	ERROR_MSG("bad parse of errstat");
  	snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
	return 0;
    }
    data = asn_parse_int(data, &length, &type, &errindex, sizeof(errindex));
    if (data == NULL){
	ERROR_MSG("bad parse of errindex");
  	snmp_increment_statistic(STAT_SNMPINASNPARSEERRS);
	return 0;
    }


    /*
     * Log a verbose message about the type of PDU.
     */
    if (verbose) {
	fprintf (stdout, "    ");
	switch (pi->pdutype) {
	case SNMP_MSG_GET:
	    fprintf (stdout, "GET");
	    break;
	case SNMP_MSG_GETNEXT:
	    fprintf (stdout, "GETNEXT");
	    break;
	case SNMP_MSG_GETBULK:
	    fprintf (stdout, "GETBULK non-rep = %ld, max-rep = %ld",
		     errstat, errindex);
	    break;
	case SNMP_MSG_SET:
	    fprintf (stdout, "SET");
	    break;
	}
	fprintf (stdout, "\n");
    }



    /* 
     * Begin building the PDU structure for the outgoing packet;
     * create the requid, errstatus, errindex for the output packet;
     * parse the var-bind list.
     */
    out_reqid = asn_build_sequence(out_header, out_length,
				 (u_char)SNMP_MSG_RESPONSE, 0);
    if (out_reqid == NULL){
	ERROR_MSG("");
	return 0;
    }

    /* return identical request id 
     */
    type = (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER);
    out_data = asn_build_int(out_reqid, out_length, type, &reqid,
			     sizeof(reqid));
    if (out_data == NULL){
	ERROR_MSG("build reqid failed");
	return 0;
    }

    /* assume that error status will be zero
     */
    out_data = asn_build_int(out_data, out_length, type, &zero, sizeof(zero));
    if (out_data == NULL){
	ERROR_MSG("build errstat failed");
	return 0;
    }

    /* assume that error index will be zero
     */
    out_data = asn_build_int(out_data, out_length, type, &zero, sizeof(zero));
    if (out_data == NULL){
	ERROR_MSG("build errindex failed");
	return 0;
    }

    if (pi->pdutype == SNMP_MSG_GETBULK) {
	errstat = bulk_var_op_list(data, length, out_data, *out_length,
				    errstat, errindex, &errindex, pi);
    } else {
	errstat = parse_var_op_list(data, length, out_data, *out_length,
			    &errindex, pi, RESERVE1);
    }



    /*
     * Manage a set request.
     */
    if (pi->pdutype == SNMP_MSG_SET){
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
              errstat = parse_var_op_list(
				data, length, out_data, *out_length,
				&dummyindex, pi, COMMIT);
	      parse_var_op_list(data, length, out_data, *out_length,
				&dummyindex, pi,
                                (errstat == SNMP_ERR_NOERROR) ? ACTION : FREE);

              if (errstat == SNMP_ERR_NOERROR) {
                if (create_identical(startData, out_auth, startLength, 0L, 0L,
                                     pi, pdu))
		{
		  *out_length = pi->packet_end - out_auth;
  		  snmp_increment_statistic(STAT_SNMPOUTGETRESPONSES);
		  snmp_increment_statistic_by(STAT_SNMPINTOTALSETVARS,
                                            snmp_vars_inc);
		  return 1;
                }
                return 0;
              }  /* endif -- SNMP_ERR_NOERROR */

	} else {
	      parse_var_op_list(data, length, out_data, *out_length,
				&dummyindex, pi, FREE);

	}  /* endif -- SNMP_ERR_NOERROR */
    }  /* endif -- message set */



    /*
     * Complete construction of the outgoing message;
     * properly create error responses.
     */
    DEBUGP("building SNMPv%d message\n", (pi->version?pi->version:1));

    switch( (short) errstat )
    {
	case SNMP_ERR_NOERROR:
	  /* 
	   * the pdu data has been stored into the v3data array,
	   * create the outgoing message
	   */
          if (pi->version == SNMP_VERSION_3)
	  {
            int pdu_buf_len = out_data - v3data;

            pdu_buf_len = *out_length = pi->packet_end - out_header;
	    out_data    = asn_build_sequence(out_header, out_length,
                                          SNMP_MSG_RESPONSE,
                                          pi->packet_end - out_reqid);
	    if (out_data != out_reqid){
              ERROR_MSG("internal error: header");
              return 0;
	    }

            *out_length = SNMP_MAX_MSG_SIZE;
            if (snmpv3_packet_build(pdu, out_auth, out_length, out_header,
                                    pdu_buf_len) != 0) {
              ERROR_MSG("internal error: v3 build");
              return 0;
	    }

            pi->packet_end = out_auth + *out_length;

	  /* 
	   * re-encode the headers with the real lengths
	   */
          } else {
	    *out_length = pi->packet_end - out_header;
	    out_data    = asn_build_sequence(
				out_header, out_length, SNMP_MSG_RESPONSE,
				pi->packet_end - out_reqid);
	    if (out_data != out_reqid){
		ERROR_MSG("internal error: header");
		return 0;
	    }

	    *out_length = pi->packet_end - out_auth;
	    if (pi->version == SNMP_VERSION_1 || pi->version == SNMP_VERSION_2c)
	    {
		out_data = snmp_comstr_build(out_auth, out_length,
					   pi->community, &pi->community_len,
					   &pi->version,
					   pi->packet_end - out_header);
		if (out_data != out_header){
		    ERROR_MSG("internal error");
		    return 0;
		}

#ifdef USE_V2PARTY_PROTOCOL
	    } else if (pi->version == SNMP_VERSION_2p) {
		out_data = snmp_party_build(out_auth, out_length, pi,
					      pi->packet_end - out_header,
					      pi->dstParty, pi->dstPartyLength,
					      pi->srcParty, pi->srcPartyLength,
					      pi->context, pi->contextLength,
					      &packet_len, LAST_PASS);
#endif /* USE_V2PARTY_PROTOCOL */
	    }  /* endif -- build community string (per message verion) */


	    /* packet_end is correct for old SNMP.  This dichotomy needs
	     * to be fixed.  XXX
	     */
	    if (pi->version == SNMP_VERSION_2p)
              pi->packet_end = out_auth + packet_len;

          }  /* endif -- case of SNMP_ERR_NOERROR: building messages */

          snmp_increment_statistic(STAT_SNMPOUTGETRESPONSES);
	  snmp_increment_statistic_by(STAT_SNMPINTOTALREQVARS, snmp_vars_inc);
	  break;

	case SNMP_ERR_TOOBIG:
          snmp_increment_statistic(STAT_SNMPINTOOBIGS);

#ifdef USE_V2PARTY_PROTOCOL
	  if (pi->version == SNMP_VERSION_2p){
	        create_toobig(out_auth, *out_length, reqid, pi);
		break;
	  }
#endif /* USE_V2PARTY_PROTOCOL */

	  goto reterr;

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
	  goto reterr;

	case SNMP_ERR_NOSUCHNAME:
          snmp_increment_statistic(STAT_SNMPOUTNOSUCHNAMES);
	  goto reterr;

	case SNMP_ERR_BADVALUE:
          snmp_increment_statistic(STAT_SNMPINBADVALUES);
	  goto reterr;

	case SNMP_ERR_READONLY:
          snmp_increment_statistic(STAT_SNMPINREADONLYS);
	  goto reterr;

	case SNMP_ERR_GENERR:
          snmp_increment_statistic(STAT_SNMPINGENERRS);

reterr:
          if (pi->version == SNMP_VERSION_1 && errstat > SNMP_ERR_GENERR)
              errstat = SNMP_ERR_GENERR; /* translate newer errors into
                                            a generic error */
	  if (create_identical(startData, out_auth, startLength, errstat,
				 errindex, pi, pdu)){
		*out_length = pi->packet_end - out_auth;
		return 1;
	  }
	  return 0;

	default:
	  return 0;

    }  /* endswitch -- errstat */


    if (version == SNMP_VERSION_3) {
      snmp_free_pdu(pdu);
    }

    *out_length = pi->packet_end - out_auth;


    return 1;

}  /* end snmp_agent_parse() */



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
static int
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
    int	    (*write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
    u_char  *headerP, *var_list_start;
    int	    dummyLen;
    int	    noSuchObject;

    if (pi->pdutype == SNMP_MSG_SET)
	rw = WRITE;
    else
	rw = READ;
    if (pi->pdutype == SNMP_MSG_GETNEXT){
	exact = FALSE;
    } else {
	exact = TRUE;
    }
    data = asn_parse_header(data, &length, &type);
    if (data == NULL){
	ERROR_MSG("not enough space for varlist");
	return PARSE_ERROR;
    }
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)){
	ERROR_MSG("wrong type");
	return PARSE_ERROR;
    }
    headerP = out_data;
    out_data = asn_build_sequence(out_data, &out_length,
				(u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (out_data == NULL){
    	ERROR_MSG("not enough space in output packet");
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

	if (verbose && action == RESERVE1) {
	    char buf [256];
	    sprint_objid (buf, var_name, var_name_len);
	    fprintf (stdout, "    -- %s\n", buf);
	}

	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(var_name, &var_name_len, &statType, &statLen, &acl,
			   exact, &write_method, pi, &noSuchObject);
	if (statP == NULL && pi->pdutype != SNMP_MSG_SET) {
	    if (verbose) fprintf (stdout, "    >> noSuchName\n");
	    else {
		char buf [256];
		sprint_objid(buf, var_name, var_name_len);
		DEBUGP("%s(%s) --  OID Doesn't exist or access is denied\n",
                       exact ? "GET" : "GETNEXT", buf);
	    }
	    return SNMP_ERR_NOSUCHNAME; 
	}

	/* Effectively, check if this variable is read-only or read-write
	   (in the MIB sense). */
	if ((pi->pdutype == SNMP_MSG_SET && !(acl & 2))) {
	    if (pi->version == SNMP_VERSION_1 || pi->pdutype != SNMP_MSG_SET) {
		if (verbose) fprintf (stdout, "    >> noSuchName (read-only)\n");
		ERROR_MSG("read-only");
		return SNMP_ERR_NOSUCHNAME;
	    }
	    else {
		if (verbose) fprintf (stdout, "    >> notWritable\n");
		ERROR_MSG("Not Writable");
		return SNMP_ERR_NOTWRITABLE;
	    }
	}

	/* Its bogus to check here on getnexts - the whole packet shouldn't
	   be dumped - this should should be the loop in getStatPtr
	   luckily no objects are set unreadable.  This can still be
	   useful for sets to determine which are intrinsically writable */

	if (pi->pdutype == SNMP_MSG_SET){
	    if (write_method == NULL){
		if (statP != NULL){
		    /* see if the type and value is consistent with this
		       entity's variable */
		    if (!goodValue(var_val_type, var_val_len, statType,
				   statLen)){
			if (pi->version != SNMP_VERSION_1)
			    return SNMP_ERR_BADVALUE;
			else
			    return SNMP_ERR_WRONGTYPE; /* poor approximation */
		    }
		    /* actually do the set if necessary */
		    if (action == COMMIT)
			setVariable(var_val, var_val_type, var_val_len,
				    statP, statLen);
		} else {
		    if (pi->version != SNMP_VERSION_1)
			return SNMP_ERR_NOCREATION;
		    else
			return SNMP_ERR_NOSUCHNAME;
		}
	    } else {
		err = (*write_method)(action, var_val, var_val_type,
				     var_val_len, statP, var_name,
				     var_name_len);
		if (err != SNMP_ERR_NOERROR){
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
	    if (verbose)
		dump_var(var_name, var_name_len, statType, statP, statLen);
            out_data = snmp_build_var_op(out_data, var_name, &var_name_len,
					 statType, statLen, statP,
					 &out_length);
	    if (out_data == NULL){
	        return SNMP_ERR_TOOBIG;
	    }
	}

	(*index)++;
	snmp_vars_inc++;
    }
    if (pi->pdutype != SNMP_MSG_SET){
	/* save a pointer to the end of the packet */
        pi->packet_end = out_data;

        /* Now rebuild header with the actual lengths */
        dummyLen = pi->packet_end - var_list_start;
        if (asn_build_sequence(headerP, &dummyLen,
			       (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
			       dummyLen) == NULL){
	    return SNMP_ERR_TOOBIG;	/* bogus error XXX */
        }
    }
    *index = 0;
    return SNMP_ERR_NOERROR;

}  /* end parse_var_op_list() */



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
static int
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
    int	    (*write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
    u_char  *headerP, *var_list_start;
    int	    dummyLen;
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
	ERROR_MSG("not enough space for varlist");
	return PARSE_ERROR;
    }
    if (type != (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR)){
	ERROR_MSG("wrong type");
	return PARSE_ERROR;
    }
    headerP = out_data;
    out_data = asn_build_sequence(out_data, &out_length,
				(u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (out_data == NULL){
    	ERROR_MSG("not enough space in output packet");
	return BUILD_ERROR;
    }
#if 0  /* XXX */
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

	if (verbose) {
	    char buf [256];
	    sprint_objid (buf, var_name, var_name_len);
	    fprintf (stdout, "    non-rep -- %s\n", buf);
	}

	/* now attempt to retrieve the variable on the local entity */
	statP = getStatPtr(var_name, &var_name_len, &statType, &statLen, &acl,
			   FALSE, &write_method, pi, &noSuchObject);

	if (statP == NULL)
	    statType = SNMP_ENDOFMIBVIEW;

	/* save out_data so this varbind can be removed if it goes over
	   the limit for this packet */

	/* retrieve the value of the variable and place it into the
	 * outgoing packet */
	if (verbose)
	    dump_var(var_name, var_name_len, statType, statP, statLen);
	out_data = snmp_build_var_op(out_data, var_name, &var_name_len,
				     statType, statLen, statP,
				     &out_length);
	if (out_data == NULL){
	    return SNMP_ERR_TOOBIG;	/* XXX */
	}
	(*index)++;
	non_repeaters--;
	snmp_vars_inc++;
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

	if (verbose) {
	    char buf [256];
	    sprint_objid (buf, rl->name, rl->length);
	    fprintf (stdout, "    rep -- %s\n", buf);
	}

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
	if (verbose)
	    dump_var(rl->name, rl->length, statType, statP, statLen);
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
	    if (verbose)
		dump_var(rl->name, rl->length, statType, statP, statLen);
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
	return SNMP_ERR_TOOBIG;	/* bogus error XXX */
    }
    *index = 0;


    return SNMP_ERR_NOERROR;

}  /* end bulk_var_op_list() */




/*
 * create a packet identical to the input packet, except for the error status
 * and the error index which are set according to the input variables.
 * Returns 1 upon success and 0 upon failure.
 */
static int
create_identical(snmp_in, snmp_out, snmp_length, errstat, errindex, pi, pdu)
    u_char	    	*snmp_in;
    u_char	    	*snmp_out;
    int		    	snmp_length;
    long	    	errstat, errindex;
    struct packet_info 	*pi;
    struct snmp_pdu     *pdu;
{
    register u_char *data;
    u_char	    type;
    long	    dummy;
    long            version;
    int		    length, messagelen, headerLength;
    register u_char *headerPtr, *reqidPtr, *errstatPtr,
    *errindexPtr, *varListPtr;
    int		    packet_len;
    struct partyEntry *tmp;
    int ret;
    
    length = snmp_length;
    
    /* for snmpv3, we already have an entire breakdown of the incoming
       message in the pdu so simple change the error codes and send it
       back */
    if (pi->version == SNMP_VERSION_3) {
      pdu->errstat = errstat;
      pdu->errindex = errindex;
      pdu->command = SNMP_MSG_RESPONSE;
      ret = snmpv3_packet_build(pdu, snmp_out, &length, NULL, 0);
      pi->packet_end = snmp_out + length;
      if (ret == 0)
        return 1;
      else
        return 0;
    }
      
    data = asn_parse_header(snmp_in, &length, &type);

    length = snmp_length;
    if (type == (ASN_SEQUENCE | ASN_CONSTRUCTOR)){
        asn_parse_int(data, &length, &type, &version, sizeof(version));
        /* authenticates message and returns length if valid */
        pi->community_len = COMMUNITY_MAX_LEN;
        headerPtr = snmp_comstr_parse(snmp_in, &length,
                                      pi->community, &pi->community_len,
                                      &pi->version);

#ifdef USE_V2PARTY_PROTOCOL
    } else if (type == (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)) {
        pi->srcPartyLength = sizeof(pi->srcParty)/sizeof(oid);
        pi->dstPartyLength = sizeof(pi->dstParty)/sizeof(oid);

        /* authenticates message and returns length if valid */
        headerPtr = snmp_party_parse(snmp_in, &length, pi,
				       pi->srcParty, &pi->srcPartyLength,
				       pi->dstParty, &pi->dstPartyLength,
				       pi->context, &pi->contextLength, 0);
#endif /* USE_V2PARTY_PROTOCOL */

    } else {
        ERROR_MSG("unknown auth header type");
        return 0;
    }
    if (pi->version == SNMP_VERSION_2p){
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
    data = asn_build_header(headerPtr, &headerLength, SNMP_MSG_RESPONSE,
			    headerLength);
    if (data != reqidPtr)
	return 0;
#else
    /* quick fix to solve the problem of different length encoding rules.
     * The entire creat_identical routine should probably be excised from
     * this code as a long-term solution (we should re-encode the error/set
     * reply packet).
     */
    *headerPtr = SNMP_MSG_RESPONSE;
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
    if (pi->version == SNMP_VERSION_1 || pi->version == SNMP_VERSION_2c)
    {
	data = snmp_comstr_build(snmp_out, (int *)&dummy,
			       pi->community, &pi->community_len,
			       &pi->version, messagelen);
    }

#ifdef USE_V2PARTY_PROTOCOL
      else if (pi->version == SNMP_VERSION_2p)
    {
	data = snmp_party_build(snmp_out, (int *)&dummy, pi, messagelen,
				  pi->dstParty, pi->dstPartyLength,
				  pi->srcParty, pi->srcPartyLength,
				  pi->context, pi->contextLength,
				  &packet_len, 0);
    }
#endif /* USE_V2PARTY_PROTOCOL */

    if (data == NULL){
	ERROR_MSG("couldn't read_identical");
	return 0;
    }
    memcpy(data, headerPtr, messagelen);

#ifdef USE_V2PARTY_PROTOCOL
    if (pi->version == SNMP_VERSION_2p){
	dummy = snmp_length;
	data = snmp_party_build(snmp_out, (int *)&dummy, pi, messagelen,
				  pi->dstParty, pi->dstPartyLength,
				  pi->srcParty, pi->srcPartyLength,
				  pi->context, pi->contextLength,
				  &packet_len, LAST_PASS);
	if (data == NULL){
	    ERROR_MSG("compute digest");
	    return 0;
	}
	pi->packet_end = snmp_out + packet_len;
    } else
#endif /* USE_V2PARTY_PROTOCOL */

    {
	pi->packet_end = data + messagelen;
    }


    return 1;

}  /* end create_identical() */



#ifdef USE_V2PARTY_PROTOCOL
/*
 * XXX	Is this really a v2p-only function?
 */
static int
create_toobig(snmp_out, snmp_length, reqid, pi)
    u_char	    	*snmp_out;
    int		    	snmp_length;
    long	    	reqid;
    struct packet_info 	*pi;
{
    register u_char *data;
    u_char	    type;
    long	    errstat = SNMP_ERR_TOOBIG;
    long	    errindex = 0;
    int		    length;
    register u_char *headerPtr, *reqidPtr;
    int		    packet_len;

    length = snmp_length;
    data = snmp_party_build(snmp_out, (int *)&length, pi, 16,
			      pi->dstParty, pi->dstPartyLength,
			      pi->srcParty, pi->srcPartyLength,
			      pi->context, pi->contextLength,
			      &packet_len, 0);
    if (data == NULL)
	return 0;
    headerPtr = data;
    data = asn_build_sequence(data, &length, SNMP_MSG_RESPONSE, 16);
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
    data = asn_build_sequence(headerPtr, &length, SNMP_MSG_RESPONSE,
			      data - reqidPtr);
    if (data != reqidPtr)
	return 0;

    data = snmp_party_build(snmp_out, (int *)&snmp_length, pi,
			      pi->packet_end - headerPtr,
			      pi->dstParty, pi->dstPartyLength,
			      pi->srcParty, pi->srcPartyLength,
			      pi->context, pi->contextLength,
			      &packet_len, LAST_PASS);
    if (data == NULL && data != headerPtr){
	ERROR_MSG("compute digest");
	return 0;
    }


    return 1;

}  /* end create_toobig() */

#endif /* USE_V2PARTY_PROTOCOL */



static int
goodValue(inType, inLen, actualType, actualLen)
    u_char	inType, actualType;
    int		inLen, actualLen;
{
    if (inLen > actualLen)
	return FALSE;
    return (inType == actualType);

}  /* end goodValue() */



static void
setVariable(var_val, var_val_type, var_val_len, statP, statLen)
    u_char  *var_val;
    u_char  var_val_type;
    int	    var_val_len;
    u_char  *statP;
    int	    statLen;
{
    int	    buffersize = SNMP_MAXBUF_MEDIUM;

    switch(var_val_type){
	case ASN_INTEGER:
	    asn_parse_int(var_val, &buffersize, &var_val_type, (long *)statP, statLen);
	    break;
	case ASN_COUNTER:
	case ASN_GAUGE:
	case ASN_TIMETICKS:
	    asn_parse_unsigned_int(var_val, &buffersize, &var_val_type, (u_long *)statP, statLen);
	    break;
	case ASN_COUNTER64:
	    asn_parse_unsigned_int64(var_val, &buffersize, &var_val_type,
				     (struct counter64 *)statP, statLen);
	    break;
	case ASN_OCTET_STR:
	case ASN_IPADDRESS:
	case ASN_OPAQUE:
	case ASN_NSAP:
	    asn_parse_string(var_val, &buffersize, &var_val_type, statP, &statLen);
	    break;
	case ASN_OBJECT_ID:
	    asn_parse_objid(var_val, &buffersize, &var_val_type, (oid *)statP, &statLen);
	    break;
	case ASN_BIT_STR:
	    asn_parse_bitstring(var_val, &buffersize, &var_val_type, statP, &statLen);
	    break;
    }
}  /* end setVariable() */

