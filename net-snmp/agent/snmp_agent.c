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

#include <config.h>

#include <sys/types.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
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

#include "asn1.h"
#define SNMP_NEED_REQUEST_LIST
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp.h"
#include "acl.h"
#include "party.h"
#include "context.h"
#include "mib.h"
#include "snmp_client.h"

#include "snmp_vars.h"
#if USING_MIBII_SNMP_MIB_MODULE
#include "mibgroup/mibII/snmp_mib.h"
#endif
#include "snmpd.h"
#include "mibgroup/struct.h"
#include "mibgroup/util_funcs.h"
#include "var_struct.h"
#include "read_config.h"
#include "mib_module_config.h"
#if USING_MIBII_VACM_VARS_MODULE
#include "mibgroup/mibII/vacm_vars.h"
#endif

#include "snmp_agent.h"

static int snmp_vars_inc;

static struct agent_snmp_session *agent_session_list = NULL;


static void dump_var(oid *, int, int, void *, int);
static int goodValue(u_char, int, u_char, int);
static void setVariable(u_char *, u_char, int, u_char *, int);

static void dump_var (var_name, var_name_len, statType, statP, statLen)
    oid *var_name;
    int var_name_len;
    int statType;
    void *statP;
    int statLen;
{
    char buf [2560];
    struct variable_list temp_var;

    temp_var.type = statType;
    temp_var.val.string = statP;
    temp_var.val_len = statLen;
    sprint_variable (buf, var_name, var_name_len, &temp_var);
    fprintf (stdout, "    >> %s\n", buf);
}


int
handle_snmp_packet(int operation, struct snmp_session *session, int reqid,
                   struct snmp_pdu *pdu, void *magic)
{
    struct agent_snmp_session  *asp;

    switch (pdu->command) {
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
    }
	
    asp = malloc( sizeof( struct agent_snmp_session ));
    asp->mode = RESERVE1;
    asp->start = pdu->variables;
    asp->end   = pdu->variables;
    asp->session = session;
    asp->pdu     = pdu;
    asp->outstanding_requests = NULL;
    asp->next = agent_session_list;
    agent_session_list = asp;
    
    if ( asp->end != NULL )
	while ( asp->end->next_variable != NULL )
	    asp->end = asp->end->next_variable;
	
    asp->next = agent_session_list;
    agent_session_list = asp;

    handle_next_pass( asp );
    return 1;
 }


void
handle_next_pass( asp )
    struct agent_snmp_session  *asp;
{
    int status, allDone, i;
    struct variable_list *var_ptr, *vp2;
    struct request_list *req_p, *next_req;
    struct agent_snmp_session  *asp2;

    /* XXX: Limit max repitions to something reasonable
                    (we should figure out what will fit somehow...)
            */
    if (asp->pdu->command == SNMP_MSG_GETBULK && asp->pdu->errindex > 10)
      asp->pdu->errindex = 10; 
          
    while ( 1 ) {
        if ( asp->outstanding_requests != NULL )
	    return;
	status = handle_var_list( asp );
        if ( asp->outstanding_requests != NULL ) {
	    if ( status == SNMP_ERR_NOERROR ) {
		/* Send out any AgentX (or similar) requests */
		return;
	    }
	    else {
	    	/* discard outstanding requests */
		for ( req_p = asp->outstanding_requests ;
			req_p != NULL ; req_p = next_req ) {
			
			next_req = req_p->next_request;
			free( req_p );
		}
	    }
	}
	
	if ( asp->pdu->command == SNMP_MSG_SET) {
    	    /*
	     * SETS require 3-4 passes through the var_op_list.  The first two
	     * passes verify that all types, lengths, and values are valid
	     * and may reserve resources and the third does the set and a
	     * fourth executes any actions.  Then the identical GET RESPONSE
	     * packet is returned.
	     * If either of the first two passes returns an error, another
	     * pass is made so that any reserved resources can be freed.
	     * If the third pass returns an error, another pass is made so that
	     * any changes can be reversed.
	     * If the fourth pass returns an error, we shuffle our feet and
	     * look extremely embarrassed!
	     */
	    switch ( asp->mode ) {
	        case RESERVE1:
			asp->pdu->errstat = status;
			asp->mode = (status==SNMP_ERR_NOERROR ? RESERVE2 : FREE);
			break;
	        case RESERVE2:
	    				/*
					 *  'COMMIT' and 'ACTION' have been
					 *  the wrong way round up to now.
					 *  Module code appears to use them correctly,
					 *  so they've now been switched 
					 */
			asp->pdu->errstat = status;
			asp->mode = (status==SNMP_ERR_NOERROR ? ACTION : FREE);
			break;
	        case ACTION:
			asp->mode = (status==SNMP_ERR_NOERROR ? COMMIT : UNDO);
			if ( status != SNMP_ERR_NOERROR )
				asp->pdu->errstat = SNMP_ERR_COMMITFAILED;
			break;
	        case COMMIT:
					/* This should not fail */
			asp->mode = FINISHED_SUCCESS;
			if ( status != SNMP_ERR_NOERROR )
				asp->pdu->errstat = SNMP_ERR_COMMITFAILED;
			break;
	        case UNDO:
			if ( status != SNMP_ERR_NOERROR ) {
				asp->pdu->errstat = SNMP_ERR_UNDOFAILED;
				asp->pdu->errindex = 0;
			}
			    /* Fallthrough */
	        case FREE:
			asp->mode = FINISHED_FAILURE;
			break;
	    }
	}
	else if ( asp->pdu->command == SNMP_MSG_GETBULK) {
	    /*
	     * GETBULKS require multiple passes. The first pass handles the
	     * explicitly requested varbinds, and subsequent passes append
	     * to the existing var_op_list.  Each pass (after the first)
	     * uses the results of the preceeding pass as the input list
	     * (delimited by the start & end pointers.
	     * Processing is terminated if all entries in a pass are
	     * EndOfMib, or the maximum number of repetitions are made.
	     */

	    if ( --asp->pdu->errindex == 0 ) {	/* Max repetitions */
	        asp->mode = FINISHED_SUCCESS;
		asp->pdu->errindex = 0;
		asp->pdu->errstat = SNMP_ERR_NOERROR;
	    }
	    else {
	    	if ( asp->mode == RESERVE1 ) {
			/* First pass - need to skip non-repeaters */
		    asp->start = asp->pdu->variables;
		    while ( asp->pdu->errstat-- > 0) {
		        asp->start = asp->start->next_variable;
		    }
		    asp->mode = ACTION;
		}
		
			/*
			 * Add new variable structures for the
			 * repeating elements, ready for the next pass.
			 * Also check that these are not all EndOfMib
			 *
			 * Hack alert:
			 *    The variable handling routines assume that
			 * the name variable passed in has room for the
			 * returned name, which may be longer than the
			 * requested name.
			 *    Temporary fix is to allocate the maximum
                         * allowable space possible (MAX_OID_LEN).
			 */
		 
		allDone = TRUE;
		var_ptr = asp->start;
		for ( var_ptr=asp->start; var_ptr != asp->end->next_variable;
		      var_ptr = var_ptr->next_variable) {
		      vp2 = snmp_add_null_var( asp->pdu,
		      	 		 var_ptr->name,
					 MAX_OID_LEN);
		      for ( i=var_ptr->name_length ; i< MAX_OID_LEN; i++)
		          vp2->name[var_ptr->name_length+i] = '\0';
		      vp2->name_length = var_ptr->name_length;
		      
		      if ( var_ptr->type != SNMP_ENDOFMIBVIEW ) {
		          allDone=FALSE;
		      }
		}
		if ( allDone ) {
		    asp->mode = FINISHED_SUCCESS;
		    asp->pdu->errindex = 0;
		    asp->pdu->errstat = SNMP_ERR_NOERROR;
		}
		    
		    	/*
			 * Update the start/end pointers to use the
			 * new portion of the list.
			 */
		asp->start = asp->end->next_variable;
                while ( asp->end->next_variable !=NULL )
                    asp->end = asp->end->next_variable;
	    }
	}
	    /*
	     * All other PDU types are single pass
	     */
	else {
	    asp->pdu->errstat = status;
	    asp->mode = (status==SNMP_ERR_NOERROR ?
			    FINISHED_SUCCESS : FINISHED_FAILURE );
	}
	
	if (( asp->mode == FINISHED_FAILURE ) ||
	    ( asp->mode == FINISHED_SUCCESS
			 && asp->outstanding_requests == NULL)) {

	    /*  All Done - send back the reply & tidy up */
	    asp->pdu->command = SNMP_MSG_RESPONSE;
	    snmp_send( asp->session, asp->pdu );
            snmp_increment_statistic(STAT_SNMPOUTPKTS);
	    
	    if ( agent_session_list == asp ) {
	        agent_session_list = asp->next;
	    }
	    else {
	         asp2 = agent_session_list;
		 while ( asp2->next != NULL && asp2->next != asp )
		     asp2 = asp2->next;
		 asp2->next = asp->next;
	    }
	    free( asp );
	    return;
	}
    }
}


int
handle_var_list( asp )
    struct agent_snmp_session  *asp;
{
    struct variable_list *varbind_ptr;
    u_char  var_val_type, *var_val, statType;
    register u_char *statP;
    int	    statLen;
    u_short acl;
    int	    (*write_method) (int, u_char *, u_char, int, u_char *, oid *, int);
    int	    noSuchObject;
    int count, rw, exact;
    
    if (asp->pdu->command == SNMP_MSG_SET)
	rw = WRITE;
    else
	rw = READ;
    if (asp->pdu->command == SNMP_MSG_GETNEXT ||
        asp->pdu->command == SNMP_MSG_GETBULK){
	exact = FALSE;
    } else {
	exact = TRUE;
    }
        
    count = 0;
    varbind_ptr = asp->start;
    while (1) {
    
statp_loop:
	statP = getStatPtr(  varbind_ptr->name,
			   &(varbind_ptr->name_length),
			   &statType, &statLen, &acl,
			   exact, &write_method, asp->pdu, &noSuchObject);
			   
	if (statP == NULL && rw != WRITE) {
	    if ( rw != WRITE ) {
	    	    varbind_ptr->val   = NULL;
	    	    varbind_ptr->val_len = 0;
		    if ( exact ) {
	        	if ( noSuchObject == TRUE ){
			    statType = SNMP_NOSUCHOBJECT;
			} else {
			    statType = SNMP_NOSUCHINSTANCE;
			}
		    } else {
	        	statType = SNMP_ENDOFMIBVIEW;
		    }
		    varbind_ptr->type = statType;
	    }
	}
		/* GETNEXT/GETBULK should just skip inaccessible entries */
	else if ( !in_a_view(varbind_ptr->name, &varbind_ptr->name_length,
                             asp->pdu, varbind_ptr->type)
			 && !exact) {
		goto statp_loop;
	}
		/* Other access problems are permanent */
	else if (( rw == WRITE && !(acl & 2))
	      || !in_a_view(varbind_ptr->name, &varbind_ptr->name_length,
                            asp->pdu, varbind_ptr->type)) {
	    if (asp->pdu->version == SNMP_VERSION_1 || rw != WRITE) {
		if (verbose) fprintf (stdout, "    >> noSuchName (read-only)\n");
		ERROR_MSG("read-only");
		statType = SNMP_ERR_NOSUCHNAME;
	    }
	    else {
		if (verbose) fprintf (stdout, "    >> notWritable\n");
		ERROR_MSG("Not Writable");
		statType = SNMP_ERR_NOTWRITABLE;
	    }
	    asp->pdu->errstat = statType;
	    asp->pdu->errindex = count;
	    return statType;
        }
	else {
            /* dump verbose info */
	    if (verbose && statP)
	        dump_var(varbind_ptr->name, varbind_ptr->name_length,
				statType, statP, statLen);

		/*  FINALLY we can act on SET requests ....*/
	    if ( rw == WRITE ) {
	        if ( write_method != NULL ) {
		    statType = (*write_method)(asp->mode,
                                               varbind_ptr->val.string,
                                               varbind_ptr->type,
                                               varbind_ptr->val_len, statP,
                                               varbind_ptr->name,
                                               varbind_ptr->name_length);
                    if (statType != SNMP_ERR_NOERROR) {
                      asp->pdu->errstat = statType;
                      asp->pdu->errindex = count;
                      return statType;
                    }
		}
		else {
                    if (!goodValue(varbind_ptr->type, varbind_ptr->val_len,
                                    statType, statLen)){
                        if (asp->pdu->version == SNMP_VERSION_1)
                            statType = SNMP_ERR_BADVALUE;
                        else
                            statType = SNMP_ERR_WRONGTYPE; /* poor approximation */
			asp->pdu->errstat = statType;
			asp->pdu->errindex = count;
			return statType;
                    }
                    /* actually do the set if necessary */
                    if (asp->mode == COMMIT)
                        setVariable(varbind_ptr->val.string, varbind_ptr->type,
                                    varbind_ptr->val_len, statP, statLen);
                }
	    }
		/* ... or save the results from assorted GETs */
	    else {
		     varbind_ptr->type = statType;
		     varbind_ptr->val_len  = statLen;
		     /* free( varbind_ptr->val.string ); */
		     varbind_ptr->val.string    = malloc( statLen );
		     memcpy((char*)varbind_ptr->val.string, (char*)statP, statLen);
	    }
	}
	
	if ( varbind_ptr == asp->end )
	     return SNMP_ERR_NOERROR;
	varbind_ptr = varbind_ptr->next_variable;
	count++;
	if ( asp->mode == RESERVE1 )
	    snmp_vars_inc++;
    }
}



static int
goodValue(inType, inLen, actualType, actualLen)
    u_char	inType, actualType;
    int		inLen, actualLen;
{
    if (inLen > actualLen)
	return FALSE;
    return (inType == actualType);
}

static void
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
}
