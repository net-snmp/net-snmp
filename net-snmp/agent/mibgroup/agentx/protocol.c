#include <config.h>

#include <stdio.h>
#include <errno.h>
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
#include <sys/types.h>
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
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "snmp.h"
#include "snmp_client.h"
#include "snmp_debug.h"
#include "mib.h"

#include "agentx/protocol.h"

const char *
agentx_cmd( u_char code )
{
   switch (code) {
	case AGENTX_MSG_OPEN:		return "Open";
	case AGENTX_MSG_CLOSE:		return "Close";
	case AGENTX_MSG_REGISTER:	return "Register";
	case AGENTX_MSG_UNREGISTER:	return "Unregister";
	case AGENTX_MSG_GET:		return "Get";
	case AGENTX_MSG_GETNEXT:	return "Get Next";
	case AGENTX_MSG_GETBULK:	return "Get Bulk";
	case AGENTX_MSG_TESTSET:	return "Test Set";
	case AGENTX_MSG_COMMITSET:	return "Commit Set";
	case AGENTX_MSG_UNDOSET:	return "Undo Set";
	case AGENTX_MSG_CLEANUPSET:	return "Cleanup Set";
	case AGENTX_MSG_NOTIFY:		return "Notify";
	case AGENTX_MSG_PING:		return "Ping";
	case AGENTX_MSG_INDEX_ALLOCATE:		return "Index Allocate";
	case AGENTX_MSG_INDEX_DEALLOCATE:	return "Index Deallocate";
	case AGENTX_MSG_ADD_AGENT_CAPS:		return "Add Agent Caps";
	case AGENTX_MSG_REMOVE_AGENT_CAPS:	return "Remove Agent Caps";
	case AGENTX_MSG_RESPONSE:		return "Response";
	default:			return "Unknown";
   }
}

void
agentx_build_int(u_char *bufp, u_int value, int network_byte_order)
{
    u_char *orig_bufp = bufp;
    u_int   orig_val  = value;

    if ( network_byte_order ) {
#ifndef WORDS_BIGENDIAN
	value = ntohl( value );
#endif
	memmove( bufp, &value, 4);
    }
    else {
#ifndef WORDS_BIGENDIAN
	memmove( bufp, &value, 4);
#else
	*bufp = (u_char)value & 0xff;	value >>=8;	bufp++;
	*bufp = (u_char)value & 0xff;	value >>=8;	bufp++;
	*bufp = (u_char)value & 0xff;	value >>=8;	bufp++;
	*bufp = (u_char)value & 0xff;
#endif
    }
    DEBUGDUMPSETUP("send", orig_bufp, 4);
    DEBUGMSG(("dumpv_send", "  Integer:\t%ld (0x%.2X)\n", orig_val, orig_val));
}

void
agentx_build_short(u_char *bufp, int in_value, int network_byte_order)
{
    u_char *orig_bufp = bufp;
    u_short value = (u_short)in_value;
    if ( network_byte_order ) {
#ifndef WORDS_BIGENDIAN
	value = ntohs( value );
#endif
	memmove( bufp, &value, 2);
    }
    else {
#ifndef WORDS_BIGENDIAN
	memmove( bufp, &value, 2);
#else
	*bufp = (u_char)value & 0xff;	value >>=8;	bufp++;
	*bufp = (u_char)value & 0xff;
#endif
    }
    DEBUGDUMPSETUP("send", orig_bufp, 2);
    DEBUGMSG(("dumpv_send", "  Short:\t%ld (0x%.2X)\n", in_value, in_value));
}


u_char*
agentx_build_oid(u_char *bufp, size_t *out_length, int inc,
	oid *name, size_t name_len, int network_byte_order)
{
    u_char *orig_bufp = bufp;
    int prefix = 0;
    size_t i;

    DEBUGPRINTINDENT("dumpv_send");
    DEBUGMSG(("dumpv_send", "OID: "));
    DEBUGMSGOID(("dumpv_send", name, name_len));
    DEBUGMSG(("dumpv_send", "\n"));

    if ( name_len == 2 && name[0]  == 0 && name[1]  == 0  ) {
	 name_len = 0;	/* Null OID */
    }
    
    	/* 'Compact' internet OIDs */
    if ( name_len >= 5 &&
	 name[0] == 1 && name[1] == 3 &&
         name[2] == 6 && name[3] == 1 ) {
	 
	 prefix = name[4];
	 name += 5;
	 name_len -= 5;
    }
    
    if ( *out_length < 4 + 4*name_len )
        return NULL;

    *bufp = (u_char)name_len;	bufp++;
    *bufp = (u_char)prefix;	bufp++;
    *bufp = (u_char)inc;	bufp++;
    *bufp = 0;			bufp++;
    *out_length -= 4;
    
    DEBUGDUMPHEADER("send", "OID Header");
    DEBUGDUMPSETUP("send", orig_bufp, 4);
    DEBUGMSG(("dumpv_send", "  # subids:\t%d (0x%.2X)\n",
					orig_bufp[0], orig_bufp[0]));
    DEBUGPRINTINDENT("dumpv_send");
    DEBUGMSG(("dumpv_send", "  prefix:\t%d (0x%.2X)\n",
					orig_bufp[1], orig_bufp[1]));
    DEBUGPRINTINDENT("dumpv_send");
    DEBUGMSG(("dumpv_send", "  inclusive:\t%d (0x%.2X)\n",
					orig_bufp[2], orig_bufp[2]));
    DEBUGINDENTLESS();
    DEBUGDUMPHEADER("send", "OID Segments");

    for ( i = 0 ; i < name_len ; i++ ) {
        agentx_build_int( bufp, name[i], network_byte_order );
	bufp        += 4;
	*out_length -= 4;
    }
    DEBUGINDENTLESS();

    return bufp;
}

u_char*
agentx_build_string(u_char *bufp, size_t *out_length,
	u_char *name, size_t name_len, int network_byte_order)
{
    u_char *orig_bufp = bufp;

    if ( *out_length < 4 + name_len ) {
        return NULL;
    }
    DEBUGDUMPHEADER("send", "Build String");
    DEBUGDUMPHEADER("send", "length");
    agentx_build_int( bufp, (u_int)name_len, network_byte_order );
    bufp        += 4;
    *out_length -= 4;
    if ( name_len == 0 ) {
	DEBUGMSG(("dumpv_send", "  String: <empty>\n"));
	DEBUGINDENTLESS();
	DEBUGINDENTLESS();
	return bufp;
    }
    orig_bufp += 4;
    
    memmove( bufp, name, name_len );
    bufp        +=  name_len;
    *out_length -= name_len;    
    
    	/* Pad to a multiple of 4 bytes */
    name_len &= 0x3;
    if ( name_len )
	name_len = 4-name_len; 
    for ( ; name_len ; name_len-- ) {
	*bufp = 0;
	bufp++;
	(*out_length)--;
    }
    DEBUGDUMPSETUP("send", orig_bufp, bufp - orig_bufp);
    DEBUGMSG(("dumpv_send", "  String:\t%s\n", name));
    DEBUGINDENTLESS();
    DEBUGINDENTLESS();
    return bufp;
}

#ifdef OPAQUE_SPECIAL_TYPES
u_char*
agentx_build_double(u_char *bufp, size_t *out_length,
	double double_val, int network_byte_order)
{
    union {
	double	doubleVal;
	int	intVal[2];
	char	c[sizeof(double)];
    } du;
    int tmp;
    u_char buf[BUFSIZ];

    if ( *out_length < 4 + 3 + sizeof(double) ) {
        return NULL;
    }

    buf[0] = ASN_OPAQUE_TAG1;
    buf[1] = ASN_OPAQUE_DOUBLE;
    buf[2] = sizeof(double);

    du.doubleVal = double_val;
    tmp          = htonl(du.intVal[0]);
    du.intVal[0] = htonl(du.intVal[1]);
    du.intVal[1] = tmp;
    memcpy( &buf[3], &du.c[0], sizeof(double) );

    return agentx_build_string( bufp, out_length,
	    		buf, 3 + sizeof(double), network_byte_order);
}

u_char*
agentx_build_float(u_char *bufp, size_t *out_length,
	float float_val, int network_byte_order)
{
    union {
	float	floatVal;
	int	intVal;
	char	c[sizeof(float)];
    } fu;
    u_char buf[BUFSIZ];

    if ( *out_length < 4 + 3 + sizeof(float) ) {
        return NULL;
    }

    buf[0] = ASN_OPAQUE_TAG1;
    buf[1] = ASN_OPAQUE_FLOAT;
    buf[2] = sizeof(float);

    fu.floatVal = float_val;
    fu.intVal   = htonl(fu.intVal);
    memcpy( &buf[3], &fu.c[0], sizeof(float) );

    return agentx_build_string( bufp, out_length,
	    		buf, 3 + sizeof(float), network_byte_order);
}
#endif

u_char*
agentx_build_varbind(u_char *bufp, size_t *out_length,
	struct variable_list *vp, int network_byte_order)
{
    if ( *out_length < 4 )
    	return NULL;
	

    DEBUGDUMPHEADER("send", "VarBind");
    DEBUGDUMPHEADER("send", "type");
#ifdef OPAQUE_SPECIAL_TYPES
    if (( vp->type == ASN_OPAQUE_FLOAT )  ||
        ( vp->type == ASN_OPAQUE_DOUBLE ) ||
        ( vp->type == ASN_OPAQUE_I64 )    ||
        ( vp->type == ASN_OPAQUE_U64 )    ||
        ( vp->type == ASN_OPAQUE_COUNTER64 ))
	agentx_build_short( bufp, ASN_OPAQUE, network_byte_order);
    else
#endif
    agentx_build_short( bufp, (u_int)vp->type, network_byte_order);
    bufp        +=2;
    *bufp = 0;			bufp++;
    *bufp = 0;			bufp++;		/* <reserved> */
    *out_length -=4;
    DEBUGINDENTLESS();

    DEBUGDUMPHEADER("send", "name");
    bufp = agentx_build_oid( bufp, out_length, 0,
	    		vp->name, vp->name_length, network_byte_order);
    if ( bufp == NULL )
    	return NULL;
    DEBUGINDENTLESS();

    DEBUGDUMPHEADER("send", "value");
    switch ( (short)vp->type ) {
    
  	case ASN_INTEGER:
	case ASN_COUNTER:
	case ASN_GAUGE:
	case ASN_TIMETICKS:
		if ( *out_length < 4 )
		    return NULL;
		agentx_build_int( bufp, *(vp->val.integer), network_byte_order);
		bufp        += 4;
		*out_length -= 4;
		break;

#ifdef OPAQUE_SPECIAL_TYPES
	case ASN_OPAQUE_FLOAT:
		DEBUGDUMPHEADER("send", "Build Opaque Float");
		DEBUGPRINTINDENT("dumpv_send");
		DEBUGMSG(("dumpv_send", "  Float:\t%f\n", *(vp->val.floatVal)));
		bufp = agentx_build_float( bufp, out_length,
	    		*(vp->val.floatVal), network_byte_order);
		DEBUGINDENTLESS();
		break;

	case ASN_OPAQUE_DOUBLE:
		DEBUGDUMPHEADER("send", "Build Opaque Double");
		DEBUGPRINTINDENT("dumpv_send");
		DEBUGMSG(("dumpv_send", "  Double:\t%lf\n", *(vp->val.doubleVal)));
		bufp = agentx_build_double( bufp, out_length,
	    		*(vp->val.doubleVal), network_byte_order);
		DEBUGINDENTLESS();
		break;

	case ASN_OPAQUE_I64:
	case ASN_OPAQUE_U64:
	case ASN_OPAQUE_COUNTER64:
		/* XXX - ToDo - encode as raw OPAQUE for now */
#endif

	case ASN_OCTET_STR:
	case ASN_IPADDRESS:
	case ASN_OPAQUE:
		bufp = agentx_build_string( bufp, out_length,
	    		vp->val.string, vp->val_len, network_byte_order);
		break;

	case ASN_OBJECT_ID:
		bufp = agentx_build_oid( bufp, out_length, 0,
	    		vp->val.objid, vp->val_len/4, network_byte_order);
		break;

	case ASN_COUNTER64:
		if ( *out_length < 8 )
		    return NULL;
		if ( network_byte_order ) {
		    DEBUGDUMPHEADER("send", "Build Counter64 (high, low)");
		    agentx_build_int( bufp, vp->val.counter64->high, network_byte_order);
		    agentx_build_int( bufp+4, vp->val.counter64->low,  network_byte_order);
		    DEBUGINDENTLESS();
		}
		else {
		    DEBUGDUMPHEADER("send", "Build Counter64 (low, high)");
		    agentx_build_int( bufp, vp->val.counter64->low,  network_byte_order);
		    agentx_build_int( bufp+4, vp->val.counter64->high, network_byte_order);
		    DEBUGINDENTLESS();
		}
		bufp        += 8;
		*out_length -= 8;
		break;

   	case ASN_NULL:
	case SNMP_NOSUCHOBJECT:
	case SNMP_NOSUCHINSTANCE:
	case SNMP_ENDOFMIBVIEW:
		break;

	default:
		return NULL;
    }
    DEBUGINDENTLESS();
    DEBUGINDENTLESS();
    return bufp;
}

u_char*
agentx_build_header(struct snmp_pdu *pdu, u_char *bufp, size_t *out_length)
{

    u_char *orig_bufp = bufp;

    *bufp = 1;			bufp++;		/* version */
    *bufp = pdu->command;	bufp++;		/* type    */
    *bufp = (u_char)(pdu->flags & AGENTX_MSG_FLAGS_MASK);
    				bufp++;		/* AgentX flags */
    *bufp = 0;			bufp++;		/* <reserved> */
    *out_length -=4;

    DEBUGDUMPHEADER("send", "AgentX Header");
    DEBUGDUMPSETUP("send", orig_bufp, 4);
    DEBUGMSG(("dumpv_send", "  Version:\t%d\n", *orig_bufp ));
    DEBUGPRINTINDENT("dumpv_send");
    DEBUGMSG(("dumpv_send", "  Command:\t%d (%s)\n",
				*(orig_bufp+1), agentx_cmd(*(orig_bufp+1))));
    DEBUGPRINTINDENT("dumpv_send");
    DEBUGMSG(("dumpv_send", "  Flags:\t%x\n", *(orig_bufp+2) ));
    
    DEBUGDUMPHEADER("send", "Session ID");
    agentx_build_int( bufp, pdu->sessid, pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
    DEBUGINDENTLESS();
    *out_length -=4;
    bufp        +=4;

    DEBUGDUMPHEADER("send", "Transaction ID");
    agentx_build_int( bufp, pdu->transid,  pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
    DEBUGINDENTLESS();
    *out_length -=4;
    bufp        +=4;

    DEBUGDUMPHEADER("send", "Request ID");
    agentx_build_int( bufp, pdu->reqid,  pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
    DEBUGINDENTLESS();
    *out_length -=4;
    bufp        +=4;

    DEBUGDUMPHEADER("send", "Dummy Length :-(");
    agentx_build_int( bufp, 0, 0 );  /* dummy payload length */
    DEBUGINDENTLESS();
    *out_length -=4;
    bufp        +=4;

    if ( pdu->flags & AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT ) {
	DEBUGDUMPHEADER("send", "Community");
	bufp = agentx_build_string( bufp, out_length,
		pdu->community,
		pdu->community_len,
		pdu->flags & AGENTX_MSG_FLAG_NETWORK_BYTE_ORDER );
	DEBUGINDENTLESS();
    }
		
    DEBUGINDENTLESS();
    return bufp;
}


static int
_agentx_build(struct snmp_session        *session,
             struct snmp_pdu            *pdu,
             register u_char            *packet,
             size_t                        *out_length)
{
     u_char *bufp = packet;
     u_char *prefix_ptr, *range_ptr;
     struct variable_list *vp;
     int inc;
     
    session->s_snmp_errno = 0;
    session->s_errno = 0;
     
		/* Build the header (and context if appropriate) */
     if ( *out_length < 20 )
	        return -1;

			/* Various PDU types shouldn't include context information */
     switch ( pdu->command ) {
     	case AGENTX_MSG_OPEN:
     	case AGENTX_MSG_CLOSE:
	case AGENTX_MSG_RESPONSE:
	case AGENTX_MSG_COMMITSET:
	case AGENTX_MSG_UNDOSET:
	case AGENTX_MSG_CLEANUPSET:
		pdu->flags &= ~(AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT);
     }
     bufp = agentx_build_header( pdu, bufp, out_length );
     if ( bufp == NULL )
     	return -1;
     
     DEBUGDUMPHEADER("send", "AgentX Payload");
     switch ( pdu->command ) {
     	case AGENTX_MSG_OPEN:
			/* Timeout */
	    if ( *out_length < 4 )
	        return -1;
	    *bufp = (u_char)pdu->time;		bufp++;
	    *bufp = 0;			bufp++;
	    *bufp = 0;			bufp++;
	    *bufp = 0;			bufp++;
	    *out_length -= 4;
	    DEBUGDUMPHEADER("send", "Open Timeout");
	    DEBUGDUMPSETUP("send", bufp-4, 4);
	    DEBUGMSG(("dumpv_send", "  Timeout:\t%d\n", *(bufp-4) ));
	    DEBUGINDENTLESS();

	    DEBUGDUMPHEADER("send", "Open ID");
	    bufp = agentx_build_oid( bufp, out_length, 0,
	    		pdu->variables->name, pdu->variables->name_length,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGINDENTLESS();
	    if ( bufp == NULL )
	    	return -1;
	    DEBUGDUMPHEADER("send", "Open Description");
	    bufp = agentx_build_string( bufp, out_length,
	    		pdu->variables->val.string, pdu->variables->val_len,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGINDENTLESS();
	    if ( bufp == NULL )
	    	return -1;
	    break;
	    
	case AGENTX_MSG_CLOSE:
			/* Reason */
	    if ( *out_length < 4 )
	        return -1;
	    *bufp = (u_char)pdu->errstat;	bufp++;
	    *bufp = 0;			bufp++;
	    *bufp = 0;			bufp++;
	    *bufp = 0;			bufp++;
	    *out_length -= 4;
	    DEBUGDUMPHEADER("send", "Close Reason");
	    DEBUGDUMPSETUP("send", bufp-4, 4);
	    DEBUGMSG(("dumpv_send", "  Reason:\t%d\n", *(bufp-4) ));
	    DEBUGINDENTLESS();
	    break;
	    
	case AGENTX_MSG_REGISTER:
	case AGENTX_MSG_UNREGISTER:
	    if ( *out_length < 4 )
	        return -1;
	    *bufp = (u_char)pdu->time;		bufp++;	    /* Timeout (Register only) */
	    *bufp = pdu->priority;		bufp++;
	    range_ptr = bufp;	 	/* Points to the 'range_subid' field */
	    *bufp = pdu->range_subid;	bufp++;
	    *bufp = 0;			bufp++;
	    DEBUGDUMPHEADER("send", "(Un)Register Header");
	    DEBUGDUMPSETUP("send", bufp-4, 4);
	    DEBUGMSG(("dumpv_send", "  Timeout:\t%d\n", *(bufp-4) ));
	    DEBUGPRINTINDENT("dumpv_send");
	    DEBUGMSG(("dumpv_send", "  Priority:\t%d\n", *(bufp-3) ));
	    DEBUGPRINTINDENT("dumpv_send");
	    DEBUGMSG(("dumpv_send", "  Range SubID:\t%d\n", *(bufp-2) ));
	    DEBUGINDENTLESS();
	    *out_length -= 4;

	    vp = pdu->variables;
	    prefix_ptr = bufp+1;	/* Points to the 'prefix' field */
	    DEBUGDUMPHEADER("send", "(Un)Register Prefix");
	    bufp = agentx_build_oid( bufp, out_length, 0,
	    		vp->name, vp->name_length,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGINDENTLESS();
	    if ( bufp == NULL )
	    	return -1;


	    if ( pdu->range_subid ) {
		if ( *out_length < 4 )
		    return -1;

			/* This assumes that the two OIDs match
			     to form a valid range */
		DEBUGDUMPHEADER("send", "(Un)Register Range");
	    	agentx_build_int( bufp, vp->val.objid[pdu->range_subid-1],
					pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
		DEBUGINDENTLESS();
		bufp        += 4;
		*out_length -= 4;

			/* If the OID has been 'compacted', then tweak
			     the packet's 'range_subid' to reflect this */
		if ( *prefix_ptr ) {
		     *range_ptr -= 5;
		     DEBUGPRINTINDENT("dumpv_send");
		     DEBUGMSG(("dumpv_send", "  Range SubID tweaked:\t%d\n", *(range_ptr) ));
		}
	    }
	    break;
	    
	case AGENTX_MSG_GETBULK:
	    if ( *out_length < 4 )
	        return -1;
	    DEBUGDUMPHEADER("send", "GetBulk Non-Repeaters");
	    agentx_build_short( bufp  , pdu->non_repeaters,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGDUMPHEADER("send", "GetBulk Max-Repetitions");
	    agentx_build_short( bufp+2, pdu->max_repetitions,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGINDENTLESS();
	    bufp        += 4;
	    *out_length -= 4;

		/* Fallthrough */

	case AGENTX_MSG_GET:
	case AGENTX_MSG_GETNEXT:

	    DEBUGDUMPHEADER("send", "Get* Variable List");
	    for (vp = pdu->variables; vp ; vp=vp->next_variable ) {
	        inc = ( vp->type == ASN_PRIV_INCL_RANGE );
		bufp = agentx_build_oid( bufp, out_length, inc,
	    		vp->name, vp->name_length,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    	if ( bufp == NULL )
	    	    return -1;
		bufp = agentx_build_oid( bufp, out_length, 0,
	    		vp->val.objid, vp->val_len/4,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    	if ( bufp == NULL )
	    	    return -1;
	    }
	    DEBUGINDENTLESS();
	    break;

	case AGENTX_MSG_RESPONSE:
	    pdu->flags &= ~(UCD_MSG_FLAG_EXPECT_RESPONSE);
	    if ( *out_length < 4 )
	        return -1;
	    agentx_build_int( bufp, pdu->time,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGDUMPHEADER("send", "Response sysUpTime");
	    DEBUGDUMPSETUP("send", bufp, 4);
	    DEBUGMSG(("dumpv_send", "  sysUpTime:\t%d\n", pdu->time ));
	    DEBUGINDENTLESS();
	    bufp        += 4;
	    *out_length -= 4;

	    if ( *out_length < 4 )
	        return -1;
	    agentx_build_short( bufp  , pdu->errstat,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    agentx_build_short( bufp+2, pdu->errindex,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGDUMPHEADER("send", "Response errors");
	    DEBUGDUMPSETUP("send", bufp, 4);
	    DEBUGMSG(("dumpv_send", "  errstat:\t%d\n",  pdu->errstat ));
	    DEBUGPRINTINDENT("dumpv_send");
	    DEBUGMSG(("dumpv_send", "  errindex:\t%d\n", pdu->errindex ));
	    DEBUGINDENTLESS();
	    bufp        += 4;
	    *out_length -= 4;

		/* Fallthrough */

	case AGENTX_MSG_INDEX_ALLOCATE:
	case AGENTX_MSG_INDEX_DEALLOCATE:
	case AGENTX_MSG_NOTIFY:
	case AGENTX_MSG_TESTSET:
	    DEBUGDUMPHEADER("send", "Get* Variable List");
	    for (vp = pdu->variables; vp ; vp=vp->next_variable ) {
		bufp = agentx_build_varbind( bufp, out_length, vp,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    	if ( bufp == NULL )
	    	    return -1;
	    }
	    DEBUGINDENTLESS();
	    break;
	    
	case AGENTX_MSG_COMMITSET:
	case AGENTX_MSG_UNDOSET:
	case AGENTX_MSG_CLEANUPSET:
	case AGENTX_MSG_PING:
	    /* "Empty" packet */
	    break;
	    
	case AGENTX_MSG_ADD_AGENT_CAPS:
	    DEBUGDUMPHEADER("send", "AgentCaps OID");
	    bufp = agentx_build_oid( bufp, out_length, 0,
	    		pdu->variables->name, pdu->variables->name_length,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGINDENTLESS();
	    if ( bufp == NULL )
	    	return -1;
	    DEBUGDUMPHEADER("send", "AgentCaps Description");
	    bufp = agentx_build_string( bufp, out_length,
	    		pdu->variables->val.string, pdu->variables->val_len,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGINDENTLESS();
	    if ( bufp == NULL )
	    	return -1;
	    break;

	case AGENTX_MSG_REMOVE_AGENT_CAPS:
	    DEBUGDUMPHEADER("send", "AgentCaps OID");
	    bufp = agentx_build_oid( bufp, out_length, 0,
	    		pdu->variables->name, pdu->variables->name_length,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    DEBUGINDENTLESS();
	    if ( bufp == NULL )
	    	return -1;
	    break;

	default:
	    session->s_snmp_errno = SNMPERR_UNKNOWN_PDU;
	    return -1;
     }
     DEBUGINDENTLESS();
     
     		/* Insert the payload length
		  (ignoring the 20-byte header)
		  and return the full length of the packet */
     agentx_build_int( packet+16, (bufp-packet)-20,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
     *out_length = bufp-packet;
     return 0;
}

int
agentx_build(struct snmp_session        *session,
             struct snmp_pdu            *pdu,
             register u_char            *packet,
             size_t                        *out_length)
{
    int rc;
    rc = _agentx_build(session,pdu,packet,out_length);
    if (rc) {
        if (0 == session->s_snmp_errno)
            session->s_snmp_errno = SNMPERR_BAD_ASN1_BUILD;
    }
    return (rc);
}

	/***********************
	*
	*  Utility functions for parsing an AgentX packet
	*
	***********************/
	
int
agentx_parse_int(u_char *data, u_int network_byte_order)
{
    u_int    value = 0;

		/*
		 *  Note - this doesn't handle 'PDP_ENDIAN' systems
		 *	If anyone needs this added, contact the coders list
		 */
    DEBUGDUMPSETUP("recv", data, 4);
    if ( network_byte_order ) {
	memmove( &value, data, 4);
#ifndef WORDS_BIGENDIAN
	value = ntohl( value );
#endif
    }
    else {
#ifndef WORDS_BIGENDIAN
	memmove( &value, data, 4);
#else
		/* The equivalent of the 'ntohl()' macro,
			except this macro is null on big-endian systems */
        value += data[3];   value <<= 8;
        value += data[2];   value <<= 8;
        value += data[1];   value <<= 8;
        value += data[0];
#endif
    }
    DEBUGMSG(("dumpv_recv", "  Integer:\t%ld (0x%.2X)\n", value, value));
    
    return value;
}


int
agentx_parse_short(u_char *data, u_int network_byte_order)
{
    u_short    value = 0;

    if ( network_byte_order ) {
	memmove( &value, data, 2);
#ifndef WORDS_BIGENDIAN
	value = ntohs( value );
#endif
    }
    else {
#ifndef WORDS_BIGENDIAN
	memmove( &value, data, 2);
#else
		/* The equivalent of the 'ntohs()' macro,
			except this macro is null on big-endian systems */
        value += data[1];   value <<= 8;
        value += data[0];
#endif
    }
    
    DEBUGDUMPSETUP("recv", data, 2);
    DEBUGMSG(("dumpv_recv", "  Short:\t%ld (0x%.2X)\n", value, value));
    return value;
}


u_char *
agentx_parse_oid( u_char *data, size_t *length, int *inc,
		  oid *oid_buf, size_t *oid_len, u_int network_byte_order)
{
     u_int n_subid;
     u_int prefix;
     int i;
     oid *oid_ptr = oid_buf;
     u_char *buf_ptr = data;

     if ( *length < 4 ) {
	DEBUGMSGTL(("agentx","Incomplete Object ID"));
	return NULL;
     }

     DEBUGDUMPHEADER("recv", "OID Header");
     DEBUGDUMPSETUP("recv", data, 4);
     DEBUGMSG(("dumpv_recv", "  # subids:\t%d (0x%.2X)\n", data[0], data[0]));
     DEBUGPRINTINDENT("dumpv_recv");
     DEBUGMSG(("dumpv_recv", "  prefix:\t%d (0x%.2X)\n",   data[1], data[1]));
     DEBUGPRINTINDENT("dumpv_recv");
     DEBUGMSG(("dumpv_recv", "  inclusive:\t%d (0x%.2X)\n",data[2], data[2]));

     DEBUGINDENTLESS();
     DEBUGDUMPHEADER("recv", "OID Segments");

     n_subid = data[0];
     prefix  = data[1];
     if ( inc )
	*inc = data[2];

      buf_ptr += 4;
     *length -= 4;

     if (n_subid == 0 && prefix == 0) {
		/* Null OID */
         *oid_ptr = 0;		oid_ptr++;
         *oid_ptr = 0;		oid_ptr++;
	 *oid_len = 2;
         DEBUGPRINTINDENT("dumpv_recv");
         DEBUGMSG(("dumpv_recv", "OID: NULL (0.0)\n"));
	 DEBUGINDENTLESS();
         return buf_ptr;
     }


     if ( *length < 4*n_subid ) {
	DEBUGMSGTL(("agentx","Incomplete Object ID"));
	return NULL;     
     } 
     
     if ( prefix ) {
         *oid_ptr = 1;		oid_ptr++;
         *oid_ptr = 3;		oid_ptr++;
         *oid_ptr = 6;		oid_ptr++;
         *oid_ptr = 1;		oid_ptr++;
         *oid_ptr = prefix;	oid_ptr++;
     }


     for ( i = 0  ; i < (int)n_subid ; i++ ) {
        oid_ptr[i] = agentx_parse_int( buf_ptr, network_byte_order );
	buf_ptr += 4;
	*length -= 4;
     }

     *oid_len = ( prefix ? n_subid + 5 : n_subid );
     DEBUGINDENTLESS();
     DEBUGPRINTINDENT("dumpv_recv");
     DEBUGMSG(("dumpv_recv", "OID: "));
     DEBUGMSGOID(("dumpv_recv", oid_buf, *oid_len));
     DEBUGMSG(("dumpv_recv", "\n"));
     return buf_ptr;
}



u_char *
agentx_parse_string( u_char *data, size_t *length,
		  u_char *string, size_t *str_len, u_int network_byte_order)
{
     u_int len;

     if ( *length < 4 ) {
	DEBUGMSGTL(("agentx","Incomplete string (too short: %d)", *length));
	return NULL;
     }

     len = agentx_parse_int( data, network_byte_order );
     if ( *length < len + 4 ) {
	DEBUGMSGTL(("agentx","Incomplete string (still too short: %d)",
                    *length));
	return NULL;
     }
     if ( len > *str_len ) {
	DEBUGMSGTL(("agentx","String too long (too long)"));
	return NULL;
     }
     memmove( string, data+4, len );
     string[len] = '\0';
     *str_len = len;

     len += 3;	/* Extend the string length to include the padding */
     len >>= 2;
     len <<= 2;

     *length -= ( len+4 );
     DEBUGDUMPSETUP("recv", data, (len+4));
     DEBUGIF("dumpv_recv") {
       char *buf = (char *)malloc(1+len+4);
       sprint_asciistring(buf, string, len+4);
       DEBUGMSG(("dumpv_recv", "String: %s\n", buf));
       free (buf);
     }
     return data + ( len+4 );
}

u_char*
agentx_parse_opaque(u_char *data, size_t *length, int *type,
	  u_char *opaque_buf, size_t *opaque_len, u_int network_byte_order)
{
    union {
	float	floatVal;
	double	doubleVal;
	int	intVal[2];
	char	c[sizeof(double)];
    } fu;
    int tmp;
    u_char *buf;
    u_char *cp;

    cp = agentx_parse_string( data, length,
				opaque_buf, opaque_len, network_byte_order);
    if ( cp == NULL )
	return NULL;

	buf = opaque_buf;

#ifdef OPAQUE_SPECIAL_TYPES
    if (( buf[0] != ASN_OPAQUE_TAG1 ) || ( *opaque_len <= 3 ))
	return cp;	/* Unrecognised opaque type */

    switch ( buf[1] ) {
	case ASN_OPAQUE_FLOAT:
		if (( *opaque_len != (3+sizeof(float))) ||
		    ( buf[2] != sizeof(float)))
			return cp;	/* Encoding isn't right for FLOAT */

		memcpy( &fu.c[0],  &buf[3], sizeof( float ));
		fu.intVal[0] = ntohl( fu.intVal[0] );
		*opaque_len = sizeof( float );
		memcpy( opaque_buf, &fu.c[0], sizeof( float ));
		*type = ASN_OPAQUE_FLOAT;
		DEBUGMSG(("dumpv_recv", "Float: %f\n", fu.floatVal));
		return cp;

	case ASN_OPAQUE_DOUBLE:
		if (( *opaque_len != (3+sizeof(double))) ||
		    ( buf[2] != sizeof(double)))
			return cp;	/* Encoding isn't right for DOUBLE */

		memcpy( &fu.c[0],  &buf[3], sizeof( double ));
		tmp          = ntohl( fu.intVal[1] );
		fu.intVal[1] = ntohl( fu.intVal[0] );
		fu.intVal[0] = tmp;
		*opaque_len = sizeof( double );
		memcpy( opaque_buf, &fu.c[0], sizeof( double ));
		*type = ASN_OPAQUE_DOUBLE;
		DEBUGMSG(("dumpv_recv", "Double: %lf\n", fu.doubleVal));
		return cp;

	case ASN_OPAQUE_I64:
	case ASN_OPAQUE_U64:
	case ASN_OPAQUE_COUNTER64:
	default:
		return cp;	/* Unrecognised opaque sub-type */
    }
#else
    return cp;
#endif
}


u_char *
agentx_parse_varbind( u_char *data, size_t *length, int *type,
		  oid *oid_buf, size_t *oid_len,
		  u_char *data_buf, size_t *data_len,
		  u_int network_byte_order)
{
     u_char *bufp = data;
     u_int   int_val;
     struct counter64 *c64 = (struct counter64 *)data_buf;
     
     DEBUGDUMPHEADER("recv", "VarBind:");
     DEBUGDUMPHEADER("recv", "Byte Order");
     *type = agentx_parse_short( bufp, network_byte_order );
     DEBUGINDENTLESS();
     bufp    += 4;
     *length -= 4;
     
     bufp = agentx_parse_oid( bufp, length, NULL,
     			oid_buf, oid_len, network_byte_order );
     if ( bufp == NULL ) {
            DEBUGINDENTLESS();
	    return NULL;
     }

     switch ( *type ) {
	case ASN_INTEGER:
	case ASN_COUNTER:
	case ASN_GAUGE:
	case ASN_TIMETICKS:

		int_val = agentx_parse_int( bufp, network_byte_order );
		memmove( data_buf, &int_val, 4);
		*data_len = 4;
		bufp    += 4;
		*length -= 4;
		break;
		
	case ASN_OCTET_STR:
	case ASN_IPADDRESS:

		bufp = agentx_parse_string( bufp, length,
			data_buf, data_len, network_byte_order );
		break;

	case ASN_OPAQUE:

		bufp = agentx_parse_opaque( bufp, length, type,
			data_buf, data_len, network_byte_order );
		break;
		
	case ASN_OBJECT_ID:
		bufp = agentx_parse_oid( bufp, length, NULL,
			(oid *)data_buf, data_len, network_byte_order );	
		*data_len *= 4;
			/* 'agentx_parse_oid()' returns the number of sub_ids */
		break;
		
	case ASN_COUNTER64:
		if ( network_byte_order ) {
		    c64->high = agentx_parse_int( bufp,   network_byte_order );
		    c64->low  = agentx_parse_int( bufp+4, network_byte_order );
		}
		else {
		    c64->low  = agentx_parse_int( bufp,   network_byte_order );
		    c64->high = agentx_parse_int( bufp+4, network_byte_order );
		}
		*data_len = 8;
		bufp    += 8;
		*length -= 8;
		break;
		
	case ASN_NULL:
	case SNMP_NOSUCHOBJECT:
	case SNMP_NOSUCHINSTANCE:
	case SNMP_ENDOFMIBVIEW:
		/* No data associated with these types */
		*data_len = 0;
		break;
	default:
                DEBUGINDENTLESS();
		return NULL;
     }
     DEBUGINDENTLESS();
     return bufp;
}

/*
 *  AgentX header:
 *
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |    h.version  |   h.type      |   h.flags     |  <reserved>   |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       h.sessionID                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     h.transactionID                           |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       h.packetID                              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                     h.payload_length                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 *    Total length = 20 bytes
 *
 *  If we don't seem to have the full packet, return NULL
 *    and let the driving code go back for the rest.
 *  Don't report this as an error, as it's quite "normal"
 *    with a connection-oriented service.
 *
 *  Note that once the header has been successfully processed
 *    (and hence we should have the full packet), any subsequent
 *    "running out of room" is indeed an error.
 */
u_char *
agentx_parse_header(struct snmp_pdu *pdu, u_char *data, size_t *length)
{
     register u_char *bufp = data;
     size_t payload;

     if ( *length < 20 ) {	/* Incomplete header */
	return NULL;
     }

     DEBUGDUMPHEADER("recv", "AgentX Header");
     DEBUGDUMPHEADER("recv", "Version");
     DEBUGDUMPSETUP("recv", bufp, 1);
     pdu->version = AGENTX_VERSION_BASE | *bufp;
     DEBUGMSG(("dumpv_recv", "  Version:\t%d\n", *bufp));
     DEBUGINDENTLESS();
     bufp++;

     DEBUGDUMPHEADER("recv", "Command");
     DEBUGDUMPSETUP("recv", bufp, 1);
     pdu->command = *bufp;
     DEBUGMSG(("dumpv_recv", "  Command:\t%d (%s)\n", *bufp, agentx_cmd(*bufp)));
     DEBUGINDENTLESS();
     bufp++;

     DEBUGDUMPHEADER("recv", "Flags");
     DEBUGDUMPSETUP("recv", bufp, 1);
     pdu->flags |= *bufp;
     DEBUGMSG(("dumpv_recv", "  Flags:\t0x%x\n", *bufp));
     DEBUGINDENTLESS();
     bufp++;

     DEBUGDUMPHEADER("recv", "Reserved Byte");
     DEBUGDUMPSETUP("recv", bufp, 1);
     DEBUGMSG(("dumpv_recv", "  Reserved:\t0x%x\n", *bufp));
     DEBUGINDENTLESS();
     bufp++;

     DEBUGDUMPHEADER("recv", "Session ID");
     pdu->sessid = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     DEBUGINDENTLESS();
     bufp += 4;

     DEBUGDUMPHEADER("recv", "Transaction ID");
     pdu->transid = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     DEBUGINDENTLESS();
     bufp += 4;

     DEBUGDUMPHEADER("recv", "Packet ID");
     pdu->reqid = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     DEBUGINDENTLESS();
     bufp += 4;

     DEBUGDUMPHEADER("recv", "Payload Length");
     payload = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     DEBUGINDENTLESS();
     bufp += 4;

     *length -= 20;
     if ( *length != payload ) {	/* Short payload */
	return NULL;
     }
     return bufp;
}


int
agentx_parse(struct snmp_session *session, struct snmp_pdu *pdu, u_char *data, size_t len)
{
     register u_char *bufp = data;
     u_char buffer[BUFSIZ];
     u_char *prefix_ptr;
     oid    oid_buffer[MAX_OID_LEN], end_oid_buf[MAX_OID_LEN];
     size_t buf_len         = BUFSIZ;
     size_t oid_buf_len     = MAX_OID_LEN;
     size_t end_oid_buf_len = MAX_OID_LEN;

     int    range_bound;/* OID-range upper bound */
     int    inc;	/* Inclusive SearchRange flag */
     int    type;	/* VarBind data type */
     size_t *length = &len;

     if ( pdu == NULL ) {
		/* Dump the packet in a formatted style */
	pdu = (struct snmp_pdu *)malloc( sizeof( struct snmp_pdu ));
	free( pdu );
	return(0);
     }
     if (!IS_AGENTX_VERSION( session->version ))
	return SNMPERR_BAD_VERSION;

#ifndef SNMPERR_INCOMPLETE_PACKET
	/*
	 *  Ideally, "short" packets on stream connections should
	 *    be handled specially, and the driving code set up to
	 *    keep reading until the full packet is received.
	 *
	 *  For now, lets assume that all packets are read in one go.
	 *    I've probably inflicted enough damage on the UCD library
	 *    for one week!
	 *
	 *  I'll come back to this once Wes is speaking to me again.
	 */
#define SNMPERR_INCOMPLETE_PACKET SNMPERR_ASN_PARSE_ERR
#endif


		/*
		 *  Handle (common) header ....
		 */
     bufp = agentx_parse_header( pdu, bufp, length );
     if ( bufp == NULL )
	return SNMPERR_INCOMPLETE_PACKET;	/* i.e. wait for the rest */

				/* Control PDU handling */
     pdu->flags |= UCD_MSG_FLAG_ALWAYS_IN_VIEW;
     pdu->flags |= UCD_MSG_FLAG_FORCE_PDU_COPY;
     pdu->flags &= (~UCD_MSG_FLAG_RESPONSE_PDU);

		/*
		 *  ... and (not-un-common) context
		 */
     if ( pdu->flags & 	AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT ) {
        DEBUGDUMPHEADER("recv", "Context");
	bufp = agentx_parse_string( bufp, length, buffer, &buf_len,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
        DEBUGINDENTLESS();
        if ( bufp == NULL )
	    return SNMPERR_ASN_PARSE_ERR;

	pdu->community_len = buf_len;
	snmp_clone_mem((void **)&pdu->community, 
				(void *)buffer, (unsigned) buf_len);
	buf_len = BUFSIZ;
     }

     DEBUGDUMPHEADER("recv", "PDU");
     DEBUGINDENTMORE();
     switch ( pdu->command ) {
	case AGENTX_MSG_OPEN:
		pdu->time = *bufp;	/* Timeout */
		bufp     += 4;
		*length  -= 4;

			/* Store subagent OID & description in a VarBind */
                DEBUGDUMPHEADER("recv", "Subagent OID");
		bufp = agentx_parse_oid( bufp, length, NULL,
				oid_buffer, &oid_buf_len,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
                DEBUGINDENTLESS();
		if ( bufp == NULL ) {
                    DEBUGINDENTLESS();
		    return SNMPERR_ASN_PARSE_ERR;
                }
                DEBUGDUMPHEADER("recv", "Subagent Description");
		bufp = agentx_parse_string( bufp, length, buffer, &buf_len,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
                DEBUGINDENTLESS();
		if ( bufp == NULL ) {
                    DEBUGINDENTLESS();
		    return SNMPERR_ASN_PARSE_ERR;
                }
		snmp_pdu_add_variable( pdu, oid_buffer, oid_buf_len,
				ASN_OCTET_STR, buffer, buf_len);

		oid_buf_len = MAX_OID_LEN;
		buf_len     = BUFSIZ;
		break;

	case AGENTX_MSG_CLOSE:
		pdu->errstat = *bufp;	/* Reason */
		bufp     += 4;
		*length  -= 4;

		break;

	case AGENTX_MSG_UNREGISTER:
	case AGENTX_MSG_REGISTER:
		pdu->time = *bufp;	/* Timeout (Register only) */
		bufp++;
		pdu->priority = *bufp;
		bufp++;
		pdu->range_subid = *bufp;
		bufp++;
		bufp++;
		*length -= 4;

		prefix_ptr = bufp+1;
                DEBUGDUMPHEADER("recv", "Registration OID");
		bufp = agentx_parse_oid( bufp, length, NULL,
				oid_buffer, &oid_buf_len,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
                DEBUGINDENTLESS();
		if ( bufp == NULL ) {
                    DEBUGINDENTLESS();
		    return SNMPERR_ASN_PARSE_ERR;
                }

		if ( pdu->range_subid ) {
		
			if ( *prefix_ptr ) {
			    pdu->range_subid += 5;
			}
    			range_bound = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
			bufp    += 4;
			*length -= 4;

				/* Construct the end-OID */
			end_oid_buf_len = oid_buf_len*sizeof(oid);
			memmove( &end_oid_buf, oid_buffer, end_oid_buf_len );
			end_oid_buf[ pdu->range_subid-1 ] = range_bound;
			
			snmp_pdu_add_variable( pdu, oid_buffer, oid_buf_len,
				ASN_PRIV_INCL_RANGE, (u_char *)end_oid_buf, end_oid_buf_len);
		}
		else {
			snmp_add_null_var( pdu, oid_buffer, oid_buf_len );
		}

		oid_buf_len = MAX_OID_LEN;
		break;

	case AGENTX_MSG_GETBULK:
                DEBUGDUMPHEADER("recv", "Non-repeaters");
		pdu->non_repeaters = agentx_parse_short( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
                DEBUGINDENTLESS();
                DEBUGDUMPHEADER("recv", "Max-repeaters");
		pdu->max_repetitions = agentx_parse_short( bufp+2,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
                DEBUGINDENTLESS();
		bufp    += 4;
		*length -= 4;
		/*  Fallthrough - SearchRange handling is the same */
		
	case AGENTX_MSG_GETNEXT:
	case AGENTX_MSG_GET:

			/*
			*  SearchRange List
			*  Keep going while we have data left
			*/
                DEBUGDUMPHEADER("recv", "Search Range");
		while ( *length > 0 ) {
		    bufp = agentx_parse_oid( bufp, length, &inc,
				oid_buffer, &oid_buf_len,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		    if ( bufp == NULL ) {
                            DEBUGINDENTLESS();
                            DEBUGINDENTLESS();
			    return SNMPERR_ASN_PARSE_ERR;
                    }
		    bufp = agentx_parse_oid( bufp, length, NULL,
				end_oid_buf, &end_oid_buf_len,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		    if ( bufp == NULL ) {
                            DEBUGINDENTLESS();
                            DEBUGINDENTLESS();
			    return SNMPERR_ASN_PARSE_ERR;
                    }
		    end_oid_buf_len *= sizeof(oid);
			/* 'agentx_parse_oid()' returns the number of sub_ids */

		    if ( inc )
			snmp_pdu_add_variable( pdu, oid_buffer, oid_buf_len,
				ASN_PRIV_INCL_RANGE, (u_char *)end_oid_buf, end_oid_buf_len);
		    else
			snmp_pdu_add_variable( pdu, oid_buffer, oid_buf_len,
				ASN_PRIV_EXCL_RANGE, (u_char *)end_oid_buf, end_oid_buf_len);
		}

                DEBUGINDENTLESS();
                oid_buf_len     = MAX_OID_LEN;
		end_oid_buf_len = MAX_OID_LEN;
		break;


	case AGENTX_MSG_RESPONSE:

     		pdu->flags |= UCD_MSG_FLAG_RESPONSE_PDU;

					/* sysUpTime */
		pdu->time = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		bufp    += 4;
		*length -= 4;
		
		pdu->errstat   = agentx_parse_short( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		pdu->errindex  = agentx_parse_short( bufp+2,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		bufp    += 4;
		*length -= 4;
		/*  Fallthrough - VarBind handling is the same */
		
	case AGENTX_MSG_INDEX_ALLOCATE:
	case AGENTX_MSG_INDEX_DEALLOCATE:
	case AGENTX_MSG_NOTIFY:
	case AGENTX_MSG_TESTSET:
	
			/*
			*  VarBind List
			*  Keep going while we have data left
			*/

                DEBUGDUMPHEADER("recv", "VarBindList");
		while ( *length > 0 ) {
		    bufp = agentx_parse_varbind( bufp, length, &type,
				oid_buffer, &oid_buf_len,
				buffer, &buf_len,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		    if ( bufp == NULL ) {
                            DEBUGINDENTLESS();
                            DEBUGINDENTLESS();
			    return SNMPERR_ASN_PARSE_ERR;
                    }
		    snmp_pdu_add_variable( pdu, oid_buffer, oid_buf_len,
				(u_char)type, buffer, buf_len);

		    oid_buf_len = MAX_OID_LEN;
		    buf_len     = BUFSIZ;
		}
                DEBUGINDENTLESS();
                break;

	case AGENTX_MSG_COMMITSET:
	case AGENTX_MSG_UNDOSET:
	case AGENTX_MSG_CLEANUPSET:
	case AGENTX_MSG_PING:

		/* "Empty" packet */
		break;


	case AGENTX_MSG_ADD_AGENT_CAPS:
			/* Store AgentCap OID & description in a VarBind */
		bufp = agentx_parse_oid( bufp, length, NULL,
				oid_buffer, &oid_buf_len,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		if ( bufp == NULL )
		    return SNMPERR_ASN_PARSE_ERR;
		bufp = agentx_parse_string( bufp, length, buffer, &buf_len,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		if ( bufp == NULL )
		    return SNMPERR_ASN_PARSE_ERR;
		snmp_pdu_add_variable( pdu, oid_buffer, oid_buf_len,
				ASN_OCTET_STR, buffer, buf_len);

		oid_buf_len = MAX_OID_LEN;
		buf_len     = BUFSIZ;
		break;

	case AGENTX_MSG_REMOVE_AGENT_CAPS:
			/* Store AgentCap OID & description in a VarBind */
		bufp = agentx_parse_oid( bufp, length, NULL,
				oid_buffer, &oid_buf_len,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		if ( bufp == NULL )
		    return SNMPERR_ASN_PARSE_ERR;
		snmp_add_null_var( pdu, oid_buffer, oid_buf_len );

		oid_buf_len = MAX_OID_LEN;
		break;

	default:
                DEBUGINDENTLESS();
                DEBUGINDENTLESS();
		DEBUGMSGTL(("agentx","Unrecognised PDU type"));
		return SNMPERR_UNKNOWN_PDU;
     }
     DEBUGINDENTLESS();
     DEBUGINDENTLESS();
     DEBUGINDENTLESS();
     return SNMP_ERR_NOERROR;
}




#ifdef TESTING

testit( struct snmp_pdu *pdu1)
{
     char packet1[BUFSIZ];
     char packet2[BUFSIZ];
     int len1, len2;
     struct snmp_pdu pdu2;
     struct snmp_session sess;

     memset( &pdu2, 0, sizeof(struct snmp_pdu));
     memset( packet1, 0, BUFSIZ );
     memset( packet2, 0, BUFSIZ );
     
     	/* Encode this into a "packet" */
     len1 = BUFSIZ;
     if ( agentx_build( &sess, pdu1, packet1, &len1 ) < 0 ) {
         DEBUGMSGTL(("agentx","First build failed"));
	 exit(1);
     }

     DEBUGMSGTL(("agentx","First build succeeded:\n"));
     xdump( packet1, len1, "Ax1> ");
     
     	/* Unpack this into a PDU */
     len2 = len1;
     if ( agentx_parse( &pdu2, packet1, &len2, (u_char **)NULL ) < 0 ) {
         DEBUGMSGTL(("agentx","First parse failed\n"));
	 exit(1);
     }
     DEBUGMSGTL(("agentx","First parse succeeded:\n"));
     if ( len2 != 0 ) 
         DEBUGMSGTL(("agentx","Warning - parsed packet has %d bytes left\n", len2));

     	/* Encode this into another "packet" */
     len2 = BUFSIZ;
     if ( agentx_build( &sess, &pdu2, packet2, &len2 ) < 0 ) {
         DEBUGMSGTL(("agentx","Second build failed\n"));
	 exit(1);
     }

     DEBUGMSGTL(("agentx","Second build succeeded:\n"));
     xdump( packet2, len2, "Ax2> ");

	/* Compare the results */
     if ( len1 != len2 ) {
     	DEBUGMSGTL(("agentx","Error: first build (%d) is different to second (%d)\n",
			len1, len2));
	exit(1);
     }
     if (memcmp( packet1, packet2, len1 ) != 0 ) {
     	DEBUGMSGTL(("agentx","Error: first build data is different to second\n"));
	exit(1);
     }

     DEBUGMSGTL(("agentx","OK\n"));
}



main ()
{
     struct snmp_pdu pdu1;
     oid oid_buf[] = { 1, 3, 6, 1, 2, 1, 10 };
     oid oid_buf2[] = { 1, 3, 6, 1, 2, 1, 20 };
     oid null_oid[] = { 0, 0 };
     char *string = "Example string";     
     char *context = "LUCS";     

     
	/* Create an example AgentX pdu structure */

     memset( &pdu1, 0, sizeof(struct snmp_pdu));
     pdu1.command = AGENTX_MSG_TESTSET;
     pdu1.flags  =  0;
     pdu1.sessid = 16;
     pdu1.transid  = 24;
     pdu1.reqid  = 132;
     
     pdu1.time   = 10;
     pdu1.non_repeaters   = 3;
     pdu1.max_repetitions   = 32;
     pdu1.priority = 5;
     pdu1.range_subid = 0;

     snmp_pdu_add_variable( &pdu1, oid_buf, sizeof(oid_buf)/sizeof(oid),
				ASN_OBJECT_ID, (char *)oid_buf2, sizeof(oid_buf2));
     snmp_pdu_add_variable( &pdu1, oid_buf, sizeof(oid_buf)/sizeof(oid),
				ASN_INTEGER, (char *)&pdu1.reqid, sizeof(pdu1.reqid));
     snmp_pdu_add_variable( &pdu1, oid_buf, sizeof(oid_buf)/sizeof(oid),
				ASN_OCTET_STR, (char *)string, strlen(string));

     printf("Test with non-network order.....\n");
     testit( &pdu1 );

     printf("\nTest with network order.....\n");
     pdu1.flags |= AGENTX_FLAGS_NETWORK_BYTE_ORDER;
     testit( &pdu1 );

     pdu1.community = context;
     pdu1.community_len = strlen(context);
     pdu1.flags |= AGENTX_FLAGS_NON_DEFAULT_CONTEXT;
     printf("Test with non-default context.....\n");
     testit( &pdu1 );

 
}
#endif

/* returns the proper length of an incoming agentx packet. */
/*
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |   h.version   |    h.type     |    h.flags    |  <reserved>   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                          h.sessionID                          |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        h.transactionID                        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                          h.packetID                           |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                        h.payload_length                       |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    20 bytes in header
 */

int
agentx_check_packet(u_char *packet, size_t packet_len) {

  if (packet_len < 20)
    return 0; /* minimum header length == 20 */

  return agentx_parse_int(packet+16,
                          *(packet+2) & AGENTX_FLAGS_NETWORK_BYTE_ORDER) + 20;
}

  
