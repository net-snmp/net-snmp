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

int agentx_dump(struct snmp_session *,struct snmp_pdu *, u_char *, size_t);

void
agentx_build_int(u_char *bufp, u_int value, int network_byte_order)
{
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
}

void
agentx_build_short(u_char *bufp, int in_value, int network_byte_order)
{
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
}


u_char*
agentx_build_oid(u_char *bufp, size_t *out_length, int inc,
	oid *name, size_t name_len, int network_byte_order)
{
    int prefix = 0;
    size_t i;

    if ( name_len == 2 && name[0]  == 0 && name[1]  == 0  ) {
	 name_len = 0;	/* NUll OID */
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
    
    for ( i = 0 ; i < name_len ; i++ ) {
        agentx_build_int( bufp, name[i], network_byte_order );
	bufp        += 4;
	*out_length -= 4;
    }

    return bufp;
}

u_char*
agentx_build_string(u_char *bufp, size_t *out_length,
	u_char *name, size_t name_len, int network_byte_order)
{
    if ( *out_length < 4 + name_len ) {
        return NULL;
    }
    agentx_build_int( bufp, (u_int)name_len, network_byte_order );
    bufp        += 4;
    *out_length -= 4;
    if ( name_len == 0 )
	return bufp;
    
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
	*out_length--;
    }
    return bufp;
}

u_char*
agentx_build_varbind(u_char *bufp, size_t *out_length,
	struct variable_list *vp, int network_byte_order)
{
    if ( *out_length < 4 )
    	return NULL;
	
    agentx_build_short( bufp, (u_int)vp->type, network_byte_order);
    bufp        +=2;
    *bufp = 0;			bufp++;
    *bufp = 0;			bufp++;		/* <reserved> */
    *out_length -=4;

    bufp = agentx_build_oid( bufp, out_length, 0,
	    		vp->name, vp->name_length, network_byte_order);
    if ( bufp == NULL )
    	return NULL;

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
		    agentx_build_int( bufp, vp->val.counter64->high, network_byte_order);
		    agentx_build_int( bufp+4, vp->val.counter64->low,  network_byte_order);
		}
		else {
		    agentx_build_int( bufp, vp->val.counter64->low,  network_byte_order);
		    agentx_build_int( bufp+4, vp->val.counter64->high, network_byte_order);
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
    return bufp;
}

u_char*
agentx_build_header(struct snmp_pdu *pdu, u_char *bufp, size_t *out_length)
{

    *bufp = 1;			bufp++;		/* version */
    *bufp = pdu->command;	bufp++;		/* type    */
    *bufp = pdu->flags & AGENTX_MSG_FLAGS_MASK;
    				bufp++;		/* AgentX flags */
    *bufp = 0;			bufp++;		/* <reserved> */
    *out_length -=4;
    
    agentx_build_int( bufp, pdu->sessid, pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
    *out_length -=4;
    bufp        +=4;
    agentx_build_int( bufp, pdu->transid,  pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
    *out_length -=4;
    bufp        +=4;
    agentx_build_int( bufp, pdu->reqid,  pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
    *out_length -=4;
    bufp        +=4;
    agentx_build_int( bufp, 0, 0 );  /* dummy payload length */
    *out_length -=4;
    bufp        +=4;

    if ( pdu->flags & AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT ) {
	bufp = agentx_build_string( bufp, out_length,
		pdu->community,
		pdu->community_len,
		pdu->flags & AGENTX_MSG_FLAG_NETWORK_BYTE_ORDER );
    }
		
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
     size_t length;
     struct variable_list *vp;
     int inc;
     
    session->s_snmp_errno = 0;
    session->s_errno = 0;
     
		/* Build the header (and context if appropriate) */
     if ( *out_length < 20 )
	        return -1;
     bufp = agentx_build_header( pdu, bufp, out_length );
     if ( bufp == NULL )
     	return -1;
     
     switch ( pdu->command ) {
     	case AGENTX_MSG_OPEN:
			/* Timeout */
	    if ( *out_length < 4 )
	        return -1;
	    *bufp = pdu->time;		bufp++;
	    *bufp = 0;			bufp++;
	    *bufp = 0;			bufp++;
	    *bufp = 0;			bufp++;
	    *out_length -= 4;

	    bufp = agentx_build_oid( bufp, out_length, 0,
	    		pdu->variables->name, pdu->variables->name_length,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    if ( bufp == NULL )
	    	return -1;
	    bufp = agentx_build_string( bufp, out_length,
	    		pdu->variables->val.string, pdu->variables->val_len,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    if ( bufp == NULL )
	    	return -1;
	    break;
	    
	case AGENTX_MSG_CLOSE:
			/* Reason */
	    if ( *out_length < 4 )
	        return -1;
	    *bufp = pdu->errstat;	bufp++;
	    *bufp = 0;			bufp++;
	    *bufp = 0;			bufp++;
	    *bufp = 0;			bufp++;
	    *out_length -= 4;
	    break;
	    
	case AGENTX_MSG_REGISTER:
	case AGENTX_MSG_UNREGISTER:
	    if ( *out_length < 4 )
	        return -1;
	    *bufp = pdu->time;		bufp++;	    /* Timeout (Register only) */
	    *bufp = pdu->priority;		bufp++;
	    range_ptr = bufp;	 	/* Points to the 'range_subid' field */
	    *bufp = pdu->range_subid;	bufp++;
	    *bufp = 0;			bufp++;
	    *out_length -= 4;

	    vp = pdu->variables;
	    prefix_ptr = bufp+1;	/* Points to the 'prefix' field */
	    bufp = agentx_build_oid( bufp, out_length, 0,
	    		vp->name, vp->name_length,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    if ( bufp == NULL )
	    	return -1;


	    if ( pdu->range_subid ) {
		if ( *out_length < 4 )
		    return -1;

			/* This assumes that the two OIDs match
			     to form a valid range */
	    	agentx_build_int( bufp, vp->val.objid[pdu->range_subid-1],
					pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
		bufp        += 4;
		*out_length -= 4;

			/* If the OID has been 'compacted', then tweak
			     the packet's 'range_subid' to reflect this */
		if ( *prefix_ptr )
		     *range_ptr -= 5;
	    }
	    break;
	    
	case AGENTX_MSG_GETBULK:
	    if ( *out_length < 4 )
	        return -1;
	    agentx_build_short( bufp  , pdu->non_repeaters,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    agentx_build_short( bufp+2, pdu->max_repetitions,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    bufp        += 4;
	    *out_length -= 4;

		/* Fallthrough */

	case AGENTX_MSG_GET:
	case AGENTX_MSG_GETNEXT:

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
	    break;

	case AGENTX_MSG_RESPONSE:
	    pdu->flags &= ~(UCD_MSG_FLAG_EXPECT_RESPONSE);
	    if ( *out_length < 4 )
	        return -1;
	    agentx_build_int( bufp, pdu->time,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    bufp        += 4;
	    *out_length -= 4;

	    if ( *out_length < 4 )
	        return -1;
	    agentx_build_short( bufp  , pdu->errstat,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    agentx_build_short( bufp+2, pdu->errindex,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    bufp        += 4;
	    *out_length -= 4;

		/* Fallthrough */

	case AGENTX_MSG_INDEX_ALLOCATE:
	case AGENTX_MSG_INDEX_DEALLOCATE:
	case AGENTX_MSG_NOTIFY:
	case AGENTX_MSG_TESTSET:
	    for (vp = pdu->variables; vp ; vp=vp->next_variable ) {
		bufp = agentx_build_varbind( bufp, out_length, vp,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    	if ( bufp == NULL )
	    	    return -1;
	    }
	    break;
	    
	case AGENTX_MSG_COMMITSET:
	case AGENTX_MSG_UNDOSET:
	case AGENTX_MSG_CLEANUPSET:
	case AGENTX_MSG_PING:
	    /* "Empty" packet */
	    break;
	    
	case AGENTX_MSG_ADD_AGENT_CAPS:
	    bufp = agentx_build_oid( bufp, out_length, 0,
	    		pdu->variables->name, pdu->variables->name_length,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    if ( bufp == NULL )
	    	return -1;
	    bufp = agentx_build_string( bufp, out_length,
	    		pdu->variables->val.string, pdu->variables->val_len,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    if ( bufp == NULL )
	    	return -1;
	    break;

	case AGENTX_MSG_REMOVE_AGENT_CAPS:
	    bufp = agentx_build_oid( bufp, out_length, 0,
	    		pdu->variables->name, pdu->variables->name_length,
			pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER);
	    if ( bufp == NULL )
	    	return -1;
	    break;

	default:
	    session->s_snmp_errno = SNMPERR_UNKNOWN_PDU;
	    return -1;
     }
     
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
    DEBUGDUMPSETUP("dump_recv", data, 4);
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
    DEBUGMSG(("dump_recv", "  Integer:\t%ld (0x%.2X)\n", value, value));
    
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
    
    DEBUGDUMPSETUP("dump_recv", data, 2);
    DEBUGMSG(("dump_recv", "  Short:\t%ld (0x%.2X)\n", value, value));
    return value;
}


u_char *
agentx_parse_oid( u_char *data, size_t *length, int *inc,
		  oid *oid_buf, size_t *oid_len, u_int network_byte_order)
{
     u_int n_subid, subid;
     u_int prefix;
     int i;
     oid *oid_ptr = oid_buf;
     u_char *buf_ptr = data;

     if ( *length < 4 ) {
	DEBUGMSGTL(("agentx","Incomplete Object ID"));
	return NULL;
     }

     n_subid = data[0];
     prefix  = data[1];
     if ( inc )
	*inc = data[2];

      buf_ptr += 4;
     *length -= 4;

     if ( n_subid == 0 ) {
		/* Null OID */
         *oid_ptr = 0;		oid_ptr++;
         *oid_ptr = 0;		oid_ptr++;
	 *oid_len = 2;
         DEBUGDUMPSETUP("dump_recv", data, 4);
         DEBUGDUMPHEADER("dump_recv", "OID Segments\n");
         DEBUGMSG(("dump_recv", "OID: NULL (0.0)\n"));
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


     DEBUGDUMPHEADER("dump_recv", "OID Segments\n");
     for ( i = 0  ; i<n_subid ; i++ ) {
        oid_ptr[i] = agentx_parse_int( buf_ptr, network_byte_order );
	buf_ptr += 4;
	*length -= 4;
     }
     DEBUGINDENTLESS();

     *oid_len = ( prefix ? n_subid + 5 : n_subid );
     DEBUGDUMPSETUP("dump_recv", data, buf_ptr - data);
     DEBUGMSG(("dump_recv", "OID: "));
     DEBUGMSGOID(("dump_recv", oid_buf, *oid_len));
     DEBUGMSG(("dump_recv", "\n"));
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
     DEBUGDUMPSETUP("dump_recv", data, (len+4));
     DEBUGIF("dump_recv") {
       char *buf = (char *)malloc(1+len+4);
       sprint_asciistring(buf, string, len+4);
       DEBUGMSG(("dump_recv", "String: %s\n", buf));
       free (buf);
     }
     return data + ( len+4 );
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
     size_t convert_tmp;
     
     DEBUGDUMPHEADER("dump_recv", "VarBind:\n");
     DEBUGDUMPHEADER("dump_recv", "Parsing Byte Order\n");
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
	case ASN_OPAQUE:

		bufp = agentx_parse_string( bufp, length,
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

     DEBUGDUMPHEADER("dump_recv", "AgentX Header\n");
     DEBUGDUMPHEADER("dump_recv", "Parsing AgentX Version\n");
     DEBUGDUMPSETUP("dump_recv", bufp, 1);
     pdu->version = AGENTX_VERSION_BASE | *bufp;
     DEBUGMSG(("dump_recv", "Version:\t%d\n", *bufp));
     DEBUGINDENTLESS();
     bufp++;

     DEBUGDUMPHEADER("dump_recv", "Parsing AgentX Command\n");
     DEBUGDUMPSETUP("dump_recv", bufp, 1);
     pdu->command = *bufp;
     DEBUGMSG(("dump_recv", "Command:\t%d\n", *bufp));
     DEBUGINDENTLESS();
     bufp++;

     DEBUGDUMPHEADER("dump_recv", "Parsing AgentX Flags\n");
     DEBUGDUMPSETUP("dump_recv", bufp, 1);
     pdu->flags |= *bufp;
     DEBUGMSG(("dump_recv", "Flags:\t0x%x\n", *bufp));
     DEBUGINDENTLESS();
     bufp++;

     DEBUGDUMPHEADER("dump_recv", "Parsing AgentX Reserved Byte\n");
     DEBUGDUMPSETUP("dump_recv", bufp, 1);
     DEBUGMSG(("dump_recv", "Byte:\t0x%x\n", *bufp));
     DEBUGINDENTLESS();
     bufp++;

     DEBUGDUMPHEADER("dump_recv", "Parsing AgentX Session ID\n");
     pdu->sessid = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     DEBUGINDENTLESS();
     bufp += 4;

     DEBUGDUMPHEADER("dump_recv", "Parsing AgentX Transaction ID\n");
     pdu->transid = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     DEBUGINDENTLESS();
     bufp += 4;

     DEBUGDUMPHEADER("dump_recv", "Parsing AgentX Packet ID\n");
     pdu->reqid = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     DEBUGINDENTLESS();
     bufp += 4;

     DEBUGDUMPHEADER("dump_recv", "Parsing AgentX Payload Length\n");
     payload = agentx_parse_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     DEBUGINDENTLESS();
     bufp += 4;

     *length -= 20;
     DEBUGINDENTLESS();
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
	agentx_dump( session, pdu, data, len );
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
        DEBUGDUMPHEADER("dump_recv", "Parsing Context\n");
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

     DEBUGDUMPHEADER("dump_recv", "Parsing PDU\n");
     DEBUGINDENTMORE();
     DEBUGPRINTINDENT("dump_recv");
     switch ( pdu->command ) {
	case AGENTX_MSG_OPEN:
        	DEBUGMSG(("dump_recv", "Open PDU\n"));
		pdu->time = *bufp;	/* Timeout */
		bufp     += 4;
		*length  -= 4;

			/* Store subagent OID & description in a VarBind */
                DEBUGDUMPHEADER("dump_recv", "Parsing Subagent OID\n");
		bufp = agentx_parse_oid( bufp, length, NULL,
				oid_buffer, &oid_buf_len,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
                DEBUGINDENTLESS();
		if ( bufp == NULL ) {
                    DEBUGINDENTLESS();
		    return SNMPERR_ASN_PARSE_ERR;
                }
                DEBUGDUMPHEADER("dump_recv", "Parsing Subagent Description\n");
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
        	DEBUGMSG(("dump_recv", "Close PDU\n"));
		pdu->errstat = *bufp;	/* Reason */
		bufp     += 4;
		*length  -= 4;

		break;

	case AGENTX_MSG_UNREGISTER:
        	DEBUGMSG(("dump_recv", "Un"));
	case AGENTX_MSG_REGISTER:
        	DEBUGMSG(("dump_recv", "Register PDU\n"));
		pdu->time = *bufp;	/* Timeout (Register only) */
		bufp++;
		pdu->priority = *bufp;
		bufp++;
		pdu->range_subid = *bufp;
		bufp++;
		bufp++;
		*length -= 4;

		prefix_ptr = bufp+1;
                DEBUGDUMPHEADER("dump_recv", "Parsing Registration OID\n");
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
			memmove( &end_oid_buf, oid_buffer, oid_buf_len*4 );
			end_oid_buf_len = oid_buf_len*4;
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
        	DEBUGMSG(("dump_recv", "getbulk PDU\n"));
                DEBUGDUMPHEADER("dump_recv", "Parsing Non-repeaters\n");
		pdu->non_repeaters = agentx_parse_short( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
                DEBUGINDENTLESS();
                DEBUGDUMPHEADER("dump_recv", "Parsing Max-repeaters\n");
		pdu->max_repetitions = agentx_parse_short( bufp+2,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
                DEBUGINDENTLESS();
		bufp    += 4;
		*length -= 4;
		/*  Fallthrough - SearchRange handling is the same */
		
	case AGENTX_MSG_GETNEXT:
        	DEBUGMSG(("dump_recv", "next-"));
	case AGENTX_MSG_GET:
        	DEBUGMSG(("dump_recv", "get PDU\n"));

			/*
			*  SearchRange List
			*  Keep going while we have data left
			*/
                DEBUGDUMPHEADER("dump_recv", "Parsing Search Range\n");
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
		    end_oid_buf_len *= 4;
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

        	DEBUGMSG(("dump_recv", "response PDU\n"));
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

                DEBUGDUMPHEADER("dump_recv", "Parsing VarBindList\n");
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
				type, buffer, buf_len);

		    oid_buf_len = MAX_OID_LEN;
		    buf_len     = BUFSIZ;
		}
                DEBUGINDENTLESS();
                break;

	case AGENTX_MSG_COMMITSET:
	case AGENTX_MSG_UNDOSET:
	case AGENTX_MSG_CLEANUPSET:
	case AGENTX_MSG_PING:
        	DEBUGMSG(("dump_recv", "set or ping PDU\n"));

		/* "Empty" packet */
		break;


	case AGENTX_MSG_ADD_AGENT_CAPS:
			/* Store AgentCap OID & description in a VarBind */
        	DEBUGMSG(("dump_recv", "add agent caps PDU\n"));
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
        	DEBUGMSG(("dump_recv", "remove agent caps PDU\n"));
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
        	DEBUGMSG(("dump_recv", "Unrecognised PDU\n"));
                DEBUGINDENTLESS();
                DEBUGINDENTLESS();
		DEBUGMSGTL(("agentx","Unrecognised PDU type"));
		return SNMPERR_UNKNOWN_PDU;
     }
     DEBUGINDENTLESS();
     DEBUGINDENTLESS();
     return SNMP_ERR_NOERROR;
}


	/***********************
	*
	*  Utility functions for dumping an AgentX packet
	*	Cribbed shamelessly from the parsing code
	*
	*  TODO: Properly structured indentation
	*
	***********************/
	
int
agentx_dump_int(u_char *data, u_int network_byte_order)
{
    u_int    value = agentx_parse_int( data, network_byte_order );
    DEBUGMSGTL(("agentx","INTEGER %.2x %.2x %.2x %.2x = %d\n",
		*data, *(data+1), *(data+2), *(data+3), value));

    return value;
}


int
agentx_dump_short(u_char *data, u_int network_byte_order)
{
    u_int    value = agentx_parse_short( data, network_byte_order );
    DEBUGMSGTL(("agentx","SHORT %.2x %.2x = %d\n",
		*data, *(data+1), value));
    
    return value;
}


u_char *
agentx_dump_oid( u_char *data, size_t *length, u_int network_byte_order)
{
     u_int n_subid, subid;
     u_int prefix;
     int i;
     u_char *buf_ptr = data;

     if ( *length < 4 ) {
	DEBUGMSGTL(("agentx","Incomplete Object ID"));
	return NULL;
     }

     n_subid = data[0];
     prefix  = data[1];

DEBUGMSGTL(("agentx","OBJECT ID #subids = %d,  prefix = %d, inc = %d, (reserved %d)\n", data[1], data[0], data[2], data[3]));

      buf_ptr += 4;
     *length -= 4;

     if ( n_subid == 0 ) {
DEBUGMSGTL(("agentx","\t NULL OID\n"));
	return buf_ptr;
     }


     if ( *length < 4*n_subid ) {
	DEBUGMSGTL(("agentx","Incomplete Object ID"));
	return NULL;     
     } 
     
     if ( prefix ) {
DEBUGMSGTL(("agentx","\t [.1.3.6.1.%d]\n", prefix));
     }


     for ( i = 0  ; i<n_subid ; i++ ) {
DEBUGMSGTL(("agentx","\t "));
       	agentx_dump_int( buf_ptr, network_byte_order );
	buf_ptr += 4;
	*length -= 4;
     }

     return buf_ptr;
}



u_char *
agentx_dump_string( u_char *data, size_t *length, u_int network_byte_order)
{
     u_int len, i;

     if ( *length <= 4 ) {
	DEBUGMSGTL(("agentx","Incomplete string"));
	return NULL;
     }

DEBUGMSGTL(("agentx","STRING\n\tlength = "));
     len = agentx_dump_int( data, network_byte_order );
     if ( *length < len + 4 ) {
	DEBUGMSGTL(("agentx","Incomplete string"));
	return NULL;
     }
DEBUGMSGTL(("agentx","\t DATA "));
     for ( i = 0 ; i < len ; i++ ) {
	DEBUGMSGTL(("agentx"," %.2x", data[4+i]));
     }
DEBUGMSGTL(("agentx","\n\t = %c", '"'));
     for ( i = 0 ; i < len ; i++ ) {
	DEBUGMSGTL(("agentx"," %c", data[4+i]));
     }
DEBUGMSGTL(("agentx","%c\n", '"'));

     len += 3;	/* Extend the string length to include the padding */
     len >>= 2;
     len <<= 2;

     *length -= ( len+4 );
     return data + ( len+4 );
}


u_char *
agentx_dump_varbind( u_char *data, size_t *length, u_int network_byte_order)
{
     u_char *bufp = data;
     u_int   type;
     
DEBUGMSGTL(("agentx","VARBIND\n\ttype = "));
     type = agentx_dump_short( bufp, network_byte_order );
DEBUGMSGTL(("agentx","padding %.2x %.2x)\n", *(bufp+2), *(bufp+3)));
     bufp    += 4;
     *length -= 4;
     
DEBUGMSGTL(("agentx","\t "));
     bufp = agentx_dump_oid( bufp, length, network_byte_order );
     if ( bufp == NULL )
	    return NULL;

DEBUGMSGTL(("agentx","\t value = "));
     switch ( type ) {
	case ASN_INTEGER:
	case ASN_COUNTER:
	case ASN_GAUGE:
	case ASN_TIMETICKS:

		agentx_dump_int( bufp, network_byte_order );
		bufp    += 4;
		*length -= 4;
		break;
		
	case ASN_OCTET_STR:
	case ASN_IPADDRESS:
	case ASN_OPAQUE:

		bufp = agentx_dump_string( bufp, length, network_byte_order );
		break;
		
	case ASN_OBJECT_ID:
		bufp = agentx_dump_oid( bufp, length, network_byte_order );
		break;
		
	case ASN_COUNTER64:
		if ( network_byte_order ) {
		    DEBUGMSGTL(("agentx","\t High "));
		    agentx_dump_int( bufp,   network_byte_order );
		    DEBUGMSGTL(("agentx","\t Low "));
		    agentx_dump_int( bufp+4, network_byte_order );
		}
		else {
		    DEBUGMSGTL(("agentx","\t Low "));
		    agentx_dump_int( bufp,   network_byte_order );
		    DEBUGMSGTL(("agentx","\t High "));
		    agentx_dump_int( bufp+4, network_byte_order );
		}
		bufp    += 8;
		*length -= 8;
		break;
		
	case ASN_NULL:
	case SNMP_NOSUCHOBJECT:
	case SNMP_NOSUCHINSTANCE:
	case SNMP_ENDOFMIBVIEW:
		/* No data associated with these types */
DEBUGMSGTL(("agentx","null data \n"));
		break;
	default:
DEBUGMSGTL(("agentx","unrecognised \n"));
		return NULL;
     }
     return bufp;
}


u_char *
agentx_dump_header(struct snmp_pdu *pdu, u_char *data, size_t *length)
{
     register u_char *bufp = data;
     size_t payload;

     if ( *length < 20 ) {	/* Incomplete header */
	return NULL;
     }

DEBUGMSGTL(("agentx","HEADER version = %d, command = %d, flags = %.2x, (reserved %d)\n", *bufp, *(bufp+1), *(bufp+2), *(bufp+3)));
     pdu->version = AGENTX_VERSION_BASE | *bufp;
     bufp++;
     pdu->command = *bufp;
     bufp++;
     pdu->flags |= *bufp;
     bufp++;
     bufp++;

DEBUGMSGTL(("agentx","\t Session ID = "));
     agentx_dump_int( bufp, pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     bufp += 4;
DEBUGMSGTL(("agentx","\t Request ID = "));
     agentx_dump_int( bufp, pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     bufp += 4;
DEBUGMSGTL(("agentx","\t Message ID = "));
     agentx_dump_int( bufp, pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     bufp += 4;
DEBUGMSGTL(("agentx","\t Payload Length = "));
     payload = agentx_dump_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
     bufp += 4;

     *length -= 20;
     if ( *length != payload ) {	/* Short payload */
	return NULL;
     }
     return bufp;
}


int
agentx_dump(struct snmp_session *session, struct snmp_pdu *pdu, u_char *data, size_t len)
{
     register u_char *bufp = data;
     u_char buffer[BUFSIZ];
     u_char *prefix_ptr;

     int    range_subid;
     int    inc;	/* Inclusive SearchRange flag */
     int    type;	/* VarBind data type */
     size_t *length = &len;

     if (!IS_AGENTX_VERSION( session->version ))
	return SNMPERR_BAD_VERSION;

		/*
		 *  Handle (common) header ....
		 */
     bufp = agentx_dump_header( pdu, bufp, length );
     if ( bufp == NULL )
	return SNMPERR_INCOMPLETE_PACKET;	/* i.e. wait for the rest */

		/*
		 *  ... and (not-un-common) context
		 */
     if ( pdu->flags & 	AGENTX_MSG_FLAG_NON_DEFAULT_CONTEXT ) {
DEBUGMSGTL(("agentx","CONTEXT "));
	bufp = agentx_dump_string( bufp, length,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
	if ( bufp == NULL )
	    return SNMPERR_ASN_PARSE_ERR;

     }

     switch ( pdu->command ) {
	case AGENTX_MSG_OPEN:
DEBUGMSGTL(("agentx","OPEN T/Out = %d, (reserved %d %d %d)\n", *bufp, *(bufp+1), *(bufp+2), *(bufp+3)));
		bufp     += 4;
		*length  -= 4;

		bufp = agentx_dump_oid( bufp, length,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		if ( bufp == NULL )
		    return SNMPERR_ASN_PARSE_ERR;
		bufp = agentx_dump_string( bufp, length,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		if ( bufp == NULL )
		    return SNMPERR_ASN_PARSE_ERR;
		break;

	case AGENTX_MSG_CLOSE:
DEBUGMSGTL(("agentx","CLOSE reason = %d, (reserved %d %d %d)\n", *bufp, *(bufp+1), *(bufp+2), *(bufp+3)));
		bufp     += 4;
		*length  -= 4;
		break;

	case AGENTX_MSG_REGISTER:
	case AGENTX_MSG_UNREGISTER:
DEBUGMSGTL(("agentx","(Un)REGISTER T/Out = %d, priority = %d, range = %d, (reserved %d)\n", *bufp, *(bufp+1), *(bufp+2), *(bufp+3)));
		range_subid = *(bufp+2);
		bufp     += 4;
		*length -= 4;

		prefix_ptr = bufp+1;
		bufp = agentx_dump_oid( bufp, length,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		if ( bufp == NULL )
		    return SNMPERR_ASN_PARSE_ERR;

		if ( range_subid ) {
DEBUGMSGTL(("agentx","\t range bound = "));
    			agentx_dump_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
			bufp    += 4;
			*length -= 4;

		}
		break;

	case AGENTX_MSG_GETBULK:
DEBUGMSGTL(("agentx","GETBULK non-rep = "));
		agentx_dump_short( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
DEBUGMSGTL(("agentx","\t max-rep = "));
		agentx_dump_short( bufp+2,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		bufp    += 4;
		*length -= 4;
		/*  Fallthrough - SearchRange handling is the same */
		
	case AGENTX_MSG_GET:
	case AGENTX_MSG_GETNEXT:

			/*
			*  SearchRange List
			*  Keep going while we have data left
			*/
		while ( *length > 0 ) {
DEBUGMSGTL(("agentx","Search List \n"));
		    bufp = agentx_dump_oid( bufp, length,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		    if ( bufp == NULL )
			    return SNMPERR_ASN_PARSE_ERR;
		    bufp = agentx_dump_oid( bufp, length,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		    if ( bufp == NULL )
			    return SNMPERR_ASN_PARSE_ERR;

		}
		break;


	case AGENTX_MSG_RESPONSE:

					/* sysUpTime */
DEBUGMSGTL(("agentx","RESPONSE T/Out = "));
		agentx_dump_int( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		bufp    += 4;
		*length -= 4;
		
DEBUGMSGTL(("agentx","\t Error status = "));
		pdu->errstat   = agentx_dump_short( bufp,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
DEBUGMSGTL(("agentx","\t Error index = "));
		pdu->errindex  = agentx_dump_short( bufp+2,
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
		while ( *length > 0 ) {
		    bufp = agentx_dump_varbind( bufp, length,
				pdu->flags & AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		    if ( bufp == NULL )
			    return SNMPERR_ASN_PARSE_ERR;
		}
		break;

	case AGENTX_MSG_COMMITSET:
	case AGENTX_MSG_UNDOSET:
	case AGENTX_MSG_CLEANUPSET:
	case AGENTX_MSG_PING:

DEBUGMSGTL(("agentx","Empty packet\n"));
		/* "Empty" packet */
		break;


	case AGENTX_MSG_ADD_AGENT_CAPS:
DEBUGMSGTL(("agentx","ADD AGENT CAPS \n"));
		bufp = agentx_dump_oid( bufp, length,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		if ( bufp == NULL )
		    return SNMPERR_ASN_PARSE_ERR;
		bufp = agentx_dump_string( bufp, length,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		if ( bufp == NULL )
		    return SNMPERR_ASN_PARSE_ERR;
		break;

	case AGENTX_MSG_REMOVE_AGENT_CAPS:
DEBUGMSGTL(("agentx","REMOVE AGENT CAPS \n"));
		bufp = agentx_dump_oid( bufp, length,
				pdu->flags &  AGENTX_FLAGS_NETWORK_BYTE_ORDER );
		if ( bufp == NULL )
		    return SNMPERR_ASN_PARSE_ERR;
		break;

	default:
		DEBUGMSGTL(("agentx","Unrecognised PDU type"));
		return SNMPERR_UNKNOWN_PDU;
     }
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

  
