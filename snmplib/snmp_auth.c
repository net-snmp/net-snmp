/*
 * snmp_auth.c -
 *   Authentication for SNMP.
 *
 */
/**********************************************************************
    Copyright 1988, 1989, 1991, 1992 by Carnegie Mellon University

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

#ifdef KINETICS
#include "gw.h"
#include "fp4/cmdmacro.h"
#endif

#include <stdio.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
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
#if HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifndef NULL
#define NULL 0
#endif

#if HAVE_WINSOCK_H
#include <winsock.h>
#endif


#ifdef vms
#include <in.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "party.h"
#include "context.h"
#include "mib.h"
#include "md5.h"
#include "acl.h"
#include "system.h"

static void md5Digest __P((u_char *, int, u_char *));

/** snmp_comstr_parse - parse the header of a community string-based message
*                       such as that found in SNMPv1 and SNMPv2c.
*
*  NOTE: this function will need to be changed to support SNMPv2u and SNMPv3,
*        since the version field must first be examined to see
*        if the message contains a community string.
*/
u_char *
snmp_comstr_parse(data, length, sid, slen, version)
u_char          *data;      /* IN - message */
int             *length;    /* IN/OUT - bytes left in message */
u_char          *sid;       /* OUT - community string */
int             *slen;      /* OUT - length of community string */
int             *version;   /* OUT - message version */
{
    u_char    type;
    long ver;

    /* message is an ASN.1 SEQUENCE */
    data = asn_parse_header(data, length, &type);
    if (data == NULL){
        ERROR_MSG("bad header");
        return NULL;
    }
    if (type != (ASN_SEQUENCE | ASN_CONSTRUCTOR)){
        ERROR_MSG("wrong auth header type");
        return NULL;
    }

    /* first field is the version */
    data = asn_parse_int(data, length, &type, &ver, sizeof(ver));
    *version = ver;
    if (data == NULL){
        ERROR_MSG("bad parse of version");
        return NULL;
    }

    /* second field is the community string for SNMPv1 & SNMPv2c */
    data = asn_parse_string(data, length, &type, sid, slen);
    if (data == NULL){
        ERROR_MSG("bad parse of community");
        return NULL;
    }
    sid[*slen] = '\0';
    return (u_char *)data;
}

#ifdef USE_V2PARTY_PROTOCOL
/** snmp_party_parse - parse the header of a party-based message
*                      such as that found in SNMPv2p
*/
u_char *
snmp_party_parse(data, length,  pi, srcParty, srcPartyLength,
                 dstParty, dstPartyLength, context, contextLength, pass)
u_char          *data;      /* IN - message */
int		*length;    /* IN/OUT - bytes left in message */
struct packet_info *pi;     /* OUT - packet info */
oid		*srcParty;  /* OUT - source party */
oid             *dstParty;  /* OUT - dest party */
oid             *context;   /* OUT - context */
int		*srcPartyLength; /* OUT - length of source party */
int             *dstPartyLength; /* OUT - length of dest party */
int             *contextLength;  /* OUT - length of context */
int		pass;       /* IN - which pass */
{
    u_char    type;
    oid	dstParty2[64];
    int dstParty2Length = 64, authMsgLen, authMsgInternalLen;
    u_long authSrcTimeStamp, authDstTimeStamp;
    u_char authDigest[16], digest[16];
    int authDigestLen;
    u_char *authMsg, *digestStart = NULL, *digestEnd = NULL;
    struct partyEntry *srcp, *dstp;
    struct contextEntry *cxp;
    int biglen, ismd5 = 0;
    struct timeval now;

    data = asn_parse_header(data, length, &type);
    if (data == NULL){
	ERROR_MSG("bad header");
	return NULL;
    }
    if (type != (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)){
        ERROR_MSG("wrong auth header type");
        return NULL;
    }
    data = asn_parse_objid(data, length, &type, dstParty, dstPartyLength);
    if (data == NULL){
	ERROR_MSG("bad parse of dstParty");
	return NULL;
    }
    dstp = party_getEntry(dstParty, *dstPartyLength);
    if (!dstp){
	snmp_errno = SNMPERR_BAD_DST_PARTY;
	return NULL;
    }
    pi->dstp = dstp;
    /* check to see if TDomain and TAddr match here.
     * If they don't, discard the packet
     * This might be best handled by adding a user-supplied
     * function to the API that would validate the address.
     */

    data = asn_parse_header(data, length, &type);
    if (data == NULL || type != (ASN_CONTEXT | 1)){
	ERROR_MSG("bad parse of privData");
	return NULL;
    }
    authMsg = data;
    data = asn_parse_header(data, length, &type);
    if (data == NULL || type != (ASN_CONTEXT | ASN_CONSTRUCTOR | 1)){
	ERROR_MSG("bad parse of snmpAuthMsg (DES decode probably failed!)");
	return NULL;
    }
    authMsgLen = *length + data - authMsg;
    authMsgInternalLen = *length;
    data = asn_parse_header(data, &authMsgInternalLen, &type);
    if (data == NULL){
	ERROR_MSG("bad parse of snmpAuthMsg");
	return NULL;
    }
    if (type == (ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR)){
	/* noAuth */
	pi->version = SNMP_VERSION_2p;
	pi->sec_model = SNMP_SEC_MODEL_SNMPv2p;
	pi->sec_level = SNMP_SEC_LEVEL_NOAUTH;
    } else if (type == (ASN_CONTEXT | ASN_CONSTRUCTOR | 2)){
	/* AuthInformation */
	pi->version = SNMP_VERSION_2p;
        pi->mp_model = SNMP_MP_MODEL_SNMPv2p;
	pi->sec_model = SNMP_SEC_MODEL_SNMPv2p;
	pi->sec_level = SNMP_SEC_LEVEL_AUTHNOPRIV;
	ismd5 = 1;

	digestStart = data;
	authDigestLen = sizeof(authDigest);
	data = asn_parse_string(data, length, &type, authDigest,
				&authDigestLen);
	if (data == NULL){
	    ERROR_MSG("Digest");
	    return NULL;
	}
	digestEnd = data;

	data = asn_parse_unsigned_int(data, length, &type, &authDstTimeStamp,
			     sizeof(authDstTimeStamp));
	if (data == NULL){
	    ERROR_MSG("DstTimeStamp");
	    return NULL;
	}

	data = asn_parse_unsigned_int(data, length, &type, &authSrcTimeStamp,
				      sizeof(authSrcTimeStamp));
	if (data == NULL){
	    ERROR_MSG("SrcTimeStamp");
	    return NULL;
	}
    } else {
	ERROR_MSG("Bad format for authData");
	return NULL;
    }
    data = asn_parse_header(data, length, &type);
    if (data == NULL){
	ERROR_MSG("bad parse of snmpMgmtCom");
	return NULL;
    }
    data = asn_parse_objid(data, length, &type, dstParty2, &dstParty2Length);
    if (data == NULL){
	ERROR_MSG("bad parse of dstParty");
	return NULL;
    }
    data = asn_parse_objid(data, length, &type, srcParty, srcPartyLength);
    if (data == NULL){
	ERROR_MSG("bad parse of srcParty");
	return NULL;
    }
    data = asn_parse_objid(data, length, &type, context, contextLength);
    if (data == NULL){
	ERROR_MSG("bad parse of context");
	return NULL;
    }
    if (*dstPartyLength != dstParty2Length
	|| memcmp(dstParty, dstParty2, dstParty2Length)){
	ERROR_MSG("Mismatch of destination parties\n");
	return NULL;
    }

    srcp = party_getEntry(srcParty, *srcPartyLength);
    if (!srcp) {
	snmp_errno = SNMPERR_BAD_SRC_PARTY;
	return NULL;
    }
    pi->srcp = srcp;

    cxp = context_getEntry(context, *contextLength);
    if (!cxp) {
	snmp_errno = SNMPERR_BAD_CONTEXT;
	return NULL;
    }
    pi->cxp = cxp;

    /* Only perform the following authentication checks if this is the
     * first time called for this packet.
     */
    if (srcp->partyAuthProtocol == SNMPV2MD5AUTHPROT
	&& pi->version != SNMP_VERSION_2p)
	return NULL;
    if ((pass & FIRST_PASS) && (srcp->partyAuthProtocol == SNMPV2MD5AUTHPROT)){
	/* RFC1446, Pg 18, 3.2.1 */
	pi->sec_level = SNMP_SEC_LEVEL_AUTHPRIV;
	if (!ismd5){
	    /* snmpStatsBadAuths++ */
	    return NULL;
	}

	gettimeofday(&now,(struct timezone *)0);

	srcp->partyAuthClock = now.tv_sec - srcp->tv.tv_sec;
	dstp->partyAuthClock = now.tv_sec - dstp->tv.tv_sec;
	/* RFC1446, Pg 18, 3.2.3 */
	if (authSrcTimeStamp + srcp->partyAuthLifetime < srcp->partyAuthClock){
	    ERROR_MSG("Late message");
	    /* snmpStatsNotInLifetimes */
	    return NULL;
	}

	/* RFC1446, Pg 18, 3.2.5 */
	biglen = 5000;
	if (digestEnd != asn_build_string(digestStart, &biglen,
					  (u_char)(ASN_UNIVERSAL
						   | ASN_PRIMITIVE
						   | ASN_OCTET_STR),
					  srcp->partyAuthPrivate,
					  srcp->partyAuthPrivateLen)){
	    ERROR_MSG("couldn't stuff digest");
	    return NULL;
	}
	md5Digest(authMsg, authMsgLen, digest);

	/* RFC1446, Pg 19, 3.2.6 */
	if (authDigestLen != 16 || memcmp(authDigest, digest, 16)){
	    ERROR_MSG("unauthentic");
	    /* snmpStatsWrongDigestValues++ */
	    return NULL;
	}
	/* As per RFC1446, Pg 19, 3.2.7, the message is authentic */

	biglen = 5000;
	if (digestEnd != asn_build_string(digestStart, &biglen,
					  (u_char)(ASN_UNIVERSAL
						   | ASN_PRIMITIVE
						   | ASN_OCTET_STR),
					  authDigest, 16)){
	    ERROR_MSG("couldn't stuff digest back");
	    return NULL;
	}

	/* Now that we know the message is authentic, update
	 * the lastTimeStamp.
	 * As per RFC1446, Pg 19, 3.2.8, we should check that there is an
	 * acl.
	 */
	/*  RFC1446, Pg 19, 3.2.8 */
	if (srcp->partyAuthClock < authSrcTimeStamp){
	    srcp->partyAuthClock = authSrcTimeStamp;
	    gettimeofday(&srcp->tv,(struct timezone *)0);
	    srcp->tv.tv_sec -= srcp->partyAuthClock;
	}
	if (dstp->partyAuthClock < authDstTimeStamp){
	    dstp->partyAuthClock = authDstTimeStamp;
	    gettimeofday(&dstp->tv,(struct timezone *)0);
	    dstp->tv.tv_sec -= dstp->partyAuthClock;
	}
    } else if ((pass & FIRST_PASS) && dstp->partyPrivProtocol == DESPRIVPROT){
	/* noAuth and desPriv */
	ERROR_MSG("noAuth and desPriv");
	return NULL;
    }
    return data;
}
#endif /* USE_V2PARTY_PROTOCOL */

/** snmp_comstr_build - build the header of a community string-based message
*                       such as that found in SNMPv1 and SNMPv2c.
*
*  NOTE: the length of the message will have to be inserted
*        later, if not known.
*/
u_char *
snmp_comstr_build(data, length, sid, slen, version, messagelen)
    u_char      *data;
    int         *length;
    u_char      *sid;
    int         *slen;
    int         *version;
    int         messagelen;
{
  /* version is an 'int' (CMU had it as a long, but was passing in a *int.
     Grrr.) assign version to verfix and pass in that to asn_build_int
     instead which expects a long
     -- WH */

    long verfix = *version;
    u_char *h1 = data;
    u_char *h1e;
    int hlength = *length;

    /* build the the message wrapper
       (note length will be inserted later) */
    data = asn_build_sequence(data, length, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
    if (data == NULL){
        ERROR_MSG("buildheader");
        return NULL;
    }
    h1e = data;

    /* store the version field */
    data = asn_build_int(data, length,
            (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
            &verfix, sizeof(verfix));
    if (data == NULL){
        ERROR_MSG("buildint");
        return NULL;
    }

    /* store the community string */
    data = asn_build_string(data, length,
            (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OCTET_STR),
            sid, *slen);
    if (data == NULL){
        ERROR_MSG("buildstring");
        return NULL;
    }

    /* insert length */
    asn_build_sequence(h1, &hlength, (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR),
                       data-h1e + messagelen);

    return data;
}

#ifdef USE_V2PARTY_PROTOCOL
/** snmp_party_build - build the header for a party-based security message.
*                      In the first pass allocate and store all the fields.
*                      In the second pass, actually do the encryption and
*                      message digest creation.
*/
u_char *
snmp_party_build(data, length, pi, messagelen, srcParty, srcPartyLen,
		   dstParty, dstPartyLen, context, contextLen,
		   packet_len, pass)
    u_char	    *data;
    int		    *length;
    struct packet_info *pi;
    int		    messagelen;
    oid		    *srcParty;
    int		    srcPartyLen;
    oid		    *dstParty;
    int		    dstPartyLen;
    oid		    *context;
    int             contextLen;
    int		    *packet_len;    /* OUT - length of complete packet */
    int		    pass;  /* FIRST_PASS, LAST_PASS, none, or both */
{
    struct partyEntry *srcp, *dstp;
    struct timeval now;
    u_char *endOfPacket;
    int dummyLength;
    u_char *digestStart = NULL, *digestEnd = NULL, *authMsgStart;
    u_char authDigest[16];
    u_char *h1, *h2, *h3 = NULL, *h5;
    int pad;
    int authInfoSize = 0;


    srcp = pi->srcp;
    dstp = pi->dstp;
    if (!srcp || !dstp){
	srcp = party_getEntry(srcParty, srcPartyLen);
	if (!srcp) {
	    snmp_errno = SNMPERR_BAD_SRC_PARTY;
	    return NULL;
	}
	dstp = party_getEntry(dstParty, dstPartyLen);
	if (!dstp) {
	    snmp_errno = SNMPERR_BAD_SRC_PARTY;
	    return NULL;
	}
	pi->srcp = srcp;
	pi->dstp = dstp;
    }
    if (srcp->partyAuthProtocol == SNMPV2MD5AUTHPROT){
	if (pass & FIRST_PASS){
	    /* get timestamp now because they are needed for the
	     * length predictions.
	     */
	    gettimeofday(&now,(struct timezone *)0);
	    srcp->partyAuthClock = now.tv_sec - srcp->tv.tv_sec;
	}
	/* What if we don't actually send the message?  Are we now
	 * out of sync due to the above line?  Answer: No, this
	 * is just like dropping a packet, except that it is dropped
	 * due to some error detected in the software protocol layers
	 * between here and the network.
	 */
    } else {
	/* Don't send noAuth/desPriv. User interface should check for
	 * this so that it can give a reasonable error message
	 */
	if (dstp->partyPrivProtocol == DESPRIVPROT) {
	    snmp_errno = SNMPERR_NOAUTH_DESPRIV;
	    return NULL;
	}
    }
    h1 = data;
    data = asn_build_sequence(data, length,
			    (u_char)(ASN_CONTEXT | ASN_CONSTRUCTOR | 1), 0);
    if (data == NULL){
	ERROR_MSG("build_header2");
	return NULL;
    }
    data = asn_build_objid(data, length, (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_OBJECT_ID), dstParty, dstPartyLen);
    if (data == NULL){
	ERROR_MSG("build_objid");
	return NULL;
    }
    h2 = data;
    data = asn_build_sequence(data, length,
			    (u_char)(ASN_CONTEXT | 1), 0);
    if (data == NULL){
	ERROR_MSG("build_header2");
	return NULL;
    }
    authMsgStart = data;
    data = asn_build_sequence(data, length,
			    (u_char)(ASN_CONTEXT | ASN_CONSTRUCTOR | 1), 0);
    if (data == NULL){
	ERROR_MSG("build_header2");
	return NULL;
    }
    if (srcp->partyAuthProtocol == SNMPV2MD5AUTHPROT){
	h3 = data;
	data = asn_build_sequence(data, length,
				  (u_char)(ASN_CONTEXT |ASN_CONSTRUCTOR | 2),
				  0);
	if (data == NULL){
	    ERROR_MSG("build_header2");
	    return NULL;
	}

	digestStart = data;
	data = asn_build_string(data, length,
				(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE
					 | ASN_OCTET_STR),
				srcp->partyAuthPrivate,
				srcp->partyAuthPrivateLen);
	if (data == NULL){
	    ERROR_MSG("build_string");
	    return NULL;
	}
	digestEnd = data;

	data = asn_build_unsigned_int(data, length,
				      (u_char)(ASN_UINTEGER),
				      &dstp->partyAuthClock,
				      sizeof(dstp->partyAuthClock));
	if (data == NULL){
	    ERROR_MSG("build_unsigned_int");
	    return NULL;
	}

	data = asn_build_unsigned_int(data, length,
				      (u_char)(ASN_UINTEGER),
				      &srcp->partyAuthClock,
				      sizeof(srcp->partyAuthClock));
	if (data == NULL){
	    ERROR_MSG("build_unsigned_int");
	    return NULL;
	}
	authInfoSize = data - digestStart;
    } else {
	data = asn_build_string(data, length, (u_char)(ASN_UNIVERSAL
						       | ASN_PRIMITIVE
						       | ASN_OCTET_STR),
				(u_char *)"", 0);
	if (data == NULL){
	    ERROR_MSG("build_string");
	    return NULL;
	}
    }
    h5 = data;
    data = asn_build_sequence(data, length,
			    (u_char)(ASN_CONTEXT | ASN_CONSTRUCTOR | 2),
			    0);
    if (data == NULL){
	ERROR_MSG("build_header2");
	return NULL;
    }
    data = asn_build_objid(data, length,
			   (u_char)(ASN_UNIVERSAL
				    | ASN_PRIMITIVE | ASN_OBJECT_ID),
			   dstParty, dstPartyLen);
    if (data == NULL){
	ERROR_MSG("build_objid");
	return NULL;
    }
    data = asn_build_objid(data, length,
			   (u_char)(ASN_UNIVERSAL
				    | ASN_PRIMITIVE | ASN_OBJECT_ID),
			   srcParty, srcPartyLen);
    if (data == NULL){
	ERROR_MSG("build_objid");
	return NULL;
    }
    data = asn_build_objid(data, length,
			   (u_char)(ASN_UNIVERSAL
				    | ASN_PRIMITIVE | ASN_OBJECT_ID),
			   context, contextLen);
    if (data == NULL){
	ERROR_MSG("build_objid");
	return NULL;
    }
    endOfPacket = data;
    /* if not last pass, skip md5 and des computation */
    if (!(pass & LAST_PASS))
	return (u_char *)endOfPacket;

	pad = 0;
    *packet_len = (endOfPacket - h1) + messagelen + pad;
    asn_build_sequence(h1, length, (u_char)(ASN_CONTEXT | ASN_CONSTRUCTOR | 1),
		       (endOfPacket - h1) + messagelen + pad - 4);

    asn_build_sequence(h2, length, (u_char)(ASN_CONTEXT | 1),
		       (endOfPacket - h2) + messagelen + pad - 4);

    asn_build_sequence(authMsgStart, length,
		       (u_char)(ASN_CONTEXT | ASN_CONSTRUCTOR | 1),
		       (endOfPacket - authMsgStart) + messagelen - 4);

    if (srcp->partyAuthProtocol == SNMPV2MD5AUTHPROT){
	asn_build_sequence(h3, length,
			   (u_char)(ASN_CONTEXT |ASN_CONSTRUCTOR | 2),
			   authInfoSize);
    }
    asn_build_sequence(h5, length,
		       (u_char)(ASN_CONTEXT | ASN_CONSTRUCTOR | 2),
		       (endOfPacket - h5) + messagelen - 4);

    /* if it isn't MD5, we'll never do DES, so we're done */
    if (srcp->partyAuthProtocol != SNMPV2MD5AUTHPROT)
	return (u_char *)endOfPacket;
/*    xdump(srcp->partyAuthPrivate, 16, "authPrivate: "); */
    md5Digest(authMsgStart, (endOfPacket - authMsgStart) + messagelen,
	      authDigest);
    dummyLength = 5000;
    data = asn_build_string(digestStart, &dummyLength,
			    (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE
				     | ASN_OCTET_STR),
			    authDigest, sizeof(authDigest));
    if (data != digestEnd){
	ERROR_MSG("stuffing digest");
	return NULL;
    }
    return (u_char *)endOfPacket;
}
#endif /* USE_V2PARTY_PROTOCOL */

static void
md5Digest(start, length, digest)
    u_char *start;
    int length;
    u_char *digest;
{
    u_char *cp;
    MDstruct MD;
    int i, j;
#if WORDS_BIGENDIAN
    u_char *buf;
    u_char buffer[SNMP_MAX_LEN];
#endif

#if 0
    int count, sum;

    sum = 0;
    for(count = 0; count < length; count++)
	sum += start[count];
    printf("sum %d (%d)\n", sum, length);
#endif

#if WORDS_BIGENDIAN
    /* do the computation in an array */
    cp = buf = buffer;
    memmove(buf, start, length);
#else
    /* do the computation in place */
    cp = start;
#endif

    MDbegin(&MD);
    while(length >= 64){
	MDupdate(&MD, cp, 64 * 8);
	cp += 64;
	length -= 64;
    }
    MDupdate(&MD, cp, length * 8);
/*    MDprint(&MD); */
   for (i=0;i<4;i++)
     for (j=0;j<32;j=j+8)
	 *digest++ = (MD.buffer[i]>>j) & 0xFF;
}

#ifdef USE_V2PARTY_PROTOCOL
int
has_access(msg_type, target, subject, resources)
    u_char msg_type;
    int target, subject, resources;
{
    struct aclEntry *ap;

    ap = acl_getEntry(target, subject, resources);
    if (!ap)
	return 0;
    if (ap->aclPriveleges & (1 << (msg_type & 0x1F)))
	return 1;
    return 0;
}
#endif

