/*
 * Abstract Syntax Notation One, ASN.1
 * As defined in ISO/IS 8824 and ISO/IS 8825
 * This implements a subset of the above International Standards that
 * is sufficient to implement SNMP.
 *
 * Encodes abstract data types into a machine independent stream of bytes.
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
#endif

#if HAVE_STRINGS_H
#include <strings.h>
#else
#include <string.h>
#endif

#include <sys/types.h>
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#endif

#ifdef vms
#include <in.h>
#endif


#include "asn1.h"

#ifndef NULL
#define NULL	0
#endif

#include "snmp_impl.h" /* to define ERROR_MSG */

/*
 * asn_parse_int - pulls a long out of an ASN int type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_int(data, datalength, type, intp, intsize)
    register u_char	*data;	/* IN - pointer to start of object */
    register int	*datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char		*type;	/* OUT - asn type of object */
    long		*intp;	/* IN/OUT - pointer to start of output buffer */
    int			intsize;    /* IN - size of output buffer */
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */
    register u_char *bufp = data;
    u_long	    asn_length;
    register long   value = 0;

    if (intsize != sizeof (long)){
	ERROR_MSG("not long");
	return NULL;
    }
    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL){
	ERROR_MSG("bad length");
	return NULL;
    }
    if ((asn_length + (bufp - data)) > (u_long)(*datalength)){
	ERROR_MSG("overflow of message");
	return NULL;
    }
    if ((int)asn_length > intsize){
	ERROR_MSG("I don't support such large integers");
	return NULL;
    }
    *datalength -= (int)asn_length + (bufp - data);
    if (*bufp & 0x80)
	value = -1; /* integer is negative */
    while(asn_length--)
	value = (value << 8) | *bufp++;
    *intp = value;
    return bufp;
}


/*
 * asn_parse_unsigned_int - pulls an unsigned long out of an ASN int type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_unsigned_int(data, datalength, type, intp, intsize)
    register u_char	    *data;	/* IN - pointer to start of object */
    register int	    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char		    *type;	/* OUT - asn type of object */
    u_long		    *intp;	/* IN/OUT - pointer to start of output buffer */
    int			    intsize;    /* IN - size of output buffer */
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */
    register u_char *bufp = data;
    u_long	    asn_length;
    register u_long value = 0;

    if (intsize != sizeof (long)){
	ERROR_MSG("not long");
	return NULL;
    }
    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL){
	ERROR_MSG("bad length");
	return NULL;
    }
    if ((asn_length + (bufp - data)) > (u_long)(*datalength)){
	ERROR_MSG("overflow of message");
	return NULL;
    }
    if (((int)asn_length > (intsize + 1)) ||
	(((int)asn_length == intsize + 1) && *bufp != 0x00)){
	ERROR_MSG("I don't support such large integers");
	return NULL;
    }
    *datalength -= (int)asn_length + (bufp - data);
    if (*bufp & 0x80)
	value = ~value; /* integer is negative */
    while(asn_length--)
	value = (value << 8) | *bufp++;
    *intp = value;
    return bufp;
}


/*
 * asn_build_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_int(data, datalength, type, intp, intsize)
    register u_char *data;	/* IN - pointer to start of output buffer */
    register int    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - asn type of object */
    register long   *intp;	/* IN - pointer to start of long integer */
    register int    intsize;    /* IN - size of *intp */
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */

    register long integer;
    register u_long mask;

    if (intsize != sizeof (long))
	return NULL;
    integer = *intp;
    /*
     * Truncate "unnecessary" bytes off of the most significant end of this
     * 2's complement integer.  There should be no sequence of 9
     * consecutive 1's or 0's at the most significant end of the
     * integer.
     */
    mask = ((u_long) 0x1FF) << ((8 * (sizeof(long) - 1)) - 1);
    /* mask is 0xFF800000 on a big-endian machine */
    while((((integer & mask) == 0) || ((integer & mask) == mask))
	  && intsize > 1){
	intsize--;
	integer <<= 8;
    }
    data = asn_build_header(data, datalength, type, intsize);
    if (data == NULL)
	return NULL;
    if (*datalength < intsize)
	return NULL;
    *datalength -= intsize;
    mask = ((u_long) 0xFF) << (8 * (sizeof(long) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    while(intsize--){
	*data++ = (u_char)((integer & mask) >> (8 * (sizeof(long) - 1)));
	integer <<= 8;
    }
    return data;
}


/*
 * asn_build_unsigned_int - builds an ASN object containing an integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_unsigned_int(data, datalength, type, intp, intsize)
    register u_char *data;	/* IN - pointer to start of output buffer */
    register int    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - asn type of object */
    register u_long *intp;	/* IN - pointer to start of long integer */
    register int    intsize;    /* IN - size of *intp */
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */

    register u_long integer;
    register u_long mask;
    int add_null_byte = 0;

    if (intsize != sizeof (long))
	return NULL;
    integer = *intp;
    mask = ((u_long) 0xFF) << (8 * (sizeof(long) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    if ((u_char)((integer & mask) >> (8 * (sizeof(long) - 1))) & 0x80){
	/* if MSB is set */
	add_null_byte = 1;
	intsize++;
    } else {
	/*
	 * Truncate "unnecessary" bytes off of the most significant end of this 2's complement integer.
	 * There should be no sequence of 9 consecutive 1's or 0's at the most significant end of the
	 * integer.
	 */
	mask = ((u_long) 0x1FF) << ((8 * (sizeof(long) - 1)) - 1);
	/* mask is 0xFF800000 on a big-endian machine */
	while((((integer & mask) == 0) || ((integer & mask) == mask)) && intsize > 1){
	    intsize--;
	    integer <<= 8;
	}
    }
    data = asn_build_header(data, datalength, type, intsize);
    if (data == NULL)
	return NULL;
    if (*datalength < intsize)
	return NULL;
    *datalength -= intsize;
    if (add_null_byte == 1){
	*data++ = '\0';
	intsize--;
    }
    mask = ((u_long) 0xFF) << (8 * (sizeof(long) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    while(intsize--){
	*data++ = (u_char)((integer & mask) >> (8 * (sizeof(long) - 1)));
	integer <<= 8;
    }
    return data;
}


/*
 * asn_parse_string - pulls an octet string out of an ASN octet string type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "string" is filled with the octet string.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_string(data, datalength, type, string, strlength)
    u_char	    *data;	    /* IN - pointer to start of object */
    register int    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    *type;	    /* OUT - asn type of object */
    u_char	    *string;	    /* IN/OUT - pointer to start of output buffer */
    register int    *strlength;     /* IN/OUT - size of output buffer */
{
/*
 * ASN.1 octet string ::= primstring | cmpdstring
 * primstring ::= 0x04 asnlength byte {byte}*
 * cmpdstring ::= 0x24 asnlength string {string}*
 */
    register u_char *bufp = data;
    u_long	    asn_length;

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
	return NULL;
    if ((asn_length + (bufp - data)) > (u_long)(*datalength)){
	ERROR_MSG("overflow of message");
	return NULL;
    }
    if ((int)asn_length > *strlength){
	ERROR_MSG("I don't support such long strings");
	return NULL;
    }
    memmove(string, bufp, (int)asn_length);
    *strlength = (int)asn_length;
    *datalength -= (int)asn_length + (bufp - data);
    return bufp + asn_length;
}


/*
 * asn_build_string - Builds an ASN octet string object containing the input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_string(data, datalength, type, string, strlength)
    u_char	    *data;	    /* IN - pointer to start of object */
    register int    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	    /* IN - ASN type of string */
    u_char	    *string;	    /* IN - pointer to start of input buffer */
    register int    strlength;	    /* IN - size of input buffer */
{
/*
 * ASN.1 octet string ::= primstring | cmpdstring
 * primstring ::= 0x04 asnlength byte {byte}*
 * cmpdstring ::= 0x24 asnlength string {string}*
 * This code will never send a compound string.
 */
    data = asn_build_header(data, datalength, type, strlength);
    if (data == NULL)
	return NULL;
    if (*datalength < strlength)
	return NULL;
    memmove(data, string, strlength);
    *datalength -= strlength;
    return data + strlength;
}


/*
 * asn_parse_header - interprets the ID and length of the current object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
u_char *
asn_parse_header(data, datalength, type)
    u_char	*data;	/* IN - pointer to start of object */
    int		*datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	*type;	/* OUT - ASN type of object */
{
    register u_char *bufp = data;
    register	    header_len;
    u_long	    asn_length;

    /* this only works on data types < 30, i.e. no extension octets */
    if (IS_EXTENSION_ID(*bufp)){
	ERROR_MSG("can't process ID >= 30");
	return NULL;
    }
    *type = *bufp;
    bufp = asn_parse_length(bufp + 1, &asn_length);
    if (bufp == NULL)
	return NULL;
    header_len = bufp - data;
    if ((header_len + asn_length) > (u_long)(*datalength)){
	ERROR_MSG("asn length too long");
	return NULL;
    }
    *datalength = (int)asn_length;
    return bufp;
}

/*
 * asn_build_header - builds an ASN header for an object with the ID and
 * length specified.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  This only works on data types < 30, i.e. no extension octets.
 *  The maximum length is 0xFFFF;
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
u_char *
asn_build_header(data, datalength, type, length)
    register u_char *data;	/* IN - pointer to start of object */
    int		    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - ASN type of object */
    int		    length;	/* IN - length of object */
{
    if (*datalength < 1)
	return NULL;
    *data++ = type;
    (*datalength)--;
    return asn_build_length(data, datalength, length);
    
}

/*
 * asn_build_sequence - builds an ASN header for a sequence with the ID and
 * length specified.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   in this object following the id and length.
 *
 *  This only works on data types < 30, i.e. no extension octets.
 *  The maximum length is 0xFFFF;
 *
 *  Returns a pointer to the first byte of the contents of this object.
 *  Returns NULL on any error.
 */
u_char *
asn_build_sequence(data, datalength, type, length)
    register u_char *data;	/* IN - pointer to start of object */
    int		    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - ASN type of object */
    int		    length;	/* IN - length of object */
{
    *datalength -= 4;
    if (*datalength < 0){
	*datalength += 4;	/* fix up before punting */
	return NULL;
    }
    *data++ = type;
    *data++ = (u_char)(0x02 | ASN_LONG_LEN);
    *data++ = (u_char)((length >> 8) & 0xFF);
    *data++ = (u_char)(length & 0xFF);
    return data;
}

/*
 * asn_parse_length - interprets the length of the current object.
 *  On exit, length contains the value of this length field.
 *
 *  Returns a pointer to the first byte after this length
 *  field (aka: the start of the data field).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_length(data, length)
    u_char  *data;	/* IN - pointer to start of length field */
    u_long  *length;	/* OUT - value of length field */
{
    register u_char lengthbyte = *data;

    if (lengthbyte & ASN_LONG_LEN){
	lengthbyte &= ~ASN_LONG_LEN;	/* turn MSb off */
	if (lengthbyte == 0){
	    ERROR_MSG("We don't support indefinite lengths");
	    return NULL;
	}
	if (lengthbyte > sizeof(long)){
	    ERROR_MSG("we can't support data lengths that long");
	    return NULL;
	}
	memmove(length, data + 1, (int)lengthbyte);
	*length = ntohl(*length);
	*length >>= (8 * ((sizeof(int)) - lengthbyte));
	return data + lengthbyte + 1;
    } else { /* short asnlength */
	*length = (long)lengthbyte;
	return data + 1;
    }
}

u_char *
asn_build_length(data, datalength, length)
    register u_char *data;	/* IN - pointer to start of object */
    int		    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    register int    length;	/* IN - length of object */
{
    u_char    *start_data = data;

    /* no indefinite lengths sent */
    if (length < 0x80){
	if (*datalength < 1){
	    ERROR_MSG("build_length");
	    return NULL;
	}	    
	*data++ = (u_char)length;
    } else if (length <= 0xFF){
	if (*datalength < 2){
	    ERROR_MSG("build_length");
	    return NULL;
	}	    
	*data++ = (u_char)(0x01 | ASN_LONG_LEN);
	*data++ = (u_char)length;
    } else { /* 0xFF < length <= 0xFFFF */
	if (*datalength < 3){
	    ERROR_MSG("build_length");
	    return NULL;
	}	    
	*data++ = (u_char)(0x02 | ASN_LONG_LEN);
	*data++ = (u_char)((length >> 8) & 0xFF);
	*data++ = (u_char)(length & 0xFF);
    }
    *datalength -= (data - start_data);
    return data;

}

/*
 * asn_parse_objid - pulls an object indentifier out of an ASN object identifier type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "objid" is filled with the object identifier.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_objid(data, datalength, type, objid, objidlength)
    u_char	*data;		/* IN - pointer to start of object */
    int		*datalength;	/* IN/OUT - number of valid bytes left in buffer */
    u_char	*type;		/* OUT - ASN type of object */
    oid		*objid;		/* IN/OUT - pointer to start of output buffer */
    int		*objidlength;	/* IN/OUT - number of sub-id's in objid */
{
/*
 * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
 * subidentifier ::= {leadingbyte}* lastbyte
 * leadingbyte ::= 1 7bitvalue
 * lastbyte ::= 0 7bitvalue
 */
    register u_char *bufp = data;
    register oid *oidp = objid + 1;
    register u_long subidentifier;
    register long   length;
    u_long	    asn_length;

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
	return NULL;
    if ((asn_length + (bufp - data)) > (u_long)(*datalength)){
	ERROR_MSG("overflow of message");
	return NULL;
    }
    *datalength -= (int)asn_length + (bufp - data);

    /* Handle invalid object identifier encodings of the form 06 00 robustly */
    if (asn_length == 0)
	objid[0] = objid[1] = 0;

    length = asn_length;
    (*objidlength)--;	/* account for expansion of first byte */
    while (length > 0 && (*objidlength)-- > 0){
	subidentifier = 0;
	do {	/* shift and add in low order 7 bits */
	    subidentifier = (subidentifier << 7) + (*(u_char *)bufp & ~ASN_BIT8);
	    length--;
	} while (*(u_char *)bufp++ & ASN_BIT8);	/* last byte has high bit clear */
/*?? note, this test will never be true, since the largest value
     of subidentifier is the value of MAX_SUBID! */
	if (subidentifier > (u_long)MAX_SUBID){
	    ERROR_MSG("subidentifier too long");
	    return NULL;
	}
	*oidp++ = (oid)subidentifier;
    }

    /*
     * The first two subidentifiers are encoded into the first component
     * with the value (X * 40) + Y, where:
     *	X is the value of the first subidentifier.
     *  Y is the value of the second subidentifier.
     */
    subidentifier = (u_long)objid[1];
    if (subidentifier == 0x2B){
	objid[0] = 1;
	objid[1] = 3;
    } else {
        if (subidentifier < 40) {
            objid[0] = 0;
	    objid[1] = subidentifier;
        } else if (subidentifier < 80) {
            objid[0] = 1;
            objid[1] = subidentifier - 40;
        } else {
            objid[0] = 2;
            objid[1] = subidentifier - 80;
        }
    }

    *objidlength = (int)(oidp - objid);
    return bufp;
}

/*
 * asn_build_objid - Builds an ASN object identifier object containing the
 * input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_objid(data, datalength, type, objid, objidlength)
    register u_char *data;	    /* IN - pointer to start of object */
    int		    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	    /* IN - ASN type of object */
    oid		    *objid;	    /* IN - pointer to start of input buffer */
    int		    objidlength;    /* IN - number of sub-id's in objid */
{
/*
 * ASN.1 objid ::= 0x06 asnlength subidentifier {subidentifier}*
 * subidentifier ::= {leadingbyte}* lastbyte
 * leadingbyte ::= 1 7bitvalue
 * lastbyte ::= 0 7bitvalue
 */
    int asnlength;
    register oid *op = objid;
    u_char objid_size[MAX_OID_LEN];
    register u_long objid_val;
    u_long first_objid_val;
    register int i;

    /* check if there are at least 2 sub-identifiers */
    if (objidlength < 2){
        /* there are not, so make OID have two with value of zero */
        objid_val = 0;
	objidlength = 2;
    } else {
        /* combine the first two values */
	objid_val = (op[0] * 40) + op[1];
	op += 2;
    }
    first_objid_val = objid_val;

    /* calculate the number of bytes needed to store the encoded value */
    for (i = 1, asnlength = 0;;) {
        if (objid_val < 0x80U) {
            objid_size[i] = 1;
            asnlength += 1;
        } else if (objid_val < 0x4000U) {
            objid_size[i] = 2;
            asnlength += 2;
        } else if (objid_val < 0x200000U) {
            objid_size[i] = 3;
            asnlength += 3;
        } else if (objid_val < 0x10000000U) {
            objid_size[i] = 4;
            asnlength += 4;
        } else {
            objid_size[i] = 5;
            asnlength += 5;
        }
        i++;
        if (i >= objidlength)
            break;
        objid_val = *op++;
    } 

    /* store the ASN.1 tag and length */
    data = asn_build_header(data, datalength, type, asnlength);
    if (data == NULL)
	return NULL;
    if (*datalength < asnlength)
	return NULL;

    /* store the encoded OID value */
    for (i = 1, objid_val = first_objid_val, op = objid+2; i < objidlength;
                i++, objid_val = *op++) {
        switch (objid_size[i]) {
        case 1:
            *data++ = (u_char)objid_val;
            break;

        case 2:
            *data++ = (u_char)((objid_val>>7) | 0x80);
            *data++ = (u_char)(objid_val & 0x07f);
            break;

        case 3:
            *data++ = (u_char)((objid_val>>14) | 0x80);
            *data++ = (u_char)((objid_val>>7 & 0x7f) | 0x80);
            *data++ = (u_char)(objid_val & 0x07f);
            break;

        case 4:
            *data++ = (u_char)((objid_val>>21) | 0x80);
            *data++ = (u_char)((objid_val>>14 & 0x7f) | 0x80);
            *data++ = (u_char)((objid_val>>7 & 0x7f) | 0x80);
            *data++ = (u_char)(objid_val & 0x07f);
            break;

        case 5:
            *data++ = (u_char)((objid_val>>28) | 0x80);
            *data++ = (u_char)((objid_val>>21 & 0x7f) | 0x80);
            *data++ = (u_char)((objid_val>>14 & 0x7f) | 0x80);
            *data++ = (u_char)((objid_val>>7 & 0x7f) | 0x80);
            *data++ = (u_char)(objid_val & 0x07f);
            break;
        }
    }    

    /* return the length and data ptr */
    *datalength -= asnlength;
    return data;
}

/*
 * asn_parse_null - Interprets an ASN null type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_null(data, datalength, type)
    u_char	    *data;	    /* IN - pointer to start of object */
    int		    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    *type;	    /* OUT - ASN type of object */
{
/*
 * ASN.1 null ::= 0x05 0x00
 */
    register u_char   *bufp = data;
    u_long	    asn_length;

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
	return NULL;
    if (asn_length != 0){
	ERROR_MSG("Malformed NULL");
	return NULL;
    }
    *datalength -= (bufp - data);
    return bufp + asn_length;
}


/*
 * asn_build_null - Builds an ASN null object.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_null(data, datalength, type)
    u_char	    *data;	    /* IN - pointer to start of object */
    int		    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	    /* IN - ASN type of object */
{
/*
 * ASN.1 null ::= 0x05 0x00
 */
    return asn_build_header(data, datalength, type, 0);
}

/*
 * asn_parse_bitstring - pulls a bitstring out of an ASN bitstring type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  "string" is filled with the bit string.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_bitstring(data, datalength, type, string, strlength)
    u_char	    *data;	    /* IN - pointer to start of object */
    register int    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    *type;	    /* OUT - asn type of object */
    u_char	    *string;	    /* IN/OUT - pointer to start of output buffer */
    register int    *strlength;     /* IN/OUT - size of output buffer */
{
/*
 * bitstring ::= 0x03 asnlength unused {byte}*
 */
    register u_char *bufp = data;
    u_long	    asn_length;

    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL)
	return NULL;
    if ((asn_length + (bufp - data)) > (u_long)(*datalength)){
	ERROR_MSG("overflow of message");
	return NULL;
    }
    if ((int)asn_length > *strlength){
	ERROR_MSG("I don't support such long bitstrings");
	return NULL;
    }
    if (asn_length < 1){
	ERROR_MSG("Invalid bitstring");
	return NULL;
    }
    if (*bufp > 7){
	ERROR_MSG("Invalid bitstring");
	return NULL;
    }
    memmove(string, bufp, (int)asn_length);
    *strlength = (int)asn_length;
    *datalength -= (int)asn_length + (bufp - data);
    return bufp + asn_length;
}


/*
 * asn_build_bitstring - Builds an ASN bit string object containing the
 * input string.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the beginning of the next object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_bitstring(data, datalength, type, string, strlength)
    u_char	    *data;	    /* IN - pointer to start of object */
    register int    *datalength;    /* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	    /* IN - ASN type of string */
    u_char	    *string;	    /* IN - pointer to start of input buffer */
    register int    strlength;	    /* IN - size of input buffer */
{
/*
 * ASN.1 bit string ::= 0x03 asnlength unused {byte}*
 */
    if (strlength < 1 || *string > 7){
	ERROR_MSG("Building invalid bitstring");
	return NULL;
    }
    data = asn_build_header(data, datalength, type, strlength);
    if (data == NULL)
	return NULL;
    if (*datalength < strlength)
	return NULL;
    memmove(data, string, strlength);
    *datalength -= strlength;
    return data + strlength;
}


/*
 * asn_parse_unsigned_int64 - pulls a 64 bit unsigned long out of an ASN int
 * type.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_parse_unsigned_int64(data, datalength, type, cp, countersize)
    register u_char	    *data;	/* IN - pointer to start of object */
    register int	    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char		    *type;	/* OUT - asn type of object */
    struct counter64	    *cp;	/* IN/OUT -pointer to counter struct */
    int			    countersize;/* IN - size of output buffer */
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */
    register u_char *bufp = data;
    u_long	    asn_length;
    register u_long low = 0, high = 0;
    int intsize = 4;
    
    if (countersize != sizeof(struct counter64)){
	ERROR_MSG("not right size");
	return NULL;
    }
    *type = *bufp++;
    bufp = asn_parse_length(bufp, &asn_length);
    if (bufp == NULL){
	ERROR_MSG("bad length");
	return NULL;
    }
    if ((asn_length + (bufp - data)) > (u_long)(*datalength)){
	ERROR_MSG("overflow of message");
	return NULL;
    }
    if (((int)asn_length > (intsize * 2 + 1)) ||
	(((int)asn_length == (intsize * 2 + 1)) && *bufp != 0x00)){
	ERROR_MSG("I don't support such large integers");
	return NULL;
    }
    *datalength -= (int)asn_length + (bufp - data);
    if (*bufp & 0x80){
	low = ~low; /* integer is negative */
	high = ~high;
    }
    while(asn_length--){
	high = (high << 8) | ((low & 0xFF000000) >> 24);
	low = (low << 8) | *bufp++;
    }
    cp->low = low;
    cp->high = high;
    return bufp;
}


/*
 * asn_build_unsigned_int64 - builds an ASN object containing a 64 bit integer.
 *  On entry, datalength is input as the number of valid bytes following
 *   "data".  On exit, it is returned as the number of valid bytes
 *   following the end of this object.
 *
 *  Returns a pointer to the first byte past the end
 *   of this object (i.e. the start of the next object).
 *  Returns NULL on any error.
 */
u_char *
asn_build_unsigned_int64(data, datalength, type, cp, countersize)
    register u_char *data;	/* IN - pointer to start of output buffer */
    register int    *datalength;/* IN/OUT - number of valid bytes left in buffer */
    u_char	    type;	/* IN - asn type of object */
    struct counter64 *cp;	/* IN - pointer to counter struct */
    register int    countersize; /* IN - size of *intp */
{
/*
 * ASN.1 integer ::= 0x02 asnlength byte {byte}*
 */

    register u_long low, high;
    register u_long mask, mask2;
    int add_null_byte = 0;
    int intsize;

    if (countersize != sizeof (struct counter64))
	return NULL;
    intsize = 8;
    low = cp->low;
    high = cp->high;
    mask = ((u_long) 0xFF) << (8 * (sizeof(long) - 1));
    /* mask is 0xFF000000 on a big-endian machine */
    if ((u_char)((high & mask) >> (8 * (sizeof(long) - 1))) & 0x80){
	/* if MSB is set */
	add_null_byte = 1;
	intsize++;
    } else {
	/*
	 * Truncate "unnecessary" bytes off of the most significant end of this 2's
	 * complement integer.
	 * There should be no sequence of 9 consecutive 1's or 0's at the most
	 * significant end of the integer.
	 */
	mask2 = ((u_long) 0x1FF) << ((8 * (sizeof(long) - 1)) - 1);
	/* mask2 is 0xFF800000 on a big-endian machine */
	while((((high & mask2) == 0) || ((high & mask2) == mask2)) && intsize > 1){
	    intsize--;
	    high = (high << 8)
		| ((low & mask) >> (8 * (sizeof(long) - 1)));
	    low <<= 8;
	}
    }
    data = asn_build_header(data, datalength, type, intsize);
    if (data == NULL)
	return NULL;
    if (*datalength < intsize)
	return NULL;
    *datalength -= intsize;
    if (add_null_byte == 1){
	*data++ = '\0';
	intsize--;
    }
    while(intsize--){
	*data++ = (u_char)((high & mask) >> (8 * (sizeof(long) - 1)));
	high = (high << 8)
	    | ((low & mask) >> (8 * (sizeof(long) - 1)));
	low <<= 8;
	
    }
    return data;
}
