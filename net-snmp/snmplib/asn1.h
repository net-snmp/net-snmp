#ifndef ASN1_H
#define ASN1_H
/*
 * Definitions for Abstract Syntax Notation One, ASN.1
 * As defined in ISO/IS 8824 and ISO/IS 8825
 *
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

#ifndef EIGHTBIT_SUBIDS
typedef u_long	oid;
#define MAX_SUBID   0xFFFFFFFF
#else
typedef u_char	oid;
#define MAX_SUBID   0xFF
#endif

#define MAX_OID_LEN	    128	/* max subid's in an oid */

#define ASN_BOOLEAN	    (0x01)
#define ASN_INTEGER	    (0x02)
#define ASN_BIT_STR	    (0x03)
#define ASN_OCTET_STR	    (0x04)
#define ASN_NULL	    (0x05)
#define ASN_OBJECT_ID	    (0x06)
#define ASN_SEQUENCE	    (0x10)
#define ASN_SET		    (0x11)

#define ASN_UNIVERSAL	    (0x00)
#define ASN_APPLICATION     (0x40)
#define ASN_CONTEXT	    (0x80)
#define ASN_PRIVATE	    (0xC0)

#define ASN_PRIMITIVE	    (0x00)
#define ASN_CONSTRUCTOR	    (0x20)

#define ASN_LONG_LEN	    (0x80)
#define ASN_EXTENSION_ID    (0x1F)
#define ASN_BIT8	    (0x80)

#define IS_CONSTRUCTOR(byte)	((byte) & ASN_CONSTRUCTOR)
#define IS_EXTENSION_ID(byte)	(((byte) & ASN_EXTENSION_ID) == ASN_EXTENSION_ID)

struct counter64 {
    u_long high;
    u_long low;
};

#ifdef OPAQUE_SPECIAL_TYPES
typedef struct counter64 integer64;
typedef struct counter64 unsigned64;

/* The BER inside an OPAQUE is an context specific with a value of 48 (0x30)
   plus the "normal" tag. For a Counter64, the tag is 0x46 (i.e., an
   applications specific tag with value 6). So the value for a 64 bit
   counter is 0x46 + 0x30, or 0x76 (118 base 10). However, values
   greater than 30 can not be encoded in one octet. So the first octet
   has the class, in this case context specific (ASN_CONTEXT), and
   the special value (i.e., 31) to indicate that the real value follows
   in one or more octets. The high order bit of each following octet
   indicates if the value is encoded in additional octets. A high order
   bit of zero, indicates the last. For this "hack", only one octet
   will be used for the value. */

  /* first octet of the tag */
#define ASN_OPAQUE_TAG1 (ASN_CONTEXT | ASN_EXTENSION_ID)
/* base value for the second octet of the tag - the
   second octet was the value for the tag */
#define ASN_OPAQUE_TAG2 (0x30) 

#define ASN_OPAQUE_TAG2U (0x2f) /* second octet of tag for union */

/* All the ASN.1 types for SNMP "should have been" defined in this file,
   but they were not. (They are defined in snmp_impl.h)  Thus, the tag for
   Opaque and Counter64 is defined, again, here with a different names. */
#define ASN_APP_OPAQUE (ASN_APPLICATION | 4)
#define ASN_APP_COUNTER64 (ASN_APPLICATION | 6)
#define ASN_APP_FLOAT (ASN_APPLICATION | 8)
#define ASN_APP_DOUBLE (ASN_APPLICATION | 9)
#define ASN_APP_I64 (ASN_APPLICATION | 10)
#define ASN_APP_U64 (ASN_APPLICATION | 11)
#define ASN_APP_UNION (ASN_PRIVATE | 1)

/* value for Counter64 */
#define ASN_OPAQUE_COUNTER64 (ASN_OPAQUE_TAG2 + ASN_APP_COUNTER64)
/* max size of BER encoding of Counter64 */
#define ASN_OPAQUE_COUNTER64_MX_BER_LEN 12  

/* value for Float */
#define ASN_OPAQUE_FLOAT (ASN_OPAQUE_TAG2 + ASN_APP_FLOAT)
/* size of BER encoding of Float */
#define ASN_OPAQUE_FLOAT_BER_LEN 7    

/* value for Double */
#define ASN_OPAQUE_DOUBLE (ASN_OPAQUE_TAG2 + ASN_APP_DOUBLE)
/* size of BER encoding of Double */
#define ASN_OPAQUE_DOUBLE_BER_LEN 11  

/* value for Integer64 */
#define ASN_OPAQUE_I64 (ASN_OPAQUE_TAG2 + ASN_APP_I64)
/* max size of BER encoding of Integer64 */
#define ASN_OPAQUE_I64_MX_BER_LEN 11

/* value for Unsigned64 */
#define ASN_OPAQUE_U64 (ASN_OPAQUE_TAG2 + ASN_APP_U64) 
/* max size of BER encoding of Unsigned64 */
#define ASN_OPAQUE_U64_MX_BER_LEN 12

#endif /* OPAQUE_SPECIAL_TYPES */

u_char	*asn_parse_int __P((u_char *, int *, u_char *, long *, int));
u_char	*asn_build_int __P((u_char *, int *, u_char, long *, int));
u_char	*asn_parse_unsigned_int __P((u_char *, int *, u_char *, u_long *, int));
u_char	*asn_build_unsigned_int __P((u_char *, int *, u_char, u_long *, int));
u_char	*asn_parse_string __P((u_char *, int *, u_char *, u_char *, int *));
u_char	*asn_build_string __P((u_char *, int *, u_char, u_char *, int));
u_char	*asn_parse_header __P((u_char *, int *, u_char *));
u_char	*asn_build_header __P((u_char *, int *, u_char, int));
u_char	*asn_build_sequence __P((u_char *, int *, u_char, int));
u_char	*asn_parse_length __P((u_char *, u_long *));
u_char	*asn_build_length __P((u_char *, int *, int));
u_char	*asn_parse_objid __P((u_char *, int *, u_char *, oid *, int *));
u_char	*asn_build_objid __P((u_char *, int *, u_char, oid *, int));
u_char	*asn_parse_null __P((u_char *, int *, u_char *));
u_char	*asn_build_null __P((u_char *, int *, u_char));
u_char	*asn_parse_bitstring __P((u_char *, int *, u_char *, u_char *, int *));
u_char	*asn_build_bitstring __P((u_char *, int *, u_char, u_char *, int));
u_char	*asn_parse_unsigned_int64 __P((u_char *, int *, u_char *,
                                       struct counter64 *, int));
u_char	*asn_build_unsigned_int64 __P((u_char *, int *, u_char,
                                       struct counter64 *, int));
u_char	*asn_parse_signed_int64 __P((u_char *, int *, u_char *,
                                       struct counter64 *, int));
u_char	*asn_build_signed_int64 __P((u_char *, int *, u_char,
                                       struct counter64 *, int));
u_char	*asn_build_float __P((u_char *, int *, u_char, float *,
                              int));
u_char	*asn_parse_float __P((u_char *, int *, u_char *, float *, int));
u_char	*asn_build_double __P((u_char *, int *, u_char, double *,
                               int));
u_char	*asn_parse_double __P((u_char *, int *, u_char *, double *, int));
#endif /* ASN1_H */
