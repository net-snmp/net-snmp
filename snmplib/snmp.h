/*
 * Definitions for the Simple Network Management Protocol (RFC 1067).
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

#define SNMP_PORT	    161
#define SNMP_TRAP_PORT	    162

#define SNMP_MAX_LEN	    1500

#define SNMP_VERSION_1	    0
#define SNMP_SECURITY_1     1
#define SNMP_VERSION_2	    2

#define GET_REQ_MSG	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0)
#define GETNEXT_REQ_MSG	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x1)
#define GET_RSP_MSG	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x2)
#define SET_REQ_MSG	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x3)
#define TRP_REQ_MSG	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x4)
#define BULK_REQ_MSG	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x5)
#define INFORM_REQ_MSG	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x6)
#define TRP2_REQ_MSG	    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x7)

#define SNMP_NOSUCHOBJECT    (ASN_CONTEXT | ASN_PRIMITIVE | 0x0)
#define SNMP_NOSUCHINSTANCE  (ASN_CONTEXT | ASN_PRIMITIVE | 0x1)
#define SNMP_ENDOFMIBVIEW    (ASN_CONTEXT | ASN_PRIMITIVE | 0x2)

#define SNMP_ERR_NOERROR    (0x0)
#define SNMP_ERR_TOOBIG	    (0x1)
#define SNMP_ERR_NOSUCHNAME (0x2)
#define SNMP_ERR_BADVALUE   (0x3)
#define SNMP_ERR_READONLY   (0x4)
#define SNMP_ERR_GENERR	    (0x5)

#define SNMP_ERR_NOACCESS		(6)
#define SNMP_ERR_WRONGTYPE		(7)
#define SNMP_ERR_WRONGLENGTH		(8)
#define SNMP_ERR_WRONGENCODING		(9)
#define SNMP_ERR_WRONGVALUE		(10)
#define SNMP_ERR_NOCREATION		(11)
#define SNMP_ERR_INCONSISTENTVALUE	(12)
#define SNMP_ERR_RESOURCEUNAVAILABLE	(13)
#define SNMP_ERR_COMMITFAILED		(14)
#define SNMP_ERR_UNDOFAILED		(15)
#define SNMP_ERR_AUTHORIZATIONERROR	(16)
#define SNMP_ERR_NOTWRITABLE		(17)

#define SNMP_TRAP_COLDSTART		(0x0)
#define SNMP_TRAP_WARMSTART		(0x1)
#define SNMP_TRAP_LINKDOWN		(0x2)
#define SNMP_TRAP_LINKUP		(0x3)
#define SNMP_TRAP_AUTHFAIL		(0x4)
#define SNMP_TRAP_EGPNEIGHBORLOSS	(0x5)
#define SNMP_TRAP_ENTERPRISESPECIFIC	(0x6)

void xdump __P((u_char *, int, char *));
u_char *snmp_parse_var_op __P((u_char *, oid *, int *, u_char *, int *,
                               u_char **, int *));
u_char *snmp_build_var_op __P((u_char *, oid *, int *, u_char, int, u_char *,
                               int *));
