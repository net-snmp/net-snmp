#ifndef _net_snmp_transform_oids_h
#define _net_snmp_transform_oids_h

#ifdef __cplusplus
extern          "C" {
#endif
/*
 * transform_oids.h
 *
 * Numeric MIB names for auth and priv transforms.
 */

/** auth */
#define NETSNMP_USMAUTH_BASE_OID 1,3,6,1,6,3,10,1,1
#define NETSNMP_USMAUTH_NOAUTH            1
#define NETSNMP_USMAUTH_HMACMD5           2
#define NETSNMP_USMAUTH_HMACSHA1          3
#define NETSNMP_USMAUTH_HMACSHA           NETSNMP_USMAUTH_HMACSHA1
#define NETSNMP_USMAUTH_HMAC128SHA224     4 /* RFC 7860; OPTIONAL */
#define NETSNMP_USMAUTH_HMAC192SHA256     5 /* RFC 7860; MUST */
#define NETSNMP_USMAUTH_HMAC256SHA384     6 /* RFC 7860; OPTIONAL */
#define NETSNMP_USMAUTH_HMAC384SHA512     7 /* RFC 7860; SHOULD */

NETSNMP_IMPORT oid      usmNoAuthProtocol[10];  /* == { NETSNMP_USMAUTH_BASE,1 }; */
#ifndef NETSNMP_DISABLE_MD5
NETSNMP_IMPORT oid      usmHMACMD5AuthProtocol[10];     /* == { NETSNMP_USMAUTH_BASE,2 }; */
#endif
NETSNMP_IMPORT oid      usmHMACSHA1AuthProtocol[10];    /* == { NETSNMP_USMAUTH_BASE,3 }; */

NETSNMP_IMPORT oid      usmHMAC128SHA224AuthProtocol[10];
NETSNMP_IMPORT oid      usmHMAC192SHA256AuthProtocol[10];
NETSNMP_IMPORT oid      usmHMAC256SHA384AuthProtocol[10];
NETSNMP_IMPORT oid      usmHMAC384SHA512AuthProtocol[10];

/** priv */
NETSNMP_IMPORT oid      usmNoPrivProtocol[10];  /* == { 1,3,6,1,6,3,10,1,2,1 }; */
#ifndef NETSNMP_DISABLE_DES
NETSNMP_IMPORT oid      usmDESPrivProtocol[10]; /* == { 1,3,6,1,6,3,10,1,2,2 }; */
#endif

/* XXX: OIDs not defined yet */
NETSNMP_IMPORT oid      usmAESPrivProtocol[10]; /* == { 1,3,6,1,6,3,10,1,2,4 }; */
NETSNMP_IMPORT oid      *usmAES128PrivProtocol; /* backwards compat */


#define USM_AUTH_PROTO_NOAUTH_LEN USM_LENGTH_OID_TRANSFORM
#define USM_AUTH_PROTO_MD5_LEN    USM_LENGTH_OID_TRANSFORM
#define USM_AUTH_PROTO_SHA_LEN    USM_LENGTH_OID_TRANSFORM
#define USM_PRIV_PROTO_NOPRIV_LEN USM_LENGTH_OID_TRANSFORM
#define USM_PRIV_PROTO_DES_LEN    USM_LENGTH_OID_TRANSFORM

#define USM_PRIV_PROTO_AES_LEN    USM_LENGTH_OID_TRANSFORM
#define USM_PRIV_PROTO_AES128_LEN USM_LENGTH_OID_TRANSFORM /* backwards compat */

#ifdef __cplusplus
}
#endif
#endif
