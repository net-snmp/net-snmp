#ifndef _net_snmp_transform_oids_h
#define _net_snmp_transform_oids_h
/*
 * transform_oids.h
 *
 * Numeric MIB names for auth and priv transforms.
 */

extern oid      usmNoAuthProtocol[10];  /* == { 1,3,6,1,6,3,10,1,1,1 }; */
extern oid      usmHMACMD5AuthProtocol[10];     /* == { 1,3,6,1,6,3,10,1,1,2 }; */
extern oid      usmHMACSHA1AuthProtocol[10];    /* == { 1,3,6,1,6,3,10,1,1,3 }; */
extern oid      usmNoPrivProtocol[10];  /* == { 1,3,6,1,6,3,10,1,2,1 }; */
extern oid      usmDESPrivProtocol[10]; /* == { 1,3,6,1,6,3,10,1,2,2 }; */

#define USM_AUTH_PROTO_NOAUTH_LEN 10
#define USM_AUTH_PROTO_MD5_LEN 10
#define USM_AUTH_PROTO_SHA_LEN 10
#define USM_PRIV_PROTO_NOPRIV_LEN 10
#define USM_PRIV_PROTO_DES_LEN 10

#endif
