/* 
 * usmUser.h
 *
 */

#ifndef _MIBGROUP_USMUSER_H
#define _MIBGROUP_USMUSER_H

#include "snmpusm.h"

/* <...prefix>.<engineID_length>.<engineID>.<user_name_length>.<user_name>
   = 1 + 32 + 1 + 32 */
#define USM_LENGTH_OID_MAX	66

/* we use header_generic and checkmib from the util_funcs module */

config_require(util_funcs)
config_add_mib(SNMP-USER-BASED-SM-MIB)

/* Magic number definitions: */

#define   USMUSERSPINLOCK       1
#define   USMUSERSECURITYNAME   2
#define   USMUSERCLONEFROM      3
#define   USMUSERAUTHPROTOCOL   4
#define   USMUSERAUTHKEYCHANGE  5
#define   USMUSEROWNAUTHKEYCHANGE  6
#define   USMUSERPRIVPROTOCOL   7
#define   USMUSERPRIVKEYCHANGE  8
#define   USMUSEROWNPRIVKEYCHANGE  9
#define   USMUSERPUBLIC         10
#define   USMUSERSTORAGETYPE    11
#define   USMUSERSTATUS         12

/* function definitions */

extern void   init_usmUser(void);
extern unsigned char *var_usmUser(struct variable *, oid *, int *, int, int *, int (**write)(int, unsigned char *, unsigned char, int, unsigned char *, oid *, int)) ;
void shutdown_usmUser(void);
oid *usm_generate_OID(oid *prefix, int prefixLen, struct usmUser *uptr,
                  int *length);
int usm_parse_oid(oid *oidIndex, int oidLen,
              unsigned char **engineID, int *engineIDLen,
              unsigned char **name, int *nameLen);
int write_usmUserSpinLock(int, u_char *,u_char, int, u_char *,oid*, int);
int write_usmUserCloneFrom(int, u_char *,u_char, int, u_char *,oid*, int);
int write_usmUserAuthProtocol(int, u_char *,u_char, int, u_char *,oid*, int);
int write_usmUserAuthKeyChange(int, u_char *,u_char, int, u_char *,oid*, int);
int write_usmUserPrivProtocol(int, u_char *,u_char, int, u_char *,oid*, int);
int write_usmUserPrivKeyChange(int, u_char *,u_char, int, u_char *,oid*, int);
int write_usmUserPublic(int, u_char *,u_char, int, u_char *,oid*, int);
int write_usmUserStorageType(int, u_char *,u_char, int, u_char *,oid*, int);
int write_usmUserStatus(int, u_char *,u_char, int, u_char *,oid*, int);

/* Only load this structure when this .h file is called in the snmp_vars.c 
   file in tha agent subdirectory of the source tree */

#ifdef IN_SNMP_VARS_C

/* this variable defines function callbacks and type return information 
   for the usmUser mib */

struct variable4 usmUser_variables[] = {
  { USMUSERSPINLOCK     , ASN_INTEGER   , RWRITE, var_usmUser, 1, { 1 } },
  { USMUSERSECURITYNAME , ASN_OCTET_STR , RONLY , var_usmUser, 3, { 2,1,3 } },
  { USMUSERCLONEFROM    , ASN_OBJECT_ID , RWRITE, var_usmUser, 3, { 2,1,4 } },
  { USMUSERAUTHPROTOCOL , ASN_OBJECT_ID , RWRITE, var_usmUser, 3, { 2,1,5 } },
  { USMUSERAUTHKEYCHANGE, ASN_OCTET_STR , RWRITE, var_usmUser, 3, { 2,1,6 } },
  { USMUSEROWNAUTHKEYCHANGE, ASN_OCTET_STR , RWRITE, var_usmUser, 3, { 2,1,7 } },
  { USMUSERPRIVPROTOCOL , ASN_OBJECT_ID , RWRITE, var_usmUser, 3, { 2,1,8 } },
  { USMUSERPRIVKEYCHANGE, ASN_OCTET_STR , RWRITE, var_usmUser, 3, { 2,1,9 } },
  { USMUSEROWNPRIVKEYCHANGE, ASN_OCTET_STR , RWRITE, var_usmUser, 3, { 2,1,10 } },
  { USMUSERPUBLIC       , ASN_OCTET_STR , RWRITE, var_usmUser, 3, { 2,1,11 } },
  { USMUSERSTORAGETYPE  , ASN_INTEGER   , RWRITE, var_usmUser, 3, { 2,1,12 } },
  { USMUSERSTATUS       , ASN_INTEGER   , RWRITE, var_usmUser, 3, { 2,1,13 } },

};

/* now load this mib into the agents mib table */
config_load_mib(1.3.6.1.6.3.12.1.2, 9, usmUser_variables)

#endif /* IN_SNMP_VARS_C */
#endif /* _MIBGROUP_USMUSER_H */
