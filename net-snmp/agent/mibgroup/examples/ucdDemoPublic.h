/* ucdDemoPublic.h */

#ifndef _MIBGROUP_UCDDEMOPUBLIC_H
#define _MIBGROUP_UCDDEMOPUBLIC_H

/* we use header_generic and checkmib from the util_funcs module */

config_require(util_funcs)

/* Magic number definitions: */

#define   UCDDEMORESETKEYS      1
#define   UCDDEMOPUBLICSTRING   2
#define   UCDDEMOUSERLIST       3
#define   UCDDEMOPASSPHRASE     4

/* function definitions */

extern void   init_ucdDemoPublic(void);
extern unsigned char *var_ucdDemoPublic(struct variable *, oid *, int *, int, int *, int (**write) (int, unsigned char *, unsigned char, int, unsigned char *, oid *, int));
int write_ucdDemoResetKeys(int, u_char *,u_char, int, u_char *,oid*, int);
int write_ucdDemoPublicString(int, u_char *,u_char, int, u_char *,oid*, int);


/* Only load this structure when this .h file is called in the snmp_vars.c 
   file in tha agent subdirectory of the source tree */

#ifdef IN_SNMP_VARS_C

/* this variable defines function callbacks and type return information 
   for the ucdDemoPublic mib */

struct variable2 ucdDemoPublic_variables[] = {
  { UCDDEMORESETKEYS    , ASN_INTEGER   , RWRITE, var_ucdDemoPublic, 1, { 1 } },
  { UCDDEMOPUBLICSTRING , ASN_OCTET_STR , RWRITE, var_ucdDemoPublic, 1, { 2 } },
  { UCDDEMOUSERLIST     , ASN_OCTET_STR , RWRITE, var_ucdDemoPublic, 1, { 3 } },
  { UCDDEMOPASSPHRASE   , ASN_OCTET_STR , RWRITE, var_ucdDemoPublic, 1, { 4 } },

};

/* now load this mib into the agents mib table */
config_load_mib(1.3.6.1.4.1.2021.14.1.1, 10, ucdDemoPublic_variables)

#endif /* IN_SNMP_VARS_C */
#endif /* _MIBGROUP_UCDDEMOPUBLIC_H */
