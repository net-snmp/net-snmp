/*
 * SNMPv3 View-based Access Control Model
 */

#ifndef _MIBGROUP_VACM_CONF_H
#define _MIBGROUP_VACM_CONF_H

#include <net-snmp/library/vacm.h>

config_require(util_funcs)
config_belongs_in(agent_module)

     void            init_vacm_conf(void);
     void            vacm_free_group(void);
     void            vacm_free_access(void);
     void            vacm_free_view(void);
     void            vacm_parse_group(const char *, char *);
     void            vacm_parse_access(const char *, char *);
     void            vacm_parse_view(const char *, char *);
     void            vacm_parse_simple(const char *, char *);

     SNMPCallback    vacm_in_view_callback;
     SNMPCallback    vacm_warn_if_not_configured;

     int             vacm_in_view(netsnmp_pdu *, oid *, size_t, int);

#endif                          /* _MIBGROUP_VACM_CONF_H */
