/*
 *  hpux specific mib sections
 *
 */
#ifndef _MIBGROUP_HPUX_H
#define _MIBGROUP_HPUX_H

int writeHP __P((int, u_char *, u_char, int, u_char *,oid *, int));
unsigned char *var_hp __P((struct variable *, oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *, oid *, int)) ));

#define TRAPAGENT 128.120.57.92

#define HPCONF 1
#define HPRECONFIG 2
#define HPFLAG 3
#define HPLOGMASK 4
#define HPSTATUS 6
#define HPTRAP 101

#ifdef IN_SNMP_VARS_C

struct variable2 hp_variables[] = {
  {HPCONF, INTEGER, RWRITE, var_hp, 1, {HPCONF}},
  {HPRECONFIG, INTEGER, RWRITE, var_hp, 1, {HPRECONFIG}},
  {HPFLAG, INTEGER, RWRITE, var_hp, 1, {HPFLAG}},
  {HPLOGMASK, INTEGER, RWRITE, var_hp, 1, {ERRORFLAG}},
  {HPSTATUS, INTEGER, RWRITE, var_hp, 1, {ERRORMSG}}
};

struct variable2 hptrap_variables[] = {
  {HPTRAP, IPADDRESS, RWRITE, var_hp, 1, {HPTRAP }},
};

config_load_mib(1.3.6.1.4.1.11.2.13.1.2.1, 12, hptrap_variables)
config_load_mib(1.3.6.1.4.1.11.2.13.2, 10, hp_variables)

#endif
#endif /* _MIBGROUP_HPUX_H */
