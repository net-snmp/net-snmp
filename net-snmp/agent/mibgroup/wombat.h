/*
 *  Template MIB group interface - wombat.h
 *
 */
#ifndef _MIBGROUP_WOMBAT_H
#define _MIBGROUP_WOMBAT_H

extern void	init_wombat();
extern u_char	*var_wombat();

/* config file parsing routines */
extern void wombat_free_config __P((void));
extern void wombat_parse_config __P((char *, char *));

config_parse_dot_conf("wombat", wombat_parse_config, wombat_free_config);
/* config_parse_dot_conf():

purpose:

   request call backs to functions for lines found in the .conf file
   beginning with the word "wombat".
  
arguments:
   "wombat":  the name of the token to look for in the snmpd.conf files.

   wombat_parse_config: A function name that is called with two
      arguments when a matching configure line is found.  The first is
      the actual name of the token found (multiple calls to a single
      function is possible), and the second is the remainder of the
      line (ie, minus the original token word).

   wombat_free_config: A function that is called to free and reset all
      variables used for local storage before reading the .conf files.
      This function should return the agent to the default state with
      respect to the wombat group.
      */

#define	WOMBATUPTIME		1
#define	WOMBATCURRENT		2
#define	WOMBATHIGHWATER		3

#ifdef IN_SNMP_VARS_C

struct variable2 wombat_variables[] = {
    { WOMBATUPTIME,  TIMETICKS, RONLY, var_wombat, 1, {1}},
    { WOMBATCURRENT,   COUNTER, RONLY, var_wombat, 1, {2}},
    { WOMBATHIGHWATER, COUNTER, RONLY, var_wombat, 1, {3}}
};
config_load_mib(1.3.6.1.2.1.99, 7, wombat_variables)
  /* arguments:
     .1.3.6.1.2.1.99:       MIB oid to put the table at.
     7:                     Length of the mib oid above.
     womat_variables: The structure we just defined above */

#endif
#endif /* _MIBGROUP_WOMBAT_H */
