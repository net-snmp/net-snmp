/*
 *  Template MIB group interface - wombat.h
 *
 */
#ifndef _MIBGROUP_WOMBAT_H
#define _MIBGROUP_WOMBAT_H

extern void	init_wombat();
extern u_char	*var_wombat();

/* config file parsing routines */
extern void wombat_free_config (void);
extern void wombat_parse_config (char *, char *);

config_parse_dot_conf("wombat", wombat_parse_config, wombat_free_config, "help string");
/*

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

#endif /* _MIBGROUP_WOMBAT_H */
