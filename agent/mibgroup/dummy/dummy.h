/*
 *  DUMMY MIB by Dynarc AB/Inc.
 *  Template MIB group interface - dummy.h
 *
 */
#ifndef _MIBGROUP_DUMMY_H
#define _MIBGROUP_DUMMY_H

#include "mibdefs.h"

extern void	init_dummy();
extern u_char	*var_dummy();

/* config file parsing routines */
extern void dummy_free_config __P((void));
extern void dummy_parse_config __P((char *, char *));

/* add the DUMMY-MIB to the list of default mibs to parse */
config_add_mib(DUMMY-MIB)

/*

purpose:

   request call backs to functions for lines found in the .conf file
   beginning with the word "dummy".
  
arguments:
   "dummy":  the name of the token to look for in the snmpd.conf files.

   dummy_parse_config: A function name that is called with two
      arguments when a matching configure line is found.  The first is
      the actual name of the token found (multiple calls to a single
      function is possible), and the second is the remainder of the
      line (ie, minus the original token word).

   dummy_free_config: A function that is called to free and reset all
      variables used for local storage before reading the .conf files.
      This function should return the agent to the default state with
      respect to the dummy group.
      */

#define	DUMMYIFINFO	       1
#define	DUMMYIFID	       2
#define	DUMMYNOOFINTERFACES    3
#define	DUMMYCAPACITY	       4
#define	DUMMYSLOTMGTSCHEME     5

#endif /* _MIBGROUP_DUMMY_H */
