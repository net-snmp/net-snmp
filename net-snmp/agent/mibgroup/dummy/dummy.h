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


#ifdef IN_SNMP_VARS_C

struct variable2 dummy_variables[] = {
    { DUMMYIFINFO,  STRING, RONLY, var_dummy, 1, {DUMMYIFINFO}},
    { DUMMYIFID,   INTEGER, RONLY, var_dummy, 1, {DUMMYIFID}},
    { DUMMYNOOFINTERFACES, COUNTER, RONLY, var_dummy, 1, {DUMMYNOOFINTERFACES}},
    { DUMMYCAPACITY, COUNTER, RONLY, var_dummy, 1, {DUMMYCAPACITY}},
    { DUMMYSLOTMGTSCHEME, INTEGER, RONLY, var_dummy, 1, {DUMMYSLOTMGTSCHEME}}
};

config_load_mib(1.3.6.1.4.1.3209, 7, dummy_variables) 
  /* arguments:
     .1.3.6.1.4.1.3209:       MIB oid to put the table at.
     7:                     Length of the mib oid above.
     dummy_variables: The structure we just defined above */

#endif
#endif /* _MIBGROUP_DUMMY_H */
