/*
 *  Template MIB group interface - example.h
 *
 *  This file is essentially a copy of wombat.h and then modified.
 *
 *  This mib is essentially duplicating the passtest script in the
 *  local directory, used by the EXAMPLE.conf file in the top level
 *  source directory.
 *
 */

/* Don't include ourselves twice */
#ifndef _MIBGROUP_EXAMPLE_H
#define _MIBGROUP_EXAMPLE_H

config_require(util_funcs);

/* Define all our functions using prototyping for ANSI compilers */
/* These functions are then defined in the example.c file */

void	init_example();
FindVarMethod var_example;


/* Magic number definitions.  These numbers are the last oid index
   numbers to the table that you are going to define.  For example,
   lets say (since we are) creating a mib table at the location
   .1.3.6.1.4.1.2021.254.  The following magic numbers would be the
   next numbers on that oid for the var_example function to use, ie:
   .1.3.6.1.4.1.2021.254.1 (and .2 and .3 ...) */

#define	EXAMPLESTRING		1
/* These two are going to be a sub-table at ...2021.254.1.2.X */
/* they must be unique, and don't have to map exactly to the mib oids */
#define EXAMPLEINTEGER		21  
#define	EXAMPLEOBJECTID         22
/* Back to the normal table */
#define EXAMPLETIMETICKS	3
#define	EXAMPLEIPADDRESS        4
#define EXAMPLECOUNTER		5  
#define	EXAMPLEGAUGE            6

#endif /* _MIBGROUP_EXAMPLE_H */
