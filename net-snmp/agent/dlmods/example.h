/*
 *  Template MIB group interface - example.h
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

void	init_example(void);
void	deinit_example(void);
int	dynamic_init_example(void);
int	dynamic_deinit_example(void);
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

/* only load this structure when this .h file is called in the
   snmp_vars.c file in the agent subdirectory of the source tree */


/* Define a 'variable' structure that is a representation of our mib. */

/* first, we have to pick the variable type.  They are all defined in
   the var_struct.h file in the agent subdirectory.  I'm picking the
   variable2 structure since the longest sub-component of the oid I
   want to load is .2.1 and .2.2 so I need at most 2 spaces in the
   last entry. */

struct variable2 example_variables[] = {
    { EXAMPLESTRING,  ASN_OCTET_STR, RONLY, var_example, 1, {1}},
  /* Load the first table entry.  arguments:
     1: EXAMPLESTRING: magic number to pass back to us and used to
                       check against the incoming mib oid requested
                       later.
     2: STRING: type of value returned.
     3: RONLY: Its read-only.  We can't use 'snmpset' to set it.
     4: var_example: The return callback function, defined in example.c
     5: 1: The length of the next miboid this will be located at

     6: {1}: The sub-oid this table entry is for.  It's appended to
             the table entry defined later.
    */

    /* Now do the rest.  The next two are the sub-table, at .2.1 and .2.2: */
    { EXAMPLEINTEGER,   ASN_INTEGER,   RONLY, var_example, 2, {2,1}},
    { EXAMPLEOBJECTID,  ASN_OBJECT_ID, RONLY, var_example, 2, {2,2}},
    { EXAMPLETIMETICKS, ASN_TIMETICKS, RONLY, var_example, 1, {3}},
    { EXAMPLEIPADDRESS, ASN_IPADDRESS, RONLY, var_example, 1, {4}},
    { EXAMPLECOUNTER,   ASN_COUNTER,   RONLY, var_example, 1, {5}},
    { EXAMPLEGAUGE,     ASN_GAUGE,     RONLY, var_example, 1, {6}}
};

/* Now, load the above table at our requested location: */
  /* arguments:
     1.3.6.1.4.1.2021.254:  MIB oid to put the table at.
     8:                     Length of the mib oid above.
     example_variables:     The structure we just defined above
     */


#endif /* _MIBGROUP_EXAMPLE_H */
