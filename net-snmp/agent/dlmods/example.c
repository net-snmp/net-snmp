/*
 *  Template MIB group implementation - example.c
 *
 */

/* include important headers */
#include <config.h>

/* needed by util_funcs.h */
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

/* mibincl.h contains all the snmp specific headers to define the
   return types and various defines and structures. */
#include "mibincl.h"

/* header_generic() comes from here */
#include "util_funcs.h"

/* include our .h file */
#include "example.h"

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


/* this is an optional function called at the time the agent starts up
   to do any initilizations you might require.  You don't have to
   create it, as it is optional. */

/* IMPORTANT: If you add or remove this function, you *must* re-run
   the configure script as it checks for its existance. */

static oid example_name[16] = {1,3,6,1,4,1,2021,254};
static int example_name_len = 8;

void
init_example (void) 
{
  /* call auto_nlist to load the nlist symbols.  We
     actually don't need it, so its commented out. */
  /* auto_nlist( "example_symbol" ); */
  register_mib("example", (struct variable *)example_variables,
	  sizeof(*example_variables),
	  sizeof(example_variables) / sizeof(*example_variables),
	  example_name, example_name_len);
}

void
deinit_example (void) 
{
    unregister_mib(example_name, example_name_len);
}

int 
dynamic_init_example (void)
{
    init_example();
    return 0;
}

int 
dynamic_deinit_example (void) 
{
    deinit_example();
    return 0;
}
/* define the callback function used in the example_variables
   structure in example.h */

u_char	*
var_example(struct variable *vp,
	    oid *name,
	    int *length,
	    int exact,
	    int *var_len,
	    WriteMethod **write_method)
{
  /* define any variables we might return as static! */
  static long long_ret;
  static char string[300];
  static oid oid_ret[8];
  
  /* header_generic is a simple function for finding out if we're in
     the right place.  This only works on scalar objects.  Use
     checkmib for simple tables, and write your own for anything
     else. */
  if (header_generic(vp, name, length, exact, var_len, write_method))
    return NULL;

  /* We can now simply test on vp's magic number, defined in example.h */
  switch (vp->magic){
    case EXAMPLESTRING:
      /* set up return information */
      sprintf(string,"life the universe and everything");
      
      /* set the length of the returned data */
      *var_len = strlen(string);
      
      /* return everything as mapped to a u_char * */
      return (u_char *) string;

    case EXAMPLEINTEGER:
      long_ret = 42;
      return (u_char *) &long_ret;
      /* note: var_len defaults to the length of a long */
      
    case EXAMPLEOBJECTID:
      oid_ret[0] = 1;
      oid_ret[1] = 3;
      oid_ret[2] = 6;
      oid_ret[3] = 1;
      oid_ret[4] = 4;
      oid_ret[5] = oid_ret[6] = oid_ret[7] = 42;
      *var_len = 8*sizeof(oid);
      return (u_char *) oid_ret;
      
    case EXAMPLETIMETICKS:
      long_ret = 363136200;
      return (u_char *) &long_ret;
      
    case EXAMPLEIPADDRESS:
      /* ipaddresses get returned as a long.  ick */
      /* we're returning 127.0.0.1 */
      long_ret = ((127 << (8*3)) + (0 << (8*2)) + (0 << (8*1)) + 1);
      return (u_char *) &long_ret;
      
    case EXAMPLECOUNTER:
      long_ret = 42;
      return (u_char *) &long_ret;
      
    case EXAMPLEGAUGE:
      long_ret = 42;
      return (u_char *) &long_ret;

    default:
      DEBUGMSGTL(("snmpd", "unknown sub-id %d in dlmods/var_example\n", vp->magic));
  }
  /* if we fall to here, fail by returning NULL */
  return NULL;
}
