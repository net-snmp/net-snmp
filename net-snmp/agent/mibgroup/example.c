/*
 *  Template MIB group implementation - example.c
 *
 */

/* include important headers */
#include <config.h>

/* mibincl.h contains all the snmp specific headers to define the
   return types and various defines and structures. */
#include "mibincl.h"

/* for the nlist struct */
#include <nlist.h>

/* include our .h file */
#include "example.h"

int header_example __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

/* if you have to read stuff out of the kernel using nlist, you can
   define an nlist structure and load it in the init_example function.
   We don't actually need one, but its here for an example. */

static struct nlist example_nl[] = {
#define N_EXAMPLESTAT    0
#define N_MIN_EXAMPLE    1
#define N_MAX_EXAMPLE    2
#if !defined(hpux) && !defined(solaris2)
        { "_examplestat"},
        { "_example_min"},
        { "_example_max"},
#else
        { "examplestat"},
        { "example_min"},
        { "example_max"},
#endif
        { 0 },
};


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

void	init_example( )
{
  /* call init_nlist to load the nlist structure defined above.  We
     actually don't need it, so its commented out. */
  /* init_nlist( example_nl ); */
}

#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

/* This function is a generic function we use to determine if the
   incoming request is within our defined mib table.  It is up to *us*
   to determine if it is or not */

int
header_example(vp, name, length, exact, var_len, write_method)
    /* vp:       IN - pointer to variable entry that we defined in example.h */
    register struct variable *vp;

    /* name:     IN/OUT - input oid requested, output oid found */
    oid     *name;	    

    /* length:   IN/OUT - length of input and output oid's */
    int     *length;	    

    /* exact:    IN - TRUE if an exact match was requested.
                      (ie getnext if not true, get if true). */
    int     exact;

    /* var_len:  OUT - length of data returned or 0 if function returned. */
    int     *var_len;

    /* write_method: OUT - pointer to function to set this variable,
                           otherwise 0 */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *, oid *, int));

{

/* The length of our mib oid.  It should match the length defined in
   the .h file using config_load_mib(). */
#define EXAMPLE_NAME_LENGTH	8

    oid newname[MAX_NAME_LEN];
    int result;

/* DODEBUG is defined if --enable-debugging is passed as a configure
   argument. */
    
#ifdef DODEBUG
    /* print out the fact that we got here */
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_example: %s %d\n", c_oid, exact);
    sprint_objid (c_oid, vp->name, vp->namelen);
    printf ("\tvp->name: %s\n", c_oid);
#endif

    /* copy our mib oid from the vp->name structure */
    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[vp->namelen] = 0;

    /* compare it against the incoming request */
    result = compare(name, *length, newname, (int)vp->namelen + 1);

    /* return if its outside of our mib definition */
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);

    /* since it is inside our mib tree, copy it back onto the name
       outing pointer. */
    bcopy((char *)newname, (char *)name, ((int)vp->namelen+1) * sizeof(oid));
    *length = vp->namelen+1;

    *write_method = 0;          /* default to read-only */
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

/* define the callback function used in the example_variables
   structure in example.h */

u_char	*
var_example(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method)();
{
  /* define any variables we might return as static! */
  static long long_ret;
  static char *string[300];
  static oid oid_ret[8];
  
  if (header_example(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
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
      ERROR_MSG("example.c: don't know how to handle this request.");
  }
  /* if we fall to here, fail by returning NULL */
  return NULL;
}
