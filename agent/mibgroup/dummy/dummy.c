/*
 *  Template MIB group implementation - dummy.c
 *
 */

#include <config.h>

#include "../mibincl.h"
#include "../struct.h"
#include "../../../snmplib/system.h"
#include "dummy.h"

/*  
 *  header_dummy routines are called to implement the final part of
 *  the oid search.  The parent snmpd routines search the subtree
 *  structure, composed of the various entries in the dummy.h file,
 *  to identify the routine likely responsible for the given oid.  vp
 *  points to the subtree element that contained pointers to the
 *  var_dummy routine, and name points to the actual request.  The
 *  var_dummy routine is called with this info, and it calls
 *  header_dummy to either verify that the request is valid (in the
 *  case of a Get [exact == 1]), or turn the request into a valid
 *  request, if possible (in the case of Get Next [exact == 0]).  When
 *  a valid request is found or generated, a pointer to the routine
 *  responsible for handling Set requests is filled in, in case that's
 *  what's really caused our invocation.
 *
 *  The subtree structure only identifies Types.  In the case of Get,
 *  we just check to see if the length is right and the request
 *  matches something we can answer to.  If the oid is a table, we
 *  validate the index.  This routine could be modified to deal with a
 *  single routine handling a sequence or other data structures, but
 *  you're probably reinventing the wheel if you do (the subtree
 *  structure should be used to reduce those cases down to a scalar or
 *  a table).
 *
 *  In the case of Get Next, we have to deal with the fact that the
 *  incoming request is probably not going to match anything --- it
 *  can be too short or too long, or the index of a table might not
 *  match anything actually in the table.
 *
 *  If the incoming request is too short, convert it to the first valid
 *  oid.  If it's too long, match as far as possible, and then convert
 *  it to the next valid oid.  */



	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

void calculate_dummy(void);

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void init_dummy(void)
{

/* define the structure we're going to ask the agent to register our
   information at */
  struct variable2 dummy_variables[] = {
    { DUMMYIFINFO,  ASN_OCTET_STR, RONLY, var_dummy, 1, {DUMMYIFINFO}},
    { DUMMYIFID,   ASN_INTEGER, RONLY, var_dummy, 1, {DUMMYIFID}},
    { DUMMYNOOFINTERFACES, ASN_COUNTER, RONLY, var_dummy, 1, {DUMMYNOOFINTERFACES}},
    { DUMMYCAPACITY, ASN_COUNTER, RONLY, var_dummy, 1, {DUMMYCAPACITY}},
    { DUMMYSLOTMGTSCHEME, ASN_INTEGER, RONLY, var_dummy, 1, {DUMMYSLOTMGTSCHEME}}
  };

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
  oid dummy_variables_oid[] = { 1,3,6,1,4,1,3209 };

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("dummy", dummy_variables, variable2, dummy_variables_oid);

#endif
}

/* function which scans a given snmpd.conf line for information */

void dummy_parse_config(char *word,
			char *line)
{
}

/* function which frees resources allocated by the .conf parser above
   and resets all values to defaults.  It called just before the agent
   re-reads all the .conf files. */

void dummy_free_config (void) {
}


#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

/* header_dummy(...
   Arguments:
   vp            IN     - pointer to variable entry that points here
   name          IN/OUT - IN/name requested, OUT/name found
   length        IN/OUT - length of input and output oid's
   exact         IN     - TRUE if an exact match was requested. 
   var_len       OUT     - length of variable or 0 if function returned.
   write_method  OUT     - pointer to function to set variable, otherwise 0
*/
   
*/
int
header_dummy(struct variable *vp,
	     oid *name,
	     int *length,
	     int exact,
	     int *var_len,
	     int (**write_method)()) 
{
#define DUMMY_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;

    /* just do trace and token print */
    DEBUGMSGTL(("dummy/dummy:var_dummy", ""));
    DEBUGMSGOID(("dummy/dummy:var_dummy", name, *length));
    DEBUGMSG(("dummy/dummy:var_dummy", " %d\n", exact));

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[DUMMY_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

u_char	*
var_dummy(struct variable *vp,
	  oid *name,
	  int *length,
	  int exact,
	  int *var_len,
	  int (**write_method)())
{

  static long long_ret;
  static char string[30];
  static oid oid_ret[8];

    if (header_dummy(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    switch (vp->magic){
	case DUMMYIFINFO:
	  printf("DUMMYIFINFO!!!\n");
	   sprintf(string, "DUMMY Host Interface, release 1.0");
	   *var_len = strlen(string);
	   return (u_char *) string;

	case DUMMYIFID:
	  printf("DUMMYIFID!!!\n");
	    long_ret = 6;
	    return (u_char *)&long_ret;
	case DUMMYNOOFINTERFACES:
	  printf("DUMMYNOOFINTERFACES!!!\n");
	    long_ret = 3;
	    return (u_char *)&long_ret;

	case DUMMYCAPACITY:
	  printf("DUMMYCAPACITY!!!\n");
	    long_ret = 4;
	    return (u_char *)&long_ret;

	case DUMMYSLOTMGTSCHEME:
	  printf("DUMMYSLOTMGTSCHEME!!!\n");
	    long_ret = 8;
	    return (u_char *)&long_ret;

	default:
	    ERROR_MSG("");
    }
    return NULL;
}


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

void calculate_dummy(void)
{
  return;
}
