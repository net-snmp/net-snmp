/*
 *  Template MIB group implementation - wombat.c
 *
 */

#include "../common_header.h"
#include "wombat.h"


/*  
 *  header_wombat routines are called to implement the final part of
 *  the oid search.  The parent snmpd routines search the subtree
 *  structure, composed of the various entries in the wombat.h file,
 *  to identify the routine likely responsible for the given oid.  vp
 *  points to the subtree element that contained pointers to the
 *  var_wombat routine, and name points to the actual request.  The
 *  var_wombat routine is called with this info, and it calls
 *  header_wombat to either verify that the request is valid (in the
 *  case of a Get [exact == 1]), or turn the request into a valid
 *  request, if possible (in the case of Get Next [exact == 0]).  When
 *  a valid request is found or generated, a pointer to the routine
 *  responsible for handling Set requests is filled in, in case that's
 *  what's really caused our invocation.
 *
 *  The subtree structure only identifies Types.  In the case of Get,
 *  if the oid is a scalar, we just check to see if the length is
 *  right and the instance identifier is 0.  If the oid is a table, we
 *  validate the index.  This routine could be modified to deal with
 *  a single routine handling a sequence or other data structures, but
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
 *  it to the next valid oid.
 */

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


static struct nlist wombat_nl[] = {
#define N_WOMBATSTAT    0
#define N_MIN_WOMBAT    1
#define N_MAX_WOMBAT    2
#if !defined(hpux) && !defined(solaris2)
        { "_wombatstat"},
        { "_wombat_min"},
        { "_wombat_max"},
#else
        { "wombatstat"},
        { "wombat_min"},
        { "wombat_max"},
#endif
        { 0 },
};


void calculate_wombat();


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_wombat( )
{
    init_nlist( wombat_nl );
}

/* function which scans a given snmpd.conf line for information */

void wombat_parse_config(word,line)
  char *word;
  char *line;
{
}

/* function which frees resources allocated by the .conf parser above
   and resets all values to defaults.  It called just before the agent
   re-reads all the .conf files. */

void wombat_free_config __P((void)) {
}


#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

int
header_wombat(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
#define WOMBAT_NAME_LENGTH	8
    oid newname[MAX_NAME_LEN];
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_wombat: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[WOMBAT_NAME_LENGTH] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
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
var_wombat(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method)();
{
    if (header_wombat(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    switch (vp->magic){
	case WOMBATUPTIME:
	    long_return = 1;
	    return (u_char *)&long_return;
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

void calculate_wombat()
{
  return;
}
