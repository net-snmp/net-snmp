/*
 *  registry:  displays a list of all loaded mib modules.
 *
 */

#include <config.h>
#if STDC_HEADERS
#include <stdlib.h>
#endif

#include "mibincl.h"
#include "snmp_api.h"
#include "registry.h"


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


extern int subtree_size;
extern struct subtree *subtrees;

#define MATCH_FAILED	-1

struct subtree *
header_registry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
#define REGISTRY_NAME_LENGTH	10
    oid newname[MAX_NAME_LEN];
    int result,i;
    char c_oid[MAX_NAME_LEN];
    struct subtree *mine = NULL;
    
    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_registry: %s %d %d\n", c_oid, exact, *length);
    }
    if (*length < REGISTRY_NAME_LENGTH)
      mine = subtrees;
    else
      mine = find_subtree_next(&(name[REGISTRY_NAME_LENGTH]),
                               *length-REGISTRY_NAME_LENGTH,
                               subtrees);
    
    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    if (mine != NULL) {
      bcopy((char *)mine->name, (char *)(name+vp->namelen),
            ((int)mine->namelen) * sizeof(oid));
      *length = vp->namelen + mine->namelen;
    }

    sprint_objid (c_oid, name, *length);
    DEBUGP ("var_registry return: %s %d\n", c_oid, *length);

    return mine;
    
    for(i=0; i < subtree_size; i++) {
      newname[REGISTRY_NAME_LENGTH] = i+1;
      result = compare(name, *length, newname, (int)vp->namelen + 1);
      if (!((exact && (result != 0)) || (!exact && (result >= 0))))
        break;
    }
    if (i >= subtree_size) {
      DEBUGP ("... index out of range: %d > %d\n",i,subtree_size);
      return(NULL);
    }
    DEBUGP ("... doing %d\n", i);
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(NULL);
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

u_char	*
var_registry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method)();
{
  struct subtree *index;
    if ((index =
         header_registry(vp, name, length, exact, var_len, write_method))
        == NULL )
      return NULL;

    switch (vp->magic){
	case REGISTRYINDEX:
            *var_len = sizeof(oid)*(index->namelen);
            return (u_char *) index->name;
        case REGISTRYNAME:
            *var_len = strlen(index->label);
            return (u_char *) index->label;
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
