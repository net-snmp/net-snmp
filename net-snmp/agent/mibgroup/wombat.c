/*
 *  Template MIB group implementation - wombat.c
 *
 */

#include "../common_header.h"
#include "wombat.h"


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
