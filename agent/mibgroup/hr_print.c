/*
 *  Host Resources MIB - printer device group implementation - hr_print.c
 *
 */

#include <config.h>

#include "host_res.h"
#include "hr_print.h"


#define HRPRINT_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

void  Init_HR_Print();
int   Get_Next_HR_Print();
/* void  Save_HR_Print(); */
/* char*  describe_printer(); */


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_hrprint( )
{
    init_device[ HRDEV_PRINTER ] = &Init_HR_Print;	
    next_device[ HRDEV_PRINTER ] = &Get_Next_HR_Print;
/*  save_device[ HRDEV_PRINTER ] = &Save_HR_Print;	*/
#ifdef HRPRINT_MONOTONICALLY_INCREASING
    dev_idx_inc[ HRDEV_DISK ] = 1;
#endif

/*  device_descr[ HRDEV_PRINTER ] = &describe_printer;	*/
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

int
header_hrprint(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
#define HRPRINT_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int print_idx, LowIndex = -1;
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_hrprint: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
	/* Find "next" print entry */

    Init_HR_Print();
    for ( ;; ) {
        print_idx = Get_Next_HR_Print();
        if ( print_idx == -1 )
	    break;
	newname[HRPRINT_ENTRY_NAME_LENGTH] = print_idx;
        result = compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowIndex = print_idx;
	    /* Save printer status information */
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowIndex == -1 || print_idx < LowIndex )) {
	    LowIndex = print_idx;
	    /* Save printer status information */
#ifdef HRPRINT_MONOTONICALLY_INCREASING
            break;
#endif
	}
    }

    if ( LowIndex == -1 ) {
#ifdef DODEBUG
        printf ("... index out of range\n");
#endif
        return(MATCH_FAILED);
    }

    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

#ifdef DODEBUG
    sprint_objid (c_oid, name, *length);
    printf ("... get print stats %s\n", c_oid);
#endif
    return LowIndex;
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrprint(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method)();
{
    int  print_idx;
    static char *string[100];

    print_idx = header_hrprint(vp, name, length, exact, var_len, write_method);
    if ( print_idx == MATCH_FAILED )
	return NULL;
        

    switch (vp->magic){
	case HRPRINT_STATUS:
	    long_return = 3;	/* idle */
	    return (u_char *)&long_return;
	case HRPRINT_ERROR:
	    long_return = 0;	/* Null string */
	    return (u_char *)&long_return;
	default:
	    ERROR("");
    }
    return NULL;
}


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

static int HRP_index;

void
Init_HR_Print()
{
   HRP_index = 1;
}

int
Get_Next_HR_Print()
{
			/*
			 * The initial implementation system
			 *   has no printers attached, and I've
			 *   no real idea how to detect them,
			 *   so don't bother.
			 */
    if ( HRP_index < 1 ) 	/* No printer */
        return ( HRDEV_PRINTER << HRDEV_TYPE_SHIFT ) + HRP_index++;
    else
        return -1;
}
