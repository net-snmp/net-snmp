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

void  Init_HR_Print (void);
int Get_Next_HR_Print (void);
/* void  Save_HR_Print (void); */
/* char*  describe_printer (void); */
int header_hrprint (struct variable *,oid *, size_t *, int, size_t *, WriteMethod **);


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

#define	HRPRINT_STATUS		1
#define	HRPRINT_ERROR		2

struct variable4 hrprint_variables[] = {
    { HRPRINT_STATUS,    ASN_INTEGER, RONLY, var_hrprint, 2, {1,1}},
    { HRPRINT_ERROR,   ASN_OCTET_STR, RONLY, var_hrprint, 2, {1,2}}
};
oid hrprint_variables_oid[] = { 1,3,6,1,2,1,25,3,5 };


void init_hr_print(void)
{
    init_device[ HRDEV_PRINTER ] = Init_HR_Print;	
    next_device[ HRDEV_PRINTER ] = Get_Next_HR_Print;
/*  save_device[ HRDEV_PRINTER ] = Save_HR_Print;	*/
#ifdef HRPRINT_MONOTONICALLY_INCREASING
    dev_idx_inc[ HRDEV_DISK ] = 1;
#endif

/*  device_descr[ HRDEV_PRINTER ] = &describe_printer;	*/

    REGISTER_MIB("host/hr_print", hrprint_variables, variable4, hrprint_variables_oid);
}

/*
  header_hrprint(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/
int
header_hrprint(struct variable *vp,
	       oid *name,
	       size_t *length,
	       int exact,
	       size_t *var_len,
	       WriteMethod **write_method)
{
#define HRPRINT_ENTRY_NAME_LENGTH	11
    oid newname[MAX_OID_LEN];
    int print_idx, LowIndex = -1;
    int result;

    DEBUGMSGTL(("host/hr_print", "var_hrprint: "));
    DEBUGMSGOID(("host/hr_print", name, *length));
    DEBUGMSG(("host/hr_print"," %d\n", exact));

    memcpy( (char *)newname,(char *)vp->name, vp->namelen * sizeof(oid));
	/* Find "next" print entry */

    Init_HR_Print();
    for ( ;; ) {
        print_idx = Get_Next_HR_Print();
        if ( print_idx == -1 )
	    break;
	newname[HRPRINT_ENTRY_NAME_LENGTH] = print_idx;
        result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);
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
        DEBUGMSGTL(("host/hr_print", "... index out of range\n"));
        return(MATCH_FAILED);
    }

    memcpy( (char *)name,(char *)newname, (vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    DEBUGMSGTL(("host/hr_print", "... get print stats "));
    DEBUGMSGOID(("host/hr_print", name, *length));
    DEBUGMSG(("host/hr_print","\n"));
    return LowIndex;
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char *
var_hrprint(struct variable *vp,
	    oid *name,
	    size_t *length,
	    int exact,
	    size_t *var_len,
	    WriteMethod **write_method)
{
    int  print_idx;

    print_idx = header_hrprint(vp, name, length, exact, var_len, write_method);
    if ( print_idx == MATCH_FAILED )
	return NULL;
        

    switch (vp->magic){
	case HRPRINT_STATUS:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = 3;	/* idle */
	    return (u_char *)&long_return;
	case HRPRINT_ERROR:
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = 0;	/* Null string */
	    return (u_char *)&long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_hrprint\n", vp->magic));
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
Init_HR_Print (void)
{
   HRP_index = 1;
}

int
Get_Next_HR_Print (void)
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
