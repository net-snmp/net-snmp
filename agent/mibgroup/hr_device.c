/*
 *  Host Resources MIB - Device group implementation - hr_device.c
 *
 */

#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "host_res.h"
#include "hr_device.h"

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

int Get_Next_Device __P((void));

PFV init_device[ HRDEV_TYPE_MAX ];
PFIV next_device[ HRDEV_TYPE_MAX ];
PFV save_device[ HRDEV_TYPE_MAX ];
int dev_idx_inc[ HRDEV_TYPE_MAX ];

PFS device_descr[ HRDEV_TYPE_MAX ];
PFO device_prodid[ HRDEV_TYPE_MAX ];
PFI device_status[ HRDEV_TYPE_MAX ];
PFI device_errors[ HRDEV_TYPE_MAX ];

int current_type;

void Init_Device __P((void));
int header_hrdevice __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

void	init_hr_device  __P((void))
{
    int i;

		/*
		 * Initially assume no devices
		 *    Insert pointers to initialisation/get_next routines
		 *    for particular device types as they are implemented
		 *	(set up in the appropriate 'init_*()' routine )
		 */

    for ( i=0 ; i<HRDEV_TYPE_MAX ; ++i ) {
	init_device[i]=NULL;
	next_device[i]=NULL;
	save_device[i]=NULL;
	dev_idx_inc[i]=0;	/* Assume random indices */

	device_descr[i]=NULL;
	device_prodid[i]=NULL;
	device_status[i]=NULL;
	device_errors[i]=NULL;
    }
}



#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0


int
header_hrdevice(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRDEV_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int dev_idx, LowIndex=-1, LowType=-1;
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_hrdevice: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));

	
		/*
	 	 *  Find the "next" device entry.
		 *  If we're in the middle of the table, then there's
		 *     no point in examining earlier types of devices,
		 *     so set the starting type to that of the variable
		 *     being queried.
		 *  If we've moved from one column of the table to another,
		 *     then we need to start at the beginning again.
		 *     (i.e. the 'compare' fails to match)
		 *  Similarly if we're at the start of the table
		 *     (i.e. *length is too short to be a full instance)
		 */

    if (( compare( vp->name, (int)vp->namelen, name, (int)vp->namelen ) == 0 ) &&
	( *length > HRDEV_ENTRY_NAME_LENGTH ))
        current_type = (name[HRDEV_ENTRY_NAME_LENGTH]>>HRDEV_TYPE_SHIFT);
    else
        current_type = 0;

    Init_Device();
    for ( ;; ) {
        dev_idx = Get_Next_Device();
        DEBUGP("(index %d ....", dev_idx);
        if ( dev_idx == -1 )
	    break;
	if ( LowType != -1 && LowType < (dev_idx>>HRDEV_TYPE_SHIFT))
	    break;
	newname[HRDEV_ENTRY_NAME_LENGTH] = dev_idx;
        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, newname, *length);
          DEBUGP("%s\n", c_oid);
        }
        result = compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    if ( save_device[current_type] != NULL )
		(*save_device[current_type])();
	    LowIndex = dev_idx;
            break;
	}
        if ((!exact && (result < 0)) &&
		(LowIndex == -1 || dev_idx < LowIndex )) {
	    if ( save_device[current_type] != NULL )
		(*save_device[current_type])();
	    LowIndex = dev_idx;
	    LowType = (dev_idx>>HRDEV_TYPE_SHIFT);
	    if (dev_idx_inc[ LowType ])		/* Increasing indices => now done */
		break;
        }
        
    }

    if ( LowIndex == -1 ) {
        DEBUGP("... index out of range\n");
        return(MATCH_FAILED);
    }

    newname[HRDEV_ENTRY_NAME_LENGTH] = LowIndex;
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP("... get device stats %s\n", c_oid);
    }
    return LowIndex;
}


oid device_type_id[] = { 1,3,6,1,2,1, 25, 3, 1, 99 };		/* hrDeviceType99 */
int device_type_len = sizeof(device_type_id)/sizeof(device_type_id[0]);


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrdevice(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
    int dev_idx, type;
    oid *oid_p;
    static char string[100];

    dev_idx = header_hrdevice(vp, name, length, exact, var_len, write_method);
    if ( dev_idx == MATCH_FAILED )
	    return NULL;
        
    type = (dev_idx>>HRDEV_TYPE_SHIFT);

    switch (vp->magic){
	case HRDEV_INDEX:
	    long_return = dev_idx;
	    return (u_char *)&long_return;
	case HRDEV_TYPE:
	    device_type_id[device_type_len-1] = type;
            *var_len = sizeof(device_type_id);
	    return (u_char *)&device_type_id;
	case HRDEV_DESCR:
	    if ( device_descr[ type ] != NULL )
        	strcpy(string, ((*device_descr[type])(dev_idx)) );
	    else
	        sprintf(string, "a black box of some sort");
	    *var_len = strlen(string);
	    return (u_char *) string;
	case HRDEV_ID:
	    if ( device_prodid[ type ] != NULL )
        	oid_p = ((*device_prodid[type])(dev_idx, var_len));
	    else {
	        oid_p = nullOid;
                *var_len = nullOidLen;
	    }
	    return (u_char *) oid_p;
	case HRDEV_STATUS:
	    if ( device_status[ type ] != NULL )
        	long_return = ((*device_status[type])(dev_idx));
	    else
	        long_return = 2;	/* Assume running */
	    return (u_char *)&long_return;
	case HRDEV_ERRORS:
	    if ( device_errors[ type ] != NULL )
        	long_return = (*device_errors[type])(dev_idx);
	    else
	        long_return = 0;	/* Assume OK */
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


void
Init_Device __P((void))
{
		/*
		 *  Find the first non-NULL initialisation function
		 *    and call it
		 */
    while ( init_device[ current_type ] == NULL )
	if ( ++current_type >= HRDEV_TYPE_MAX)
	    return;
    (*init_device[current_type]) ();
}

int
Get_Next_Device __P((void))
{
    int result = -1;

		/*
		 *  Call the 'next device' function for the current
		 *    type of device
		 *
		 *  TODO:  save the necessary information about that device
		 */
    if ( next_device[ current_type ] != NULL )
        result = (*next_device[current_type]) ();

		/*
		 *  No more devices of the current type.
		 *  Try the next type (if any)
		 */
    if ( result == -1 ) {
	if (++current_type >= HRDEV_TYPE_MAX ) {
	    current_type=0;
	    return -1 ;
	}
	Init_Device();
	return Get_Next_Device();
    }
        return result;
}


