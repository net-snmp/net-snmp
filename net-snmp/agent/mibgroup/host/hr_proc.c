/*
 *  Host Resources MIB - proc processor group implementation - hr_proc.c
 *
 */

#include <config.h>

#include "host_res.h"
#include "hr_proc.h"
#include "auto_nlist.h"

#define HRPROC_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

extern void  Init_HR_Proc __P((void));
extern int   Get_Next_HR_Proc __P((void));
int header_hrproc __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_hr_proc( )
{
    init_device[ HRDEV_PROC ] = &Init_HR_Proc;	
    next_device[ HRDEV_PROC ] = &Get_Next_HR_Proc;
#ifdef HRPROC_MONOTONICALLY_INCREASING
    dev_idx_inc[ HRDEV_PROC ] = 1;
#endif

    auto_nlist( LOADAVE_SYMBOL,0,0 );
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

int
header_hrproc(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRPROC_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int proc_idx, LowIndex=-1;
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_hrproc: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
	/* Find "next" proc entry */

    Init_HR_Proc();
    for ( ;; ) {
        proc_idx = Get_Next_HR_Proc();
        if ( proc_idx == -1 )
	    break;
	newname[HRPROC_ENTRY_NAME_LENGTH] = proc_idx;
        result = compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowIndex = proc_idx;
	    /* Save processor status information */
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowIndex == -1 || proc_idx < LowIndex )) {
	    LowIndex = proc_idx;
	    /* Save processor status information */
#ifdef HRPROC_MONOTONICALLY_INCREASING
            break;
#endif
	}
    }

    if ( LowIndex == -1 ) {
        DEBUGP ("... index out of range\n");
        return(MATCH_FAILED);
    }

    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("... get proc stats %s\n", c_oid);
    }
    return LowIndex;
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrproc(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
    int  proc_idx;
#if defined(sun) || defined(__alpha)
  long   avenrun[3];
#else
#ifndef linux
  double avenrun[3];
#endif
#endif
 

    proc_idx = header_hrproc(vp, name, length, exact, var_len, write_method);
    if ( proc_idx == MATCH_FAILED )
	return NULL;

#ifndef linux
    if (auto_nlist(LOADAVE_SYMBOL, (char*) avenrun, sizeof(avenrun)) == 0 )
	return NULL;
#endif

    switch (vp->magic){
	case HRPROC_ID:
            *var_len = nullOidLen;
	    return (u_char *) nullOid;
	case HRPROC_LOAD:
			/*
			 * XXX
			 *   To calculate this, we need to compare
			 *   successive values of the kernel array
			 *   '_cp_times', and calculate the resulting
			 *   percentage changes.
			 *     This calculation needs to be performed
			 *   regularly - perhaps as a background process.
			 *
			 *   See the source to 'top' for full details.
			 *
			 * The linux SNMP HostRes implementation
			 *   uses 'avenrun[0]*100' as an approximation.
			 *   This is less than accurate, but has the
			 *   advantage of being simple to implement!
			 *
			 * I'm also assuming a single processor
			 */
#ifndef linux
	    long_return = avenrun[0] * 100;	/* 1 minute average */
	    if ( long_return > 100 )
		long_return=100;
#else
	    long_return=42;
#endif
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

static int HRP_index;

void
Init_HR_Proc __P((void))
{
   HRP_index = 1;
}

int
Get_Next_HR_Proc __P((void))
{
		/*
		 * Silly question time:
		 *   How do you detect processors?
		 *   Assume we've just got one.
		 */

    if ( HRP_index < 2 ) 
        return ( HRDEV_PROC << HRDEV_TYPE_SHIFT ) + HRP_index++;
    else
        return -1;
}
