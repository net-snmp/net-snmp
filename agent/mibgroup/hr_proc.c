/*
 *  Host Resources MIB - proc processor group implementation - hr_proc.c
 *
 */

#include <config.h>
#ifdef HAVE_NLIST_H
#include <nlist.h>
#endif

#include "host_res.h"
#include "hr_proc.h"


#define HRPROC_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

extern void  Init_HR_Proc();
extern int   Get_Next_HR_Proc();

#ifndef linux
static struct nlist hrproc_nl[] = {
#define N_AVENRUN     0
#if !defined(hpux) && !defined(solaris2) && !defined(__sgi)
        { "_avenrun"},
#else
        { "avenrun"},
#endif
	{ 0 }
};
#endif

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

#ifndef linux
    init_nlist( hrproc_nl );
#endif
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
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
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

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
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

    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
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
    int     (**write_method)();
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
    if ( KNLookup(hrproc_nl, N_AVENRUN, (char*) avenrun, sizeof(avenrun)) == 0 )
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
Init_HR_Proc()
{
   HRP_index = 1;
}

int
Get_Next_HR_Proc()
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
