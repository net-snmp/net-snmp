/*
 *  Host Resources MIB - Installed Software group implementation - hr_swinst.c
 *
 */

#include <config.h>

#include "host_res.h"
#include "hr_swinst.h"
#include "hr_utils.h"

#include <sys/stat.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_DIRENT_H
#include <dirent.h>
#else
# define dirent direct
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#ifdef HAVE_LIBRPM
#include <rpm/rpmlib.h>
#include <rpm/header.h>
#include <fcntl.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#define HRSWINST_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef hpux	/* This *is* HP-UX specific, I think */
#define	INSTALLED_SW_IN_SYSTEM
#endif

extern struct timeval starttime;

#ifdef	INSTALLED_SW_IN_SYSTEM
extern char HRSW_name[];
#endif

#ifdef HAVE_LIBRPM
static rpmdb	rpm_db;
#endif
	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/
extern void  Init_HR_SWInst();
extern int   Get_Next_HR_SWInst();
extern void  End_HR_SWInst();


void	init_hr_swinst( )
{
#ifdef HAVE_LIBRPM
    rpmReadConfigFiles( NULL, NULL, NULL, 0);
#endif
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

int
header_hrswinst(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
#define HRSWINST_NAME_LENGTH	9
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_hrswinst: %s %d\n", c_oid, exact);
    }

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[HRSWINST_NAME_LENGTH] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}

int
header_hrswInstEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
#define HRSWINST_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int swinst_idx, LowIndex = -1;
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_hrswInstEntry: %s %d\n", c_oid, exact);
    }

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
	/* Find "next" installed software entry */

    Init_HR_SWInst();
    for ( ;; ) {
        swinst_idx = Get_Next_HR_SWInst();
        DEBUGP ("(index %d ....", swinst_idx);
        if ( swinst_idx == -1 )
	    break;
	newname[HRSWINST_ENTRY_NAME_LENGTH] = swinst_idx;
        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, newname, *length);
          DEBUGP ("%s\n", c_oid);
        }
        result = compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowIndex = swinst_idx;
	    /* Save software status information */
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowIndex == -1 || swinst_idx < LowIndex )) {
	    LowIndex = swinst_idx;
	    /* Save software status information */
#ifdef HRSWINST_MONOTONICALLY_INCREASING
            break;
#endif
	}
    }

    End_HR_SWInst();
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
      DEBUGP ("... get installed S/W stats %s\n", c_oid);
    }
    return LowIndex;
}

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrswinst(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method)();
{
    int sw_idx;
    static char string[100];
    struct stat stat_buf;
#ifdef HAVE_LIBRPM
    Header rpm_head;
#endif

    if ( vp->magic < HRSWINST_INDEX ) {
        if (header_hrswinst(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	    return NULL;
    }
    else {
        
        sw_idx = header_hrswInstEntry(vp, name, length, exact, var_len, write_method);
        if ( sw_idx == MATCH_FAILED )
	    return NULL;
        
#ifdef HAVE_LIBRPM
	rpm_head = rpmdbGetRecord( rpm_db, sw_idx );
	rpmdbClose(rpm_db);		/* or only on finishing ? */
	if ( rpm_head == NULL )
	    return NULL;
#endif
    }
    

    switch (vp->magic){
	case HRSWINST_CHANGE:
	case HRSWINST_UPDATE:
#if defined(INSTALLED_SW_IN_SYSTEM) || defined (HAVE_LIBRPM)
#ifdef	INSTALLED_SW_IN_SYSTEM
	    sprintf(string, "/system", HRSW_name);
#endif
#ifdef HAVE_LIBRPM
	    sprintf(string, "%s/packages.rpm", rpmGetVar(RPMVAR_DBPATH));
#endif
	    stat( string, &stat_buf );
	    if ( stat_buf.st_mtime > starttime.tv_sec )
			/* changed 'recently' - i.e. since this agent started */
	        long_return = (stat_buf.st_mtime-starttime.tv_sec)*100;
	    else
	        long_return = 0;	/* predates this agent */
#else
	    long_return = 363136200;
#endif
	    return (u_char *)&long_return;

	case HRSWINST_INDEX:
	    long_return = sw_idx;
	    return (u_char *)&long_return;
	case HRSWINST_NAME:
#ifdef	INSTALLED_SW_IN_SYSTEM
	    sprintf(string, HRSW_name);
#else
#ifdef HAVE_LIBRPM
		/* or 'headerGetEntry? */
	    getEntry(rpm_head, RPMTAG_NAME, NULL, string, NULL );
#else
	    sprintf(string, "installed name");
#endif
#endif
	    *var_len = strlen(string);
	    return (u_char *) string;
	case HRSWINST_ID:
            *var_len = nullOidLen;
	    return (u_char *) nullOid;
	case HRSWINST_TYPE:
	    long_return = 4;	/* application */
	    return (u_char *)&long_return;
	case HRSWINST_DATE:
#ifdef	INSTALLED_SW_IN_SYSTEM
	    sprintf(string, "/system/%s", HRSW_name);
	    stat( string, &stat_buf );
	    return ( date_n_time(&stat_buf.st_mtime, var_len));
#else
#ifdef HAVE_LIBRPM
		/* or 'headerGetEntry? */
	    getEntry(rpm_head, RPMTAG_INSTALLTIME, NULL, string, NULL );
			/* XXX - does this returns a string? */
#else
	    sprintf(string, "earlier");
#endif
	    *var_len = strlen(string);
	    return (u_char *) string;
#endif
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

static int HRSW_index;

#ifdef	INSTALLED_SW_IN_SYSTEM
static DIR *dp = NULL;
static char HRSW_name[100];
#endif


void
Init_HR_SWInst()
{
   HRSW_index = 0;

#ifdef	INSTALLED_SW_IN_SYSTEM
   if ( dp != NULL );
	closedir( dp );
   if ((dp = opendir("/system")) == NULL )
	HRSW_index = -1;
#endif
#ifdef HAVE_LIBRPM
   if (rpmdbOpen( "", &rpm_db, O_RDONLY, 0644) != 0 )
	HRSW_index = -1;
#endif
}

int
Get_Next_HR_SWInst()
{
#ifdef	INSTALLED_SW_IN_SYSTEM
   struct dirent *de_p;
#endif

    if (HRSW_index==-1)
	return -1;

#ifdef	INSTALLED_SW_IN_SYSTEM
    while (( de_p = readdir( dp )) != NULL ) {
	if( de_p->d_name[0] == '.' )
	    continue;

	sprintf(  HRSW_name, de_p->d_name );
	return ++HRSW_index;
    }
#endif
#ifdef HAVE_LIBRPM
    HRSW_index = ((HRSW_index == 0) ? rpmdbFirstRecNum(rpm_db)
				    : rpmdbNextRecNum(rpm_db, HRSW_index));
    if (HRSW_index == 0)
	return -1;	/* failed */
    else
	return HRSW_index;
#endif

    return -1;
}

void
End_HR_SWInst()
{
#ifdef	INSTALLED_SW_IN_SYSTEM
   if ( dp != NULL );
	closedir( dp );
   dp = NULL;
#endif

}
