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
#ifdef HAVE_PKGLOCS_H
#include <pkglocs.h>
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

int header_hrswinst (struct variable *,oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *,oid *,int) );
int header_hrswInstEntry (struct variable *,oid *, int *, int, int *, int (**write) (int, u_char *, u_char, int, u_char *,oid *,int) );

       char *HRSW_directory = NULL;

extern struct timeval starttime;

#ifdef HAVE_LIBRPM
static rpmdb	rpm_db = NULL;
#else
extern char  HRSW_name[];
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/
extern void  Init_HR_SWInst (void);
extern int   Get_Next_HR_SWInst (void);
extern void  End_HR_SWInst (void);
extern void  Save_HR_SW_info (void);


void init_hr_swinst(void)
{
	/* Read settings from config file,
	    or take system-specific defaults */

    if ( HRSW_directory == NULL ) {
#ifdef PKGLOC
	HRSW_directory = PKGLOC;
			/* Description from HRSW_dir/.../pkginfo: DESC= */
#endif
#ifdef hpux9
	HRSW_directory = "/system";
			/* Description from HRSW_dir/.../index:   fd: */
#endif
#ifdef hpux10
	HRSW_directory = "/var/adm/sw/products";
			/* Description from HRSW_dir/.../pfiles/INDEX: title */
#endif
#ifdef freebsd2
	HRSW_directory = "/var/db/pkg";
#endif

#ifdef HAVE_LIBRPM
	rpmReadConfigFiles( NULL, NULL, NULL, 0);
#endif
    }

#ifndef HAVE_LIBRPM
    strcpy(HRSW_name, "[installed name]");	/* default name */
#endif
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

/*
  header_hrswinst(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
*/
  
int
header_hrswinst(struct variable *vp,
		oid *name,
		int *length,
		int exact,
		int *var_len,
		int (**write_method) (int, u_char *, u_char, int, u_char *, oid *, int))
{
#define HRSWINST_NAME_LENGTH	9
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGMSGTL(("host/hr_swinst", "var_hrswinst: %s %d\n", c_oid, exact));
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[HRSWINST_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}

int
header_hrswInstEntry(struct variable *vp,
		     oid *name,
		     int *length,
		     int exact,
		     int *var_len,
		     int (**write_method) (int, u_char *, u_char, int, u_char *, oid *, int))
{
#define HRSWINST_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int swinst_idx, LowIndex = -1;
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGMSGTL(("host/hr_swinst", "var_hrswInstEntry: %s %d\n", c_oid, exact));
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
	/* Find "next" installed software entry */

    Init_HR_SWInst();
    for ( ;; ) {
        swinst_idx = Get_Next_HR_SWInst();
        DEBUGMSG(("host/hr_swinst", "(index %d ....", swinst_idx));
        if ( swinst_idx == -1 )
	    break;
	newname[HRSWINST_ENTRY_NAME_LENGTH] = swinst_idx;
        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, newname, *length);
          DEBUGMSGTL(("host/hr_swinst", "%s\n", c_oid));
        }
        result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowIndex = swinst_idx;
	    Save_HR_SW_info();
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowIndex == -1 || swinst_idx < LowIndex )) {
	    LowIndex = swinst_idx;
	    Save_HR_SW_info();
#ifdef HRSWINST_MONOTONICALLY_INCREASING
            break;
#endif
	}
    }

    End_HR_SWInst();
    if ( LowIndex == -1 ) {
        DEBUGMSGTL(("host/hr_swinst", "... index out of range\n"));
        return(MATCH_FAILED);
    }

    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGMSGTL(("host/hr_swinst", "... get installed S/W stats %s\n", c_oid));
    }
    return LowIndex;
}

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrswinst(struct variable *vp,
	     oid *name,
	     int *length,
	     int exact,
	     int *var_len,
	     int (**write_method) (int, u_char *, u_char, int, u_char *, oid *, int))
{
    int sw_idx=0;
    static char string[256];
    u_char *ret = NULL;
    struct stat stat_buf;
#ifdef HAVE_LIBRPM
    Header h = NULL;
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
	if (rpm_db == NULL) {
	    Init_HR_SWInst();
	    if (rpm_db == NULL)
		return NULL;
	}
	h = rpmdbGetRecord( rpm_db, sw_idx );
	if ( h == NULL )
	    return NULL;
#endif
    }

    switch (vp->magic){
	case HRSWINST_CHANGE:
	case HRSWINST_UPDATE:
	    string[0] = '\0';
#ifdef HAVE_LIBRPM
	    sprintf(string, "%s/packages.rpm", rpmGetVar(RPMVAR_DBPATH));
#else
	    if ( HRSW_directory )
		strcpy( string, HRSW_directory);
#endif

	    if ( *string ) {
		stat( string, &stat_buf );
		if ( stat_buf.st_mtime > starttime.tv_sec )
			/* changed 'recently' - i.e. since this agent started */
		    long_return = (stat_buf.st_mtime-starttime.tv_sec)*100;
		else
		    long_return = 0;	/* predates this agent */
	    } else
		long_return = 363136200;
	    ret = (u_char *) &long_return;
	    break;

	case HRSWINST_INDEX:
	    long_return = sw_idx;
	    ret = (u_char *) &long_return;
	    break;
	case HRSWINST_NAME:
	{
#ifdef HAVE_LIBRPM
	    char *cp;
	    int type;
	    string[0] = '\0';
	    if (headerGetEntry(h, RPMTAG_NAME, &type, (void **) &cp, NULL) && cp != NULL) {
		strcpy(string, cp);
		if(type == RPM_STRING_ARRAY_TYPE || type == RPM_I18NSTRING_TYPE)
		    free(cp);
	    }
#else
	    sprintf(string, HRSW_name);
			/* This will be unchanged from the initial "null"
			   value, if HRSW_directory is not defined */
#endif
	    *var_len = strlen(string);
	    ret = (u_char *) string;
	}   break;
	case HRSWINST_ID:
            *var_len = nullOidLen;
	    ret = (u_char *) nullOid;
	    break;
	case HRSWINST_TYPE:
	    long_return = 4;	/* application */
	    ret = (u_char *) &long_return;
	    break;
	case HRSWINST_DATE:
	{
#ifdef HAVE_LIBRPM
	    int_32 *rpm_data;
	    headerGetEntry(h, RPMTAG_INSTALLTIME, NULL, (void **) &rpm_data, NULL);
            if (rpm_data != NULL) {
              time_t installTime = *rpm_data;
              ret = date_n_time(&installTime, var_len);
            } else {
              ret = date_n_time(0, var_len);
            }
#else
	    if ( HRSW_directory ) {
		sprintf(string, "%s/%s", HRSW_directory, HRSW_name);
		stat( string, &stat_buf );
		ret = date_n_time(&stat_buf.st_mtime, var_len);
	    } else {
		sprintf(string, "back in the mists of time");
		*var_len = strlen(string);
		ret = (u_char *) string;
	    }
#endif
	}   break;
	default:
	    ERROR_MSG("");
	    ret = NULL;
	    break;
    }
    if (h)
	headerFree(h);
    return ret;
}


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

static int HRSW_index;

#ifndef HAVE_LIBRPM
static DIR *dp = NULL;
static struct dirent *de_p;
static char HRSW_name[100];
#endif


void
Init_HR_SWInst (void)
{
    HRSW_index = 0;

#ifdef HAVE_LIBRPM
    if (rpm_db != NULL)
	return;
    if (rpmdbOpen( "", &rpm_db, O_RDONLY, 0644) != 0 )
	HRSW_index = -1;
#else
    if ( HRSW_directory ) {
        if ( dp != NULL ) {
            closedir( dp );
            dp = NULL;
        }
        if ((dp = opendir(HRSW_directory)) == NULL )
            HRSW_index = -1;
    }
    else
	HRSW_index = -1;
#endif
}

int
Get_Next_HR_SWInst (void)
{
    if (HRSW_index == -1)
	return -1;

#ifdef HAVE_LIBRPM
    HRSW_index = ((HRSW_index == 0) ? rpmdbFirstRecNum(rpm_db)
				    : rpmdbNextRecNum(rpm_db, HRSW_index));
    if (HRSW_index == 0)
	return -1;	/* failed */
    else
	return HRSW_index;
#else
    if ( HRSW_directory ) {
	while (( de_p = readdir( dp )) != NULL ) {
	    if( de_p->d_name[0] == '.' )
		continue;

		/* Ought to check for "properly-formed" entry */

	    return ++HRSW_index;
	}
    }
#endif

    return -1;
}

void
Save_HR_SW_info (void)
{
#ifndef HAVE_LIBRPM
    sprintf(  HRSW_name, de_p->d_name );
#endif
}

void
End_HR_SWInst (void)
{
#ifdef HAVE_LIBRPM
    rpmdbClose(rpm_db);		/* or only on finishing ? */
    rpm_db = NULL;
#else
   if ( dp != NULL )
	closedir( dp );
   dp = NULL;
#endif
}
