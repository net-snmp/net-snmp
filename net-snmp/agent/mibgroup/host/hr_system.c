/*
 *  Host Resources MIB - system group implementation - hr_system.c
 *
 */

#include <config.h>

#include "host.h"
#include "host_res.h"
#include "hr_system.h"
#include "hr_utils.h"
#include "auto_nlist.h"
#include "../../../snmplib/system.h"

#ifdef HAVE_SYS_PROC_H
#include <sys/param.h>
#include "sys/proc.h"
#endif
#include <utmp.h>
#ifdef linux
#include "linux/tasks.h"
#endif

#ifdef UTMP_FILE
void setutent (void);
void endutent (void);
struct utmp *getutent (void);
#endif /* UTMP_FILE */


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

static int get_load_dev (void);
static int count_users (void);
extern int count_processes (void);
extern int header_hrsys (struct variable *,oid *, int *, int, int *, WriteMethod **);


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void init_hr_system(void)
{
#ifdef NPROC_SYMBOL
  auto_nlist(NPROC_SYMBOL,0,0);
#endif
}


#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

/*
  header_hrsys(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
*/

int
header_hrsys(struct variable *vp,
	     oid *name,
	     int *length,
	     int exact,
	     int *var_len,
	     WriteMethod **write_method)
{
#define HRSYS_NAME_LENGTH	9
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGMSGTL(("host/hr_system", "var_hrsys: %s %d\n", c_oid, exact));
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[HRSYS_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
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
var_hrsys(struct variable *vp,
	  oid *name,
	  int *length,
	  int exact,
	  int *var_len,
	  WriteMethod **write_method)
{
    static char string[100];
    time_t	now;
#ifdef linux
    FILE       *fp;
#endif
#if defined(NPROC_SYMBOL) && !defined(NR_TASKS)
    int		nproc;
#endif

    if (header_hrsys(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	return NULL;

    switch (vp->magic){
	case HRSYS_UPTIME:
	    long_return = get_uptime();
	    return (u_char *)&long_return;
	case HRSYS_DATE:
	    (void*) time( &now );
	    return (u_char *) date_n_time( &now, var_len );
	case HRSYS_LOAD_DEV:
	    long_return = get_load_dev();
	    return (u_char *)&long_return;
	case HRSYS_LOAD_PARAM:
#ifdef linux
	    fp = fopen("/proc/cmdline", "r");
	    fgets( string, 100, fp);
	    fclose(fp);
#else
	    sprintf(string, "ask Dave");	/* XXX */
#endif
	    *var_len = strlen(string);
	    return (u_char *) string;
	case HRSYS_USERS:
	    long_return = count_users();
	    return (u_char *)&long_return;
	case HRSYS_PROCS:
#if USING_HOST_HR_SWRUN_MODULE
	    long_return = count_processes();
#else
	    long_return = 0;
#endif
	    return (u_char *)&long_return;
	case HRSYS_MAXPROCS:
#ifdef NR_TASKS
	    long_return = NR_TASKS;	/* <linux/tasks.h> */
#else
#ifdef NPROC_SYMBOL
	    auto_nlist(NPROC_SYMBOL, (char *)&nproc, sizeof (int));
	    long_return = nproc;
#else
	    long_return = 0;
#endif
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

		/*
		 *  Return the DeviceIndex corresponding
		 *   to the boot device
		 */
static int get_load_dev(void)
{
     return (HRDEV_DISK<<HRDEV_TYPE_SHIFT);	/* XXX */
}

static int count_users(void)
{
     int total=0;
     struct utmp *utmp_p;

     setutent();
     while ( (utmp_p = getutent()) != NULL ) {
#ifndef UTMP_HAS_NO_TYPE
	if ( utmp_p->ut_type == USER_PROCESS )
#endif
	    ++total;
     }
     endutent();
     return total;
}

#ifdef UTMP_FILE

static FILE *utmp_file;
static struct utmp utmp_rec;

void setutent (void)
{
	if (utmp_file) fclose(utmp_file);
	utmp_file = fopen(UTMP_FILE, "r");
}

void endutent (void)
{
	if (utmp_file) {
		fclose(utmp_file);
		utmp_file = NULL;
	}
}

struct utmp *getutent (void)
{
	while (fread(&utmp_rec, sizeof(utmp_rec), 1, utmp_file) == 1)
	    if (*utmp_rec.ut_name && *utmp_rec.ut_line)
		return &utmp_rec;
	return NULL;
}

#endif /* UTMP_FILE */
