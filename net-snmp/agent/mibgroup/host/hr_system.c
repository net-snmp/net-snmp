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
void setutent __P((void));
void endutent __P((void));
struct utmp *getutent __P((void));
#endif /* UTMP_FILE */


	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

static int get_load_dev __P((void));
static int count_users __P((void));
extern int count_processes __P((void));
extern int header_hrsys __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_hr_system( )
{
#ifdef NPROC_SYMBOL
  auto_nlist(NPROC_SYMBOL,0,0);
#endif
}


#define MATCH_FAILED	1
#define MATCH_SUCCEEDED	0

int
header_hrsys(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRSYS_NAME_LENGTH	9
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_hrsys: %s %d\n", c_oid, exact);
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
var_hrsys(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
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
static int get_load_dev()
{
     return (HRDEV_DISK<<HRDEV_TYPE_SHIFT);	/* XXX */
}

static int count_users()
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

void setutent __P((void))
{
	if (utmp_file) fclose(utmp_file);
	utmp_file = fopen(UTMP_FILE, "r");
}

void endutent __P((void))
{
	if (utmp_file) {
		fclose(utmp_file);
		utmp_file = NULL;
	}
}

struct utmp *getutent __P((void))
{
	while (fread(&utmp_rec, sizeof(utmp_rec), 1, utmp_file) == 1)
	    if (*utmp_rec.ut_name && *utmp_rec.ut_line)
		return &utmp_rec;
	return NULL;
}

#endif /* UTMP_FILE */
