/*
 *  Host Resources MIB - Running Software group implementation - hr_swrun.c
 *	(also includes Running Software Performance group )
 *
 */

#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#include <fcntl.h>

#include "host_res.h"
#include "hr_swrun.h"
#include "auto_nlist.h"

#include <ctype.h>
#if HAVE_SYS_PSTAT_H
#include <sys/pstat.h>
#endif
#if HAVE_SYS_PROC_H
#include <sys/proc.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
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

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <stdio.h>

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/
       void  Init_HR_SWRun __P((void));
       int   Get_Next_HR_SWRun __P((void));
       void  End_HR_SWRun __P((void));
       int header_hrswrun __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));
       int header_hrswrunEntry __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));

#ifndef linux
static int LowProcIndex;
#endif

#ifndef linux
#ifndef hpux10
extern struct proc *proc_table;
#else
extern struct pst_status *proc_table;
#endif
static int current_proc_entry;
#endif

void	init_hr_swrun( )
{
  auto_nlist( PROC_SYMBOL,0,0 );
  auto_nlist( NPROC_SYMBOL,0,0 );
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

int
header_hrswrun(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRSWRUN_NAME_LENGTH	9
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_hrswrun: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[HRSWRUN_NAME_LENGTH] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}

int
header_hrswrunEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRSWRUN_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int pid, LowPid=-1;
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_hrswrunEntry: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));

		/*
	 	 *  Find the "next" running process
		 */
    Init_HR_SWRun();
    for ( ;; ) {
        pid = Get_Next_HR_SWRun();
#ifndef linux
        DEBUGP ("(index %d (entry #%d) ....", pid, current_proc_entry);
#endif
        if ( pid == -1 )
	    break;
	newname[HRSWRUN_ENTRY_NAME_LENGTH] = pid;
        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, newname, *length);
          DEBUGP ("%s", c_oid);
        }
        result = compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowPid = pid;
#ifndef linux
	    LowProcIndex = current_proc_entry;
#endif
DEBUGP (" saved\n");
	    /* Save process status information */
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowPid == -1 || pid < LowPid )) {
	    LowPid = pid;
#ifndef linux
	    LowProcIndex = current_proc_entry;
#endif
	    /* Save process status information */
DEBUGP (" saved");
	}
DEBUGP ("\n");
    }

    if ( LowPid == -1 ) {
        DEBUGP ("... index out of range\n");
        return(MATCH_FAILED);
    }

    newname[HRSWRUN_ENTRY_NAME_LENGTH] = LowPid;
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    sprint_objid (c_oid, name, *length);
    DEBUGP ("... get process stats %s\n", c_oid);
    return LowPid;
}

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrswrun(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
    int pid=0;
    static char string[100];
#ifdef HAVE_SYS_PSTAT_H
    struct pst_status proc_buf;
#endif
#ifdef linux
    FILE *fp;
    char buf[256];
    int i;
#endif
    char *cp;

    if ( vp->magic == HRSWRUN_OSINDEX ) {
        if (header_hrswrun(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	    return NULL;
    }
    else {
        
        pid = header_hrswrunEntry(vp, name, length, exact, var_len, write_method);
        if ( pid == MATCH_FAILED )
	    return NULL;
    }

#ifdef HAVE_SYS_PSTAT_H
    if (pstat_getproc( &proc_buf, sizeof(struct pst_status), 0, pid ) == -1)
	    return NULL;
#endif
        

    switch (vp->magic){
	case HRSWRUN_OSINDEX:
	    long_return = 1;		/* Probably! */
	    return (u_char *)&long_return;

	case HRSWRUN_INDEX:
	    long_return = pid;
	    return (u_char *)&long_return;
	case HRSWRUN_NAME:
#ifdef HAVE_SYS_PSTAT_H
	    sprintf(string, "%s", proc_buf.pst_cmd);
	    cp = strchr( string, ' ');
	    if ( cp != NULL )
		*cp = '\0';
#else
#ifdef linux
	    sprintf( string, "/proc/%d/status", pid );
	    fp = fopen( string, "r");
	    fgets( buf, 100, fp );	/* Name: process name */
	    cp = buf;
	    while ( *cp != ':' )
		++cp;
	    ++cp;
	    while ( isspace( *cp ))
		++cp;
	    strcpy( string, cp );
            fclose(fp);
#else
	    sprintf(string, "process name");
#endif
#endif
	    *var_len = strlen(string);
	    return (u_char *) string;
	case HRSWRUN_ID:
            *var_len = nullOidLen;
	    return (u_char *) nullOid;
	case HRSWRUN_PATH:
#ifdef HAVE_SYS_PSTAT_H
		/* Path not available - use argv[0] */
	    sprintf(string, "%s", proc_buf.pst_cmd);
	    cp = strchr( string, ' ');
	    if ( cp != NULL )
		*cp = '\0';
#else
#ifdef linux
	    sprintf( string, "/proc/%d/cmdline", pid );
	    fp = fopen( string, "r");
	    fgets( buf, 100, fp );	/* argv[0] '\0' argv[1] '\0' .... */
	    strcpy( string, buf );
            fclose(fp);
#else
	    sprintf(string, "/bin/wombat");
#endif
#endif
	    *var_len = strlen(string);
	    return (u_char *) string;
	case HRSWRUN_PARAMS:
#ifdef HAVE_SYS_PSTAT_H
	    cp = strchr( proc_buf.pst_cmd, ' ');
	    if ( cp != NULL ) {
		cp++;
		sprintf(string, "%s", cp);
	    }
	    else
		string[0] = '\0';
#else
#ifdef linux
	    sprintf( string, "/proc/%d/cmdline", pid );
	    fp = fopen( string, "r");
	    memset( buf,(0), 100 );
	    fgets( buf, 100, fp );   /* argv[0] '\0' argv[1] '\0' .... */

		/* Skip over argv[0] */
	    cp = buf;
	    while ( *cp )
		++cp;
	    ++cp;
		/* Now join together separate arguments. */
	    while ( 1 ) {
	        while ( *cp )
		    ++cp;
		if ( *(cp+1) == '\0' )
		    break;	/* '\0''\0' => End of command line */
		*cp = ' ';
	    }	

	    cp = buf;
	    while ( *cp )
		++cp;
	    ++cp;
	    strcpy( string, cp );
            fclose(fp);
#else
	    sprintf(string, "-h -q -v");
#endif
#endif
	    *var_len = strlen(string);
	    return (u_char *) string;
	case HRSWRUN_TYPE:
#ifdef PID_MAXSYS
	    if ( pid < PID_MAXSYS )
		long_return = 2;	/* operatingSystem */
	    else
#endif
		long_return = 4;	/* application */
	    return (u_char *)&long_return;
	case HRSWRUN_STATUS:
#ifndef linux
#ifdef hpux10
	    switch ( proc_table[LowProcIndex].pst_stat ) {
		case PS_STOP:
	    		long_return = 3;	/* notRunnable */
			break;
		case PS_SLEEP:
	    		long_return = 2;	/* runnable */
			break;
		case PS_RUN:
	    		long_return = 1;	/* running */
			break;
		case PS_ZOMBIE:
		case PS_IDLE:
		case PS_OTHER:
		default:
	    		long_return = 4;	/* invalid */
			break;
	    }
#else
	    switch ( proc_table[LowProcIndex].p_stat ) {
		case SSTOP:
	    		long_return = 3;	/* notRunnable */
			break;
		case 0:
		case SSLEEP:
#ifdef SWAIT
		case SWAIT:
#endif
	    		long_return = 2;	/* runnable */
			break;
		case SRUN:
#ifdef SONPROC
		case SONPROC:
#endif
	    		long_return = 1;	/* running */
			break;
		case SIDL:
		case SZOMB:
		default:
	    		long_return = 4;	/* invalid */
			break;
	    }
#endif
#else
	    sprintf( string, "/proc/%d/stat", pid );
	    fp = fopen( string, "r");
	    fgets( buf, 250, fp );
	    cp = buf;
	    for ( i = 0 ; i < 2 ; ++i ) {	/* skip two fields */
		while ( *cp != ' ')
		    ++cp;
		++cp;
	    }

	    switch ( *cp ) {
		case 'R':
	    		long_return = 1;	/* running */
			break;
		case 'S':
	    		long_return = 2;	/* runnable */
			break;
		case 'D':
		case 'T':
	    		long_return = 3;	/* notRunnable */
			break;
		case 'Z':
		default:
	    		long_return = 4;	/* invalid */
			break;
	    }
            fclose(fp);
#endif
	    return (u_char *)&long_return;

	case HRSWRUNPERF_CPU:
#ifdef HAVE_SYS_PSTAT_H
	    long_return = proc_buf.pst_cptickstotal;
#else
#ifndef linux
				/*
				 * Not convinced this is right, but....
				 */
#ifdef solaris2
	    long_return = proc_table[LowProcIndex].p_utime*100 +
	    		  proc_table[LowProcIndex].p_stime*100;
#else
	    long_return = proc_table[LowProcIndex].p_utime.tv_sec*100 +
			  proc_table[LowProcIndex].p_utime.tv_usec/10000 +
	    		  proc_table[LowProcIndex].p_stime.tv_sec*100 +
			  proc_table[LowProcIndex].p_stime.tv_usec/10000;
#endif
#else
	    sprintf( string, "/proc/%d/stat", pid );
	    fp = fopen( string, "r");
	    fgets( buf, 250, fp );
	    cp = buf;
	    for ( i = 0 ; i < 13 ; ++i ) {	/* skip 13 fields */
		while ( *cp != ' ')
		    ++cp;
		++cp;
	    }

	    long_return = atoi( cp );		/* utime */

	    while ( *cp != ' ' )
		++cp;
	    ++cp;
	    long_return += atoi( cp );		/* + stime */
            fclose(fp);
#endif
#endif
	    return (u_char *)&long_return;
	case HRSWRUNPERF_MEM:
#ifdef HAVE_SYS_PSTAT_H
	    long_return = (proc_buf.pst_rssize << PGSHIFT)/1024;
#else
#ifdef linux
	    sprintf( string, "/proc/%d/stat", pid );
	    fp = fopen( string, "r");
	    fgets( buf, 250, fp );
	    cp = buf;
	    for ( i = 0 ; i < 23 ; ++i ) {	/* skip 23 fields */
		while ( *cp != ' ')
		    ++cp;
	        ++cp;
	    }
	    long_return = atoi( cp );		/* rss */
            fclose(fp);
#else
	    long_return = 16*1024;	/* XXX - 16M! */
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

#ifndef linux
static int nproc;
#ifndef hpux10
struct proc *proc_table;
#else
struct pst_status *proc_table;
struct pst_dynamic pst_dyn;
#endif

void
Init_HR_SWRun __P((void))
{
    int proc_table_base;
    int bytes;

#if defined(hpux10)
    pstat_getdynamic( &pst_dyn, sizeof( struct pst_dynamic ),
			1, 0 );
    nproc = pst_dyn.psd_activeprocs ;
    bytes = nproc*sizeof(struct pst_status);
#elif defined(solaris2)
    auto_nlist(NPROC_SYMBOL, (char *)&nproc, sizeof(int));
    bytes = nproc*sizeof(struct proc);
#else
    auto_nlist(NPROC_SYMBOL, (char *)&nproc, sizeof(int));
    bytes = nproc*sizeof(struct proc);
#endif
    if ((proc_table=(struct pst_status *) malloc(bytes)) == NULL ) {
	current_proc_entry = nproc+1;
	return;
    }

#if defined(hpux10)
    pstat_getproc( proc_table, sizeof( struct pst_status ),
			nproc, 0 );
#elif defined(solaris2)
    {   struct proc *pp;
	kvm_t *kd;
	kd = kvm_open(NULL, NULL, NULL, O_RDONLY, "oops");
	current_proc_entry = 0;
	kvm_setproc(kd);
	while ((pp = kvm_nextproc(kd)) != NULL && current_proc_entry < nproc)
	    proc_table[current_proc_entry++] = *pp;
	kvm_close(kd);
    }
#else
    auto_nlist(PROC_SYMBOL, (char *)&proc_table_base, sizeof(proc_table_base));
    klookup( proc_table_base, (char *)proc_table, bytes);
#endif
    current_proc_entry = 0;
}

int
Get_Next_HR_SWRun __P((void))
{
    while ( current_proc_entry < nproc ) {
#ifndef hpux10
	if ( proc_table[current_proc_entry].p_stat != 0 )
	    return proc_table[current_proc_entry++].p_pid;
	else
	    ++current_proc_entry;
#else
	    return proc_table[current_proc_entry++].pst_pid;
#endif

    }
    End_HR_SWRun();
    return -1;
}
	
void
End_HR_SWRun __P((void))
{
    free(proc_table);
    current_proc_entry = nproc+1;
}

#else /* linux */

DIR *procdir = NULL;
struct dirent *procentry_p;

void
Init_HR_SWRun __P((void))
{
    if ( procdir != NULL )
        closedir( procdir );
    procdir = opendir("/proc");
}

int
Get_Next_HR_SWRun __P((void))
{
   int pid;
   procentry_p = readdir( procdir );

   if ( procentry_p == NULL )
	return -1;

   pid = atoi(procentry_p->d_name);
   if ( pid == 0 )
	return( Get_Next_HR_SWRun());
   return -1;
}

void
End_HR_SWRun __P((void))
{
   closedir( procdir );
   procdir = NULL;
}

#endif

int count_processes  __P((void))
{
#ifndef linux
    int i;
#endif
    int total=0;

    Init_HR_SWRun();
#ifdef hpux10
    total = nproc;
#else
#ifndef linux
    for ( i = 0 ; i<nproc ; ++i ) {
	if ( proc_table[i].p_stat != 0 )
#else
    while ( Get_Next_HR_SWRun() != -1  ) {
#endif
	    ++total;
    }
#endif /* !hpux10 */
    End_HR_SWRun();
    return total;
}

