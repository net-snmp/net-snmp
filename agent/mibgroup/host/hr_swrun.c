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
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sys/param.h>
#include <ctype.h>
#if HAVE_SYS_PSTAT_H
#include <sys/pstat.h>
#endif
#if HAVE_SYS_USER_H
#ifdef solaris2
#define _KMEMUSER
#endif
#include <sys/user.h>
#endif
#if HAVE_SYS_PROC_H
#include <sys/proc.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
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

#if _SLASH_PROC_METHOD_
#include <procfs.h>
#endif

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <stdio.h>

#include "host_res.h"
#include "hr_swrun.h"
#include "auto_nlist.h"
#include "kernel.h"
#if solaris2
#include "kernel_sunos5.h"
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/
void  Init_HR_SWRun (void);
int   Get_Next_HR_SWRun (void);
void  End_HR_SWRun (void);
int header_hrswrun (struct variable *,oid *, size_t *, int, size_t *, WriteMethod **);
int header_hrswrunEntry (struct variable *,oid *, size_t *, int, size_t *, WriteMethod **);

#ifndef linux
static int LowProcIndex;
#endif
#ifdef hpux10
struct pst_status *proc_table;
struct pst_dynamic pst_dyn;
#elif HAVE_KVM_GETPROCS
struct kinfo_proc *proc_table;
#elif defined(solaris2)
int *proc_table;
#else
struct proc *proc_table;
#endif
int current_proc_entry;


#define	HRSWRUN_OSINDEX		1

#define	HRSWRUN_INDEX		2
#define	HRSWRUN_NAME		3
#define	HRSWRUN_ID		4
#define	HRSWRUN_PATH		5
#define	HRSWRUN_PARAMS		6
#define	HRSWRUN_TYPE		7
#define	HRSWRUN_STATUS		8

#define	HRSWRUNPERF_CPU		9
#define	HRSWRUNPERF_MEM		10

struct variable4 hrswrun_variables[] = {
    { HRSWRUN_OSINDEX,   ASN_INTEGER, RONLY, var_hrswrun, 1, {1}},
    { HRSWRUN_INDEX,     ASN_INTEGER, RONLY, var_hrswrun, 3, {2,1,1}},
    { HRSWRUN_NAME,    ASN_OCTET_STR, RONLY, var_hrswrun, 3, {2,1,2}},
    { HRSWRUN_ID,      ASN_OBJECT_ID, RONLY, var_hrswrun, 3, {2,1,3}},
    { HRSWRUN_PATH,    ASN_OCTET_STR, RONLY, var_hrswrun, 3, {2,1,4}},
    { HRSWRUN_PARAMS,  ASN_OCTET_STR, RONLY, var_hrswrun, 3, {2,1,5}},
    { HRSWRUN_TYPE,      ASN_INTEGER, RONLY, var_hrswrun, 3, {2,1,6}},
    { HRSWRUN_STATUS,    ASN_INTEGER, RONLY, var_hrswrun, 3, {2,1,7}}
};

struct variable4 hrswrunperf_variables[] = {
    { HRSWRUNPERF_CPU,   ASN_INTEGER, RONLY, var_hrswrun, 3, {1,1,1}},
    { HRSWRUNPERF_MEM,   ASN_INTEGER, RONLY, var_hrswrun, 3, {1,1,2}}
};

oid hrswrun_variables_oid[]     = { 1,3,6,1,2,1,25,4 };
oid hrswrunperf_variables_oid[] = { 1,3,6,1,2,1,25,5 };


void init_hr_swrun(void)
{
#ifdef PROC_SYMBOL
  auto_nlist( PROC_SYMBOL,0,0 );
#endif
#ifdef NPROC_SYMBOL
  auto_nlist( NPROC_SYMBOL,0,0 );
#endif

  proc_table = 0;

    REGISTER_MIB("host/hr_swrun", hrswrun_variables, variable4, hrswrun_variables_oid);
    REGISTER_MIB("host/hr_swrun", hrswrunperf_variables, variable4, hrswrunperf_variables_oid);
}

/*
  header_hrswrun(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
  
*/

int
header_hrswrun(struct variable *vp,
	       oid *name,
	       size_t *length,
	       int exact,
	       size_t *var_len,
	       WriteMethod **write_method)
{
#define HRSWRUN_NAME_LENGTH	9
    oid newname[MAX_OID_LEN];
    int result;

    DEBUGMSGTL(("host/hr_swrun", "var_hrswrun: "));
    DEBUGMSGOID(("host/hr_swrun", name, *length));
    DEBUGMSG(("host/hr_swrun"," %d\n", exact));

    memcpy( (char *)newname,(char *)vp->name, vp->namelen * sizeof(oid));
    newname[HRSWRUN_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, (vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}

int
header_hrswrunEntry(struct variable *vp,
		    oid *name,
		    size_t *length,
		    int exact,
		    size_t *var_len,
		    WriteMethod **write_method)
{
#define HRSWRUN_ENTRY_NAME_LENGTH	11
    oid newname[MAX_OID_LEN];
    int pid, LowPid=-1;
    int result;

    DEBUGMSGTL(("host/hr_swrun", "var_hrswrunEntry: "));
    DEBUGMSGOID(("host/hr_swrun", name, *length));
    DEBUGMSG(("host/hr_swrun"," %d\n", exact));

    memcpy( (char *)newname,(char *)vp->name, vp->namelen * sizeof(oid));

		/*
	 	 *  Find the "next" running process
		 */
    Init_HR_SWRun();
    for ( ;; ) {
        pid = Get_Next_HR_SWRun();
#ifndef linux
        DEBUGMSG(("host/hr_swrun",
                  "(index %d (entry #%d) ....", pid, current_proc_entry));
#endif
        if ( pid == -1 )
	    break;
	newname[HRSWRUN_ENTRY_NAME_LENGTH] = pid;
    DEBUGMSGOID(("host/hr_swrun", newname, *length));
    DEBUGMSG(("host/hr_swrun","\n"));
        result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowPid = pid;
#ifndef linux
	    LowProcIndex = current_proc_entry-1;
#endif
DEBUGMSGTL(("host/hr_swrun", " saved\n"));
	    /* Save process status information */
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowPid == -1 || pid < LowPid )) {
	    LowPid = pid;
#ifndef linux
	    LowProcIndex = current_proc_entry-1;
#endif
	    /* Save process status information */
DEBUGMSG(("host/hr_swrun", " saved"));
	}
DEBUGMSG(("host/hr_swrun", "\n"));
    }

    if ( LowPid == -1 ) {
        DEBUGMSGTL(("host/hr_swrun", "... index out of range\n"));
        return(MATCH_FAILED);
    }

    newname[HRSWRUN_ENTRY_NAME_LENGTH] = LowPid;
    memcpy( (char *)name,(char *)newname, (vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    DEBUGMSGTL(("host/hr_swrun", "... get process stats "));
    DEBUGMSGOID(("host/hr_swrun", name, *length));
    DEBUGMSG(("host/hr_swrun","\n"));
    return LowPid;
}

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char *
var_hrswrun(struct variable *vp,
	    oid *name,
	    size_t *length,
	    int exact,
	    size_t *var_len,
	    WriteMethod **write_method)
{
    int pid=0;
    static char string[256];
#ifdef HAVE_SYS_PSTAT_H
    struct pst_status proc_buf;
#elif defined(solaris2)
#if _SLASH_PROC_METHOD_
    static psinfo_t psinfo;
    static psinfo_t *proc_buf = &psinfo;
    int procfd;
    char procfn[sizeof "/proc/00000/psinfo"];
#else
    static struct proc *proc_buf;
#endif	/* _SLASH_PROC_METHOD_ */
    static time_t when = 0;
    time_t now;
    static int oldpid = -1;
    char *cp1;
#endif
#if HAVE_KVM_GETPROCS
    char **argv;
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
#elif defined(solaris2)
    time(&now);
    if (pid == oldpid) {
	if (now != when) oldpid = -1;
    }
    if (oldpid != pid || proc_buf == NULL) {
#if _SLASH_PROC_METHOD_
	sprintf(procfn, "/proc/%.5d/psinfo", pid);
	if ((procfd = open(procfn, O_RDONLY)) == -1) return NULL;
	if (read(procfd, proc_buf, sizeof(*proc_buf)) != sizeof(*proc_buf)) abort();
	close(procfd);
#else
	if (kd == NULL) return NULL;
	if ((proc_buf = kvm_getproc(kd, pid)) == NULL) return NULL;
#endif
	oldpid = pid;
	when = now;
    }
#endif

    switch (vp->magic){
	case HRSWRUN_OSINDEX:
#if NO_DUMMY_VALUES
		return NULL;
#else
	    long_return = 1;		/* Probably! */
#endif
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
#elif defined(solaris2)
#if _SLASH_PROC_METHOD_
	    strcpy(string, proc_buf->pr_fname);
#else
	    strcpy(string, proc_buf->p_user.u_comm);
#endif
#elif HAVE_KVM_GETPROCS
            strcpy(string, proc_table[LowProcIndex].kp_proc.p_comm);
#elif defined(linux)
	    sprintf( string, "/proc/%d/status", pid );
	    if ((fp = fopen( string, "r")) == NULL) return NULL;
	    fgets( buf, sizeof(buf), fp );	/* Name: process name */
	    cp = buf;
	    while ( *cp != ':' )
		++cp;
	    ++cp;
	    while ( isspace( *cp ))
		++cp;
	    strcpy( string, cp );
            fclose(fp);
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    sprintf(string, "process name");
#endif
	    *var_len = strlen(string);
	    /* remove trailing newline */
	    if (*var_len) {
	        cp = string + *var_len -1;
	        if (*cp == '\n')
	            --(*var_len);
	    }
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
#elif defined(solaris2)
#ifdef _SLASH_PROC_METHOD_
	    strcpy(string, proc_buf->pr_psargs);
	    cp = strchr(string, ' ');
	    if (cp) *cp = 0;
#else
	    cp = proc_buf->p_user.u_psargs;
	    cp1 = string;
	    while (*cp && *cp != ' ') *cp1++ = *cp++;
	    *cp1 = 0;
#endif
#elif HAVE_KVM_GETPROCS
            strcpy(string, proc_table[LowProcIndex].kp_proc.p_comm);
#elif defined(linux)
	    sprintf( string, "/proc/%d/cmdline", pid );
	    if ((fp = fopen( string, "r")) == NULL) return NULL;
	    fgets( buf, sizeof(buf), fp );	/* argv[0] '\0' argv[1] '\0' .... */
	    strcpy( string, buf );
            fclose(fp);
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    sprintf(string, "/bin/wombat");
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
#elif defined(solaris2)
#ifdef _SLASH_PROC_METHOD_
	    cp = strchr(proc_buf->pr_psargs, ' ');
	    if (cp) strcpy(string, cp+1);
	    else string[0] = 0;
#else
	    cp = proc_buf->p_user.u_psargs;
	    while (*cp && *cp != ' ') cp++;
	    if (*cp == ' ') cp++;
	    strcpy (string, cp);
#endif
#elif HAVE_KVM_GETPROCS
	    string[0] = 0;
	    argv = kvm_getargv(kd, proc_table+LowProcIndex, sizeof(string));
	    if (argv) argv++;
	    while (argv && *argv) {
		if (string[0] != 0) strcat(string, " ");
		strcat(string, *argv);
		argv++;
	    }
#elif defined(linux)
	    sprintf( string, "/proc/%d/cmdline", pid );
	    if ((fp = fopen( string, "r")) == NULL) return NULL;
	    memset( buf, 0, sizeof(buf) );
	    fgets( buf, sizeof(buf), fp );   /* argv[0] '\0' argv[1] '\0' .... */

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
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    sprintf(string, "-h -q -v");
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
#if HAVE_KVM_GETPROCS
	    switch ( proc_table[LowProcIndex].kp_proc.p_stat ) {
#elif defined(solaris2)
#if _SLASH_PROC_METHOD_
	    switch (proc_buf->pr_lwp.pr_state) {
#else
	    switch ( proc_buf->p_stat ) {
#endif
#else
	    switch ( proc_table[LowProcIndex].p_stat ) {
#endif
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
	    if ((fp = fopen( string, "r")) == NULL) return NULL;
	    fgets( buf, sizeof(buf), fp );
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
				/*
				 * Not convinced this is right, but....
				 */
#elif defined(solaris2)
#if _SLASH_PROC_METHOD_
	    long_return = proc_buf->pr_time.tv_sec * 100 +
			  proc_buf->pr_time.tv_nsec/10000000;
#else
	    long_return = proc_buf->p_utime*100 +
	    		  proc_buf->p_stime*100;
#endif
#elif HAVE_KVM_GETPROCS
	    long_return = proc_table[LowProcIndex].kp_proc.p_uticks +
	    		  proc_table[LowProcIndex].kp_proc.p_sticks +
	    		  proc_table[LowProcIndex].kp_proc.p_iticks;
#elif defined(linux)
	    sprintf( string, "/proc/%d/stat", pid );
	    if ((fp = fopen( string, "r")) == NULL) return NULL;
	    fgets( buf, sizeof(buf), fp );
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
#elif defined(sunos4)
	    long_return = proc_table[LowProcIndex].p_time;
#else
	    long_return = proc_table[LowProcIndex].p_utime.tv_sec*100 +
			  proc_table[LowProcIndex].p_utime.tv_usec/10000 +
	    		  proc_table[LowProcIndex].p_stime.tv_sec*100 +
			  proc_table[LowProcIndex].p_stime.tv_usec/10000;
#endif
	    return (u_char *)&long_return;
	case HRSWRUNPERF_MEM:
#ifdef HAVE_SYS_PSTAT_H
	    long_return = (proc_buf.pst_rssize << PGSHIFT)/1024;
#elif defined(solaris2)
#if _SLASH_PROC_METHOD_
	    long_return = proc_buf->pr_rssize;
#else
	    long_return = proc_buf->p_swrss;
#endif
#elif HAVE_KVM_GETPROCS
#ifdef freebsd3
	    long_return = proc_table[LowProcIndex].kp_eproc.e_vm.vm_map.size/1024;
#else
	    long_return = proc_table[LowProcIndex].kp_eproc.e_vm.vm_tsize +
			  proc_table[LowProcIndex].kp_eproc.e_vm.vm_ssize +
			  proc_table[LowProcIndex].kp_eproc.e_vm.vm_dsize;
	    long_return = long_return * (getpagesize() / 1024);
#endif
#elif defined(linux)
	    sprintf( string, "/proc/%d/stat", pid );
	    if ((fp = fopen( string, "r")) == NULL) return NULL;
	    fgets( buf, sizeof(buf), fp );
	    cp = buf;
	    for ( i = 0 ; i < 23 ; ++i ) {	/* skip 23 fields */
		while ( *cp != ' ')
		    ++cp;
	        ++cp;
	    }
	    long_return = atoi( cp ) * (getpagesize()/1024);		/* rss */
            fclose(fp);
#else
#if NO_DUMMY_VALUES
	    return NULL;
#endif
	    long_return = 16*1024;	/* XXX - 16M! */
#endif
	    return (u_char *)&long_return;
	default:
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_hrswrun\n", vp->magic));
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

void
Init_HR_SWRun (void)
{
    size_t bytes;
    static time_t iwhen = 0;
    time_t now;

    time(&now);
    if (now == iwhen) {
	current_proc_entry = 0;
	return;
    }
    iwhen = now;

#if defined(hpux10)
    pstat_getdynamic( &pst_dyn, sizeof( struct pst_dynamic ),
			1, 0 );
    nproc = pst_dyn.psd_activeprocs ;
    bytes = nproc*sizeof(struct pst_status);
    if ((proc_table=(struct pst_status *) realloc(proc_table, bytes)) == NULL ) {
	current_proc_entry = nproc+1;
	return;
    }
    pstat_getproc( proc_table, sizeof( struct pst_status ),
			nproc, 0 );

#elif defined(solaris2)
    if (!getKstatInt("unix", "system_misc", "nproc", &nproc)) {
    	current_proc_entry = nproc+1;
	return;
    }
    bytes = nproc*sizeof(int);
    if ((proc_table=(int *) realloc(proc_table, bytes)) == NULL ) {
	current_proc_entry = nproc+1;
	return;
    }
    {
	DIR *f;
	struct dirent *dp;
#if _SLASH_PROC_METHOD_ == 0
	if (kd == NULL) {
	    current_proc_entry = nproc+1;
	    return;
	}
#endif
	f = opendir("/proc");
	current_proc_entry = 0;
	while ((dp = readdir(f)) != NULL && current_proc_entry < nproc)
	    if (dp->d_name[0] != '.')
		proc_table[current_proc_entry++] = atoi(dp->d_name);
	closedir(f);
    }
#elif HAVE_KVM_GETPROCS
    {
	proc_table = kvm_getprocs(kd, KERN_PROC_ALL, 0, &nproc);
    }
#else

    current_proc_entry = 1;
#ifndef bsdi2
    nproc = 0;

    if (auto_nlist(NPROC_SYMBOL, (char *)&nproc, sizeof(int)) == 0) {
        snmp_log_perror("Init_HR_SWRun-auto_nlist NPROC");
        return;
    }
#endif
    bytes = nproc*sizeof(struct proc);

    if (proc_table) free((char *)proc_table);
    if ((proc_table=(struct proc *) malloc(bytes)) == NULL ) {
        nproc = 0;
        snmp_log_perror("Init_HR_SWRun-malloc");
        return;
    }

    {   int proc_table_base;
        if (auto_nlist(PROC_SYMBOL, (char *)&proc_table_base, sizeof(proc_table_base)) == 0) {
            nproc = 0;
            snmp_log_perror("Init_HR_SWRun-auto_nlist PROC");
            return;
        }
        if (klookup( proc_table_base, (char *)proc_table, bytes) == 0) {
            nproc = 0;
            snmp_log_perror("Init_HR_SWRun-klookup");
            return;
        }
    }
#endif
    current_proc_entry = 0;
}

int
Get_Next_HR_SWRun (void)
{
    while ( current_proc_entry < nproc ) {
#ifdef hpux10
	return proc_table[current_proc_entry++].pst_pid;
#elif defined(solaris2)
	return proc_table[current_proc_entry++];
#elif HAVE_KVM_GETPROCS
	if ( proc_table[current_proc_entry].kp_proc.p_stat != 0 )
	    return proc_table[current_proc_entry++].kp_proc.p_pid;
#else
	if ( proc_table[current_proc_entry].p_stat != 0 )
	    return proc_table[current_proc_entry++].p_pid;
	else
	    ++current_proc_entry;
#endif

    }
    End_HR_SWRun();
    return -1;
}

void
End_HR_SWRun (void)
{
    current_proc_entry = nproc+1;
}

#else /* linux */

DIR *procdir = NULL;
struct dirent *procentry_p;

void
Init_HR_SWRun (void)
{
    if ( procdir != NULL )
        closedir( procdir );
    procdir = opendir("/proc");
}

int
Get_Next_HR_SWRun (void)
{
   int pid;
   procentry_p = readdir( procdir );

   if ( procentry_p == NULL )
	return -1;

   pid = atoi(procentry_p->d_name);
   if ( pid == 0 )
	return( Get_Next_HR_SWRun());
   return pid;
}

void
End_HR_SWRun (void)
{
   if (procdir) closedir( procdir );
   procdir = NULL;
}

#endif

int count_processes (void)
{
#ifndef linux
    int i;
#endif
    int total=0;

    Init_HR_SWRun();
#if defined(hpux10) || HAVE_KVM_GETPROCS || defined(solaris2)
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

