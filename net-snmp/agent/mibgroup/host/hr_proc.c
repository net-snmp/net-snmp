/*
 *  Host Resources MIB - proc processor group implementation - hr_proc.c
 *
 */

#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <ctype.h>

#include "host_res.h"
#include "hr_proc.h"
#include <net-snmp/agent/auto_nlist.h>
#include <net-snmp/agent/agent_read_config.h>
#include <net-snmp/agent/hardware/cpu.h>
#include "ucd-snmp/loadave.h"

#define HRPROC_MONOTONICALLY_INCREASING

        /*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

extern void     Init_HR_Proc(void);
extern int      Get_Next_HR_Proc(void);
const char     *describe_proc(int);
int             header_hrproc(struct variable *, oid *, size_t *, int,
                              size_t *, WriteMethod **);
#ifdef linux
void detect_hrproc(void);
#endif

#ifdef solaris2
#define MAX_NUM_HRPROC  128       /* will handle up to 128 processors */
#include <kstat.h>
#include <kernel_sunos5.h>
hrtime_t  update_time = NULL;
static int ncpus = 0;             /* derived from kstat system_misc ncpus*/
struct cpuinfo {
            int id;
            char state[10];
            int state_begin;
            char cpu_type[15];
            char fpu_type[15];
            int clock_MHz;
            };                    /* derived from kstat cpu_info*/
static struct cpuinfo cpu[MAX_NUM_HRPROC];
static char proc_description[96]; /* buffer to hold description of current cpu*/
extern void kstat_CPU(void);
int proc_status(int);
#else
#ifdef linux
static char **proc_descriptions;
#else
# define MAX_NUM_HRPROC  32
char proc_descriptions[MAX_NUM_HRPROC][BUFSIZ];
#endif
#endif  /*solaris 2*/

        /*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/
static int      HRP_index;
static int      HRP_max_index = 1;

#define	HRPROC_ID		1
#define	HRPROC_LOAD		2

struct variable4 hrproc_variables[] = {
    {HRPROC_ID, ASN_OBJECT_ID, RONLY, var_hrproc, 2, {1, 1}},
    {HRPROC_LOAD, ASN_INTEGER, RONLY, var_hrproc, 2, {1, 2}}
};
oid             hrproc_variables_oid[] = { 1, 3, 6, 1, 2, 1, 25, 3, 3 };


void
init_hr_proc(void)
{
    init_device[HRDEV_PROC] = Init_HR_Proc;
    next_device[HRDEV_PROC] = Get_Next_HR_Proc;
    device_descr[HRDEV_PROC] = describe_proc;
#ifdef solaris2
    device_status[HRDEV_PROC] = proc_status;
    update_time = NULL;
#endif
#ifdef HRPROC_MONOTONICALLY_INCREASING
    dev_idx_inc[HRDEV_PROC] = 1;
#endif

#ifdef linux
    detect_hrproc();
#endif

    REGISTER_MIB("host/hr_proc", hrproc_variables, variable4,
                 hrproc_variables_oid);
}

/*
 * header_hrproc(...
 * Arguments:
 * vp     IN      - pointer to variable entry that points here
 * name    IN/OUT  - IN/name requested, OUT/name found
 * length  IN/OUT  - length of IN/OUT oid's 
 * exact   IN      - TRUE if an exact match was requested
 * var_len OUT     - length of variable or 0 if function returned
 * write_method
 * 
 */

int
header_hrproc(struct variable *vp,
              oid * name,
              size_t * length,
              int exact, size_t * var_len, WriteMethod ** write_method)
{
#define HRPROC_ENTRY_NAME_LENGTH	11
    oid             newname[MAX_OID_LEN];
    int             proc_idx, LowIndex = -1;
    int             result;

    DEBUGMSGTL(("host/hr_proc", "var_hrproc: "));
    DEBUGMSGOID(("host/hr_proc", name, *length));
    DEBUGMSG(("host/hr_proc", " %d\n", exact));

    memcpy((char *) newname, (char *) vp->name, vp->namelen * sizeof(oid));
    /*
     * Find "next" proc entry 
     */

    Init_HR_Proc();
    for (;;) {
        proc_idx = Get_Next_HR_Proc();
        if (proc_idx == -1)
            break;
        newname[HRPROC_ENTRY_NAME_LENGTH] = proc_idx;
        result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);
        if (exact && (result == 0)) {
            LowIndex = proc_idx;
            /*
             * Save processor status information 
             */
            break;
        }
        if ((!exact && (result < 0)) &&
            (LowIndex == -1 || proc_idx < LowIndex)) {
            LowIndex = proc_idx;
            /*
             * Save processor status information 
             */
#ifdef HRPROC_MONOTONICALLY_INCREASING
            break;
#endif
        }
    }

    if (LowIndex == -1) {
        DEBUGMSGTL(("host/hr_proc", "... index out of range\n"));
        return (MATCH_FAILED);
    }

    memcpy((char *) name, (char *) newname,
           (vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);    /* default to 'long' results */

    DEBUGMSGTL(("host/hr_proc", "... get proc stats "));
    DEBUGMSGOID(("host/hr_proc", name, *length));
    DEBUGMSG(("host/hr_proc", "\n"));
    return LowIndex;
}


        /*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char         *
var_hrproc(struct variable * vp,
           oid * name,
           size_t * length,
           int exact, size_t * var_len, WriteMethod ** write_method)
{
    int             proc_idx;
    double          avenrun[3];

    proc_idx =
        header_hrproc(vp, name, length, exact, var_len, write_method);
    if (proc_idx == MATCH_FAILED)
        return NULL;
    if (try_getloadavg(&avenrun[0], sizeof(avenrun) / sizeof(avenrun[0]))
        == -1)
        return NULL;

    switch (vp->magic) {
    case HRPROC_ID:
        *var_len = nullOidLen;
        return (u_char *) nullOid;
    case HRPROC_LOAD:
#if NO_DUMMY_VALUES
        return NULL;
#endif
        long_return = avenrun[0] * 100; /* 1 minute average */
        if (long_return > 100)
            long_return = 100;
        return (u_char *) & long_return;
    default:
        DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_hrproc\n",
                    vp->magic));
    }
    return NULL;
}


        /*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

void
Init_HR_Proc(void)
{
#ifdef solaris2
    hrtime_t  current_time;
#endif
    HRP_index = 0;
#ifdef solaris2
    current_time = gethrtime();
    if (current_time > update_time + 2000000000) { /* two seconds */
        kstat_CPU();
        update_time = gethrtime();
    }
#endif
}

int
Get_Next_HR_Proc(void)
{
    if (HRP_index < HRP_max_index)
        return (HRDEV_PROC << HRDEV_TYPE_SHIFT) + HRP_index++;
    else
        return -1;
}

const char     *
describe_proc(int idx)
{
#ifdef _SC_CPU_VERSION
    int             result;

    result = sysconf(_SC_CPU_VERSION);
    switch (result) {
    case CPU_HP_MC68020:
        return (" Motorola MC68020 ");
    case CPU_HP_MC68030:
        return (" Motorola MC68030 ");
    case CPU_HP_MC68040:
        return (" Motorola MC68040 ");
    case CPU_PA_RISC1_0:
        return (" HP PA-RISC 1.0 ");
    case CPU_PA_RISC1_1:
        return (" HP PA-RISC 1.1 ");
    case CPU_PA_RISC1_2:
        return (" HP PA-RISC 1.2 ");
    case CPU_PA_RISC2_0:
        return (" HP PA-RISC 2.0 ");
    default:
        return ("An electronic chip with an HP label");

    }
#elif linux
    netsnmp_cpu_info *cpu;
    cpu = netsnmp_cpu_get_byIdx( idx & HRDEV_TYPE_MASK, 0 );
    return (cpu ? cpu->descr : NULL );
#elif solaris2
    int cidx = idx & HRDEV_TYPE_MASK;
    snprintf(proc_description,sizeof(proc_description)-1, 
           "CPU %d Sun %d MHz %s with %s FPU %s",
            cpu[cidx].id,cpu[cidx].clock_MHz,cpu[cidx].cpu_type,cpu[cidx].fpu_type,cpu[cidx].state);
    return proc_description;
#else
    return ("An electronic chip that makes the computer work.");
#endif
}

#ifdef linux
void detect_hrproc(void)
{
    int i;
    char tmpbuf[BUFSIZ], *cp;
    FILE *fp;
    int nrprocs;

    DEBUGMSG(("hr_proc::detect_hrproc",""));

    /*
     * ... and try to interpret the CPU information
     */
    fp = fopen("/proc/cpuinfo", "r");
    if (!fp) {
        DEBUGMSG(("hr_proc::detect_hrproc","could not open /proc/cpuinfo"));
	nrprocs = 1;
        proc_descriptions = (char**)malloc(sizeof(char*));
        proc_descriptions[0] =
            strdup("An electronic chip that makes the computer work.");
        return;
    }
    nrprocs = 1;
    proc_descriptions = (char**)malloc(sizeof(char*)*nrprocs);
    if (!proc_descriptions) {
        fclose(fp);
	return;
    }
    proc_descriptions[0] =
        strdup("An electronic chip that makes the computer work.");
    i = -1;
    while (fgets(tmpbuf, sizeof(tmpbuf), fp)) {
        /* note that some older (eg 2.4) kernels don't have a processor line */
	if (!strncmp(tmpbuf,"processor\t",strlen("processor\t")))
		i++;
	if (!strncmp(tmpbuf,"processor ",strlen("processor ")))
		i++;
        if ((i!=-1) && (i >= nrprocs)) {
	    nrprocs++;
    	    proc_descriptions = (char**)realloc(proc_descriptions, sizeof(char*)*nrprocs);
	    if (!proc_descriptions) {
                fclose(fp);
		return;
            }
	    proc_descriptions[nrprocs-1] = strdup("An electronic chip that makes the computer work."); /* will be overwritten */
        }

#if defined(__i386__) || defined(__x86_64__)
        if ( !strncmp( tmpbuf, "vendor_id", 9)) {
	    /* Stomp on trailing newline... */
            cp = &tmpbuf[strlen(tmpbuf)-1];
	    *cp = 0;
	    /* ... and then extract the value */
            cp = index( tmpbuf, ':');
	    cp++;
	    while ( cp && isspace(*cp))
	        cp++;
            if (proc_descriptions[nrprocs-1])
                free(proc_descriptions[nrprocs-1]);
	    proc_descriptions[nrprocs-1] = strdup(cp);
        }
        if ( !strncmp( tmpbuf, "model name", 10)) {
           char *s;
	    /* Stomp on trailing newline... */
            cp = &tmpbuf[strlen(tmpbuf)-1];
	    *cp = 0;
	    /* ... and then extract the value */
            cp = index( tmpbuf, ':');
	    cp++;
	    while ( cp && isspace(*cp))
	        cp++;
            if (!proc_descriptions[nrprocs-1]) {
	        s = malloc(strlen(": ")+strlen(cp)+1);
		strcpy(s,": ");
                strcat(s,cp);
		proc_descriptions[nrprocs-1] = s;
            } else {
		s = malloc(strlen(proc_descriptions[nrprocs-1])+strlen(": ")+strlen(cp)+1);
		strcpy(s,proc_descriptions[nrprocs-1]);
		strcat(s,": ");
		strcat(s,cp);
		free(proc_descriptions[nrprocs-1]);
		proc_descriptions[nrprocs-1] = s;
            }
        }
#endif
#if defined(__powerpc__) || defined(__powerpc64__)
        if ( !strncmp( tmpbuf, "cpu\t", 4)) {
	    char *s;

	    /* Stomp on trailing newline... */
            cp = &tmpbuf[strlen(tmpbuf)-1];
	    *cp = 0;
	    /* ... and then extract the value */
            cp = index( tmpbuf, ':');
	    cp++;
	    while ( cp && isspace(*cp))
	        cp++;
            if (proc_descriptions[nrprocs-1])
                free(proc_descriptions[nrprocs-1]);
	    proc_descriptions[nrprocs-1] = strdup(cp);
	}
#endif
#if defined(__ia64__)
	/* since vendor is always Intel ... we don't parse vendor */
        if ( !strncmp( tmpbuf, "family\t", 6)) {
	    char *s;

	    /* Stomp on trailing newline... */
            cp = &tmpbuf[strlen(tmpbuf)-1];
	    *cp = 0;
	    /* ... and then extract the value */
            cp = index( tmpbuf, ':');
	    cp++;
	    while ( cp && isspace(*cp))
	        cp++;
            if (proc_descriptions[nrprocs-1])
                free(proc_descriptions[nrprocs-1]);
	    proc_descriptions[nrprocs-1] = strdup(cp);
        }
#endif
#if defined(__s390__) || defined(__s390x__)
        if (proc_descriptions[nrprocs-1])
            free(proc_descriptions[nrprocs-1]);
        proc_descriptions[nrprocs-1] = strdup("An S/390 CPU");
#endif
    }
    DEBUGMSG(("hr_proc::detect_hrproc","registered %d processors", nrprocs));
    HRP_max_index = nrprocs;
    fclose(fp);
    return;
}
#endif /* linux */

#ifdef solaris2
void kstat_CPU(void)
{
/* this routine asks the OS for the number of CPU's and uses that value
 * to set HRP_max_index for later use.  Then it asks the OS for
 * specific details of each CPU.  In Solaris, you cannot trust the 
 * first CPU to be 0 or for CPU 0 to even exist, hence there is a 
 * CPU id, state, cpu type, fpu type, state_begin (what does this do??)
 * and CPU speed.  Results are stuffed into the cpu array (see above).
 *
 * In keeping with the spirit of the RFC, the number and index of CPU's
 * is considered to be constant.  Hence, if you start yanking or adding
 * CPU modules eg. on a V880, you will need to start and stop the daemon.
 */
    int i_cpu = -1;
    int i,old_ncpus;
    kstat_ctl_t *kc;
    kstat_t *ksp;
    kstat_named_t *ks_data;
    old_ncpus = ncpus;
    for (i = 0; i < ncpus; i++) {
        strncpy(cpu[i].state,"missing",sizeof(cpu[i].state));
        cpu[i].state[sizeof(cpu[i].state)-1]='\0'; /* null terminate */
        cpu[i].id = 999999;
        cpu[i].clock_MHz = 999999;
        strncpy(cpu[i].cpu_type,"missing",sizeof(cpu[i].cpu_type));
        cpu[i].state[sizeof(cpu[i].cpu_type)-1]='\0'; /* null terminate */
        strncpy(cpu[i].fpu_type,"missing",sizeof(cpu[i].fpu_type));
        cpu[i].state[sizeof(cpu[i].cpu_type)-1]='\0'; /* null terminate */
        }
    getKstat("system_misc", "ncpus", &ncpus);
    if (ncpus > old_ncpus){
        HRP_max_index = ncpus; /* the MIB says to retain indexes */
        }
    if ((old_ncpus != ncpus)&&(old_ncpus != 0)) {
        if (ncpus > old_ncpus){
            snmp_log(LOG_NOTICE,
              "hr_proc: Cool ! Number of CPUs increased, must be hot-pluggable.\n");
            }
        else {
            snmp_log(LOG_NOTICE,
                     "hr_proc: Lost at least one CPU, RIP.\n");
            }
       }
    if ((kc = kstat_open()) == NULL) {
        DEBUGMSGTL(("hr_proc", "kstat_open failed"));
        }
    else {
        for (ksp = kc->kc_chain; ksp != NULL; ksp = ksp->ks_next)  {
            if (ksp->ks_type == KSTAT_TYPE_NAMED
               &&  strcmp(ksp->ks_module, "cpu_info") == 0
               &&  strcmp(ksp->ks_class, "misc") == 0) {
                   if (kstat_read(kc, ksp, NULL) == -1)  {
                      DEBUGMSGTL(("hr_proc", "kstat_read failed"));
                      }
                   else {
                       i_cpu++;
                       i = 0;
                       cpu[i_cpu].id = ksp->ks_instance;
                       for (ks_data = ksp->ks_data; i < ksp->ks_ndata; i++, ks_data++) {
                           if (strcmp(ks_data->name,"state")==0) {
                               strncpy(cpu[i_cpu].state,ks_data->value.c,sizeof(cpu[i_cpu].state));
                               cpu[i_cpu].state[sizeof(cpu[i_cpu].state)-1]='\0'; /* null terminate */
                               continue;
                               }
                           else if (strcmp(ks_data->name,"state_begin")==0)   {
                               cpu[i_cpu].state_begin=ks_data->value.i32;
                               continue;
                               }
                           else if (strcmp(ks_data->name,"cpu_type")==0)   {
                               strncpy(cpu[i_cpu].cpu_type,ks_data->value.c,sizeof(cpu[i_cpu].cpu_type));
                               cpu[i_cpu].state[sizeof(cpu[i_cpu].cpu_type)-1]='\0'; /* null terminate */
                               continue;
                               }
                           else if (strcmp(ks_data->name,"fpu_type")==0)   {
                               strncpy(cpu[i_cpu].fpu_type,ks_data->value.c,sizeof(cpu[i_cpu].fpu_type));
                               cpu[i_cpu].state[sizeof(cpu[i_cpu].fpu_type)-1]='\0'; /* null terminate */
                               continue;
                               }
                           else if (strcmp(ks_data->name,"clock_MHz")==0)   {
                               cpu[i_cpu].clock_MHz=ks_data->value.i32;
                               continue;
                               }
                           else    {
                                   DEBUGMSGTL(("hr_proc","kstat unexpected cpu parameter"));
                       }
                   }
               }
           }
        }
    }
    kstat_close(kc);
}
int
proc_status(int idx)
{
    /*
     * hrDeviceStatus OBJECT-TYPE
     * SYNTAX     INTEGER {
     * unknown(1), running(2), warning(3), testing(4), down(5)
     * }
     */
    int cidx = idx & HRDEV_TYPE_MASK;
    if (strcmp(cpu[cidx].state,"on-line")==0) {
        return 2;                   /* running */
         }
    else if (strcmp(cpu[cidx].state,"off-line")==0) {
        return 5;                   /* down */
         }
    else if (strcmp(cpu[cidx].state,"missing")==0) {
        return 3;                   /* warning, went missing, see above */
         }
    else if (strcmp(cpu[cidx].state,"testing")==0) {
        return 4;                   /* somebody must be testing code up above */
         }
    else {
        return 1;                   /* unknown */
         }
}
#endif /* solaris2 */
