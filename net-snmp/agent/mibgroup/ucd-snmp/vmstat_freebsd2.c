/*
 * vmstat_freebsd2.c
 */

#include <config.h>

/* Ripped from /usr/scr/usr.bin/vmstat/vmstat.c (covering all bases) */
#include <sys/param.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/dkstat.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/signal.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>

#include <vm/vm_param.h>

#include <time.h>
#include <nlist.h>
#include <kvm.h>
#include <errno.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <paths.h>
#include <limits.h>


#include "mibincl.h"
#include "util_funcs.h"

#include "vmstat.h"
#include "auto_nlist.h"


/* nlist symbols */
#define CPTIME_SYMBOL   "cp_time"
#define SUM_SYMBOL      "cnt"
#define INTRCNT_SYMBOL  "intrcnt"
#define EINTRCNT_SYMBOL "eintrcnt"
#define BOOTTIME_SYMBOL "boottime"

/* Number of interrupts */
#define INT_COUNT       10

/* CPU percentage */
#define CPU_PRC         100

long
getuptime()
{
	static time_t now, boottime;
	time_t uptime;

	if (boottime == 0)
		auto_nlist(BOOTTIME_SYMBOL, &boottime, sizeof (boottime));

	time(&now);
	uptime = now - boottime;

	return(uptime);
}

unsigned char *var_extensible_vmstat(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
/* IN - pointer to variable entry that points here */
    register oid	*name;
/* IN/OUT - input name requested, output name found */
    register int	*length;
/* IN/OUT - length of input and output oid's */
    int			exact;
/* IN - TRUE if an exact match was requested. */
    int			*var_len;
/* OUT - length of variable or 0 if function returned. */
    int			(**write_method)__P((int, u_char *, u_char, int, u_char *, oid *, int));
/* OUT - pointer to function to set variable, otherwise 0 */
{

    int loop;

    time_t time_new = getuptime();
    static time_t time_old;
    static time_t time_diff;

    static long cpu_old[CPUSTATES];
    static long cpu_new[CPUSTATES];
    static long cpu_diff[CPUSTATES];
    static long cpu_total;
    long cpu_sum;
    double cpu_prc;

    static struct vmmeter mem_old, mem_new;

    static long long_ret;
    static char errmsg[300];

    long_ret = 0;  /* set to 0 as default */

    if (!checkmib(vp,name,length,exact,var_len,write_method,1))
	return(NULL);

    /* Update structures (only if time has passed) */
    if (time_new != time_old)
    {
	time_diff = time_new - time_old;
	time_old = time_new;

	/* CPU usage */
	auto_nlist(CPTIME_SYMBOL, (char *)cpu_new, sizeof (cpu_new));
	
	cpu_total = 0;
	
	for (loop = 0; loop < CPUSTATES; loop++)
	{
	    cpu_diff[loop] = cpu_new[loop] - cpu_old[loop];
	    cpu_old[loop] = cpu_new[loop];
	    cpu_total += cpu_diff[loop];
	}
	
	if (cpu_total == 0) cpu_total = 1;

	/* Memory info */
	mem_old = mem_new;
	auto_nlist(SUM_SYMBOL, &mem_new, sizeof(mem_new));
    }

/* Rate macro */
#define rate(x) (((x)+ time_diff/2) / time_diff)

/* Page-to-kb macro */
#define ptok(p) ((p) * (mem_new.v_page_size >> 10))

    switch (vp->magic) {
    case MIBINDEX:
	long_ret = 1;
	return((u_char *) (&long_ret));
    case ERRORNAME:    /* dummy name */
	sprintf(errmsg,"systemStats");
	*var_len = strlen(errmsg);
	return((u_char *) (errmsg));
    case SWAPIN:
	long_ret = ptok(mem_new.v_swapin - mem_old.v_swapin + 
			mem_new.v_vnodein - mem_old.v_vnodein);
	long_ret = rate(long_ret);
	return((u_char *) (&long_ret));
    case SWAPOUT:
	long_ret = ptok(mem_new.v_swapout - mem_old.v_swapout + 
			mem_new.v_vnodeout - mem_old.v_vnodeout);
	long_ret = rate(long_ret);
	return((u_char *) (&long_ret));
    case IOSENT:
	long_ret = -1;
	return((u_char *) (&long_ret));
    case IORECEIVE:
	long_ret = -1;
	return((u_char *) (&long_ret));
    case SYSINTERRUPTS:
	long_ret = rate(mem_new.v_intr - mem_old.v_intr);
	return((u_char *) (&long_ret));
    case SYSCONTEXT:
	long_ret = rate(mem_new.v_swtch - mem_old.v_swtch);
	return((u_char *) (&long_ret));
    case CPUUSER:
	cpu_sum = cpu_diff[CP_USER] + cpu_diff[CP_NICE];
	cpu_prc = (float)cpu_sum / (float)cpu_total;
	long_ret = cpu_prc * CPU_PRC;
	return((u_char *) (&long_ret));
    case CPUSYSTEM:
	cpu_sum = cpu_diff[CP_SYS] + cpu_diff[CP_INTR];
	cpu_prc = (float)cpu_sum / (float)cpu_total;
	long_ret = cpu_prc * CPU_PRC;
	return((u_char *) (&long_ret));
    case CPUIDLE:
	cpu_sum = cpu_diff[CP_IDLE];
	cpu_prc = (float)cpu_sum / (float)cpu_total;
	long_ret = cpu_prc * CPU_PRC;
	return((u_char *) (&long_ret));
/* reserved for future use */
/*
  case ERRORFLAG:
  return((u_char *) (&long_ret));
  case ERRORMSG:
  return((u_char *) (&long_ret));
  */
    }
    return NULL;
}

