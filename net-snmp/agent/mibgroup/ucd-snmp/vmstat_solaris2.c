/*
 *  vmstat_solaris2.c
 *  UCD SNMP module for sysStatus section of UCD-SNMP-MIB for SunOS/Solaris
 *  Jochen Kmietsch <jochen.kmietsch@gmx.de>
 *  with fixes from Michael Slifcak <mslifcak@iss.net>
 *  Uses some ideas from xosview and top
 *  Some comments paraphrased from the SUN man pages 
 *  Version 0.1 initial release (Dec 1999)
 *  Version 0.2 added support for multiprocessor machines (Jan 2000)
 *  Version 0.3 some reliability enhancements and compile time fixes (Feb 2000)
 *
 */

/* Includes start here */

/* Standard includes */
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
#include <string.h>
     
/* UCD-SNMP config details */
#include <config.h>

/* kstat and sysinfo structs */
#include <kstat.h>
#include <sys/sysinfo.h>

/* Includes needed for all modules */
#include "mibdefs.h"
#include "mibincl.h"

/* Header file for this module */
#include "vmstat_solaris2.h"

/* Utility functions for UCD-SNMP */
#include "util_funcs.h"

/* Includes end here */


/* Global variables start here */

/* From kstat.h: */
/* Provides access to the kernel statistics library by */
/* initializing a kstat control structure and returning a pointer */
/* to this structure.  This pointer must be used as the kc argument in */
/* following function calls from libkstat (here kc is called kstat_fd). */
/* Pointer to structure to be opened with kstat_open in main procedure. */
/* We share this one with memory_solaris2 and kernel_sunos5, where it's defined. */
extern kstat_ctl_t *kstat_fd;

/* Holds number of CPUs this computer has. */
static ulong num_cpu;

/* Variables for getMisc, calloc in init function */
static ulong *swapin;
static ulong *swapout;
static ulong *blocks_read;
static ulong *blocks_write;
static ulong *interrupts;
static ulong *context_sw;

/* Variables for getCPU, calloc in init function */
static ulong *cpu_sum;
static ulong (*cpu_state)[CPU_STATES];
static ulong (*cpu_state_old)[CPU_STATES];
/* Since MIB wants CPU_SYSTEM, see getCPU function */
static float (*cpu_perc)[CPU_STATES+1];

/* To get rid of compiler warnings b/c prototype is inaccurate. */ 
static char string_cpu_stat[] = "cpu_stat";

/* Global variables end here */


/* Functions start here */

/* countCPU: Returns number of CPUs, utility routine */
ulong countCPU(kstat_ctl_t *kstat_fd)
{
  /* From kstat.h: */
  /* A "Named Kstat", see "man kstat" (Named Statistics) for description of structure */
  kstat_named_t *n_cpus;
  kstat_t *ksp_count;

  /* To get rid of compiler warnings b/c prototype is inaccurate */
  static char string_unix[]="unix";
  static char string_system_misc[]="system_misc";
  static char string_ncpus[]="ncpus";
  
  /* Look for a kstat by name */
  ksp_count = kstat_lookup(kstat_fd, string_unix, 0, string_system_misc); 
  
  if (ksp_count == NULL)
    {
      snmp_log(LOG_ERR, "vmstat_solaris2: No data in countCPU ksp_count.\n");
      return(-1);
    }
  
  /* Allocates the memory needed for kstat_data_lookup */
  kstat_read(kstat_fd, ksp_count, NULL);
  
  /* kstat_data_lookup looks in the kstat specified by arg 1 for the */
  /* string specified by arg 2.  Works only for named kstats. */
  n_cpus = kstat_data_lookup(ksp_count, string_ncpus);
  
  if (n_cpus == NULL)
    {
      snmp_log(LOG_ERR, "vmstat_solari2: No data in countCPU n_cpus.\n");
      /* Reasonable default */
      return(1);
    }
  
  /* Returns the value of the named kstat, an ulong in this case */
  return(n_cpus->value.ul);
} /* countCPU ends here */


/* init_vmstat_solaris2 starts here */
/* Init function for this module, from prototype */
/* Defines variables handled by this module, defines root OID for */
/* this module and registers it with the agent */
void init_vmstat_solaris2(void) 
{
  
  /* Which variables do we service ? */
  struct variable2 extensible_vmstat_variables[] = {
    {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_vmstat,1,{MIBINDEX }},
    {ERRORNAME, ASN_OCTET_STR, RONLY, var_extensible_vmstat, 1, {ERRORNAME }},
    {SWAPIN, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPIN }},
    {SWAPOUT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPOUT}},
    {IOSENT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {IOSENT}},
    {IORECEIVE, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {IORECEIVE}},
    {SYSINTERRUPTS, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SYSINTERRUPTS}},
    {SYSCONTEXT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SYSCONTEXT}},
    {CPUUSER, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUUSER}},
    {CPUSYSTEM, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUSYSTEM}},
    {CPUIDLE, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUIDLE}},
    /* Future use: */
    /*
      {ERRORFLAG, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {ERRORFLAG }},
      {ERRORMSG, ASN_OCTET_STR, RONLY, var_extensible_vmstat, 1, {ERRORMSG }}
      */    
  };
  
  /* Define the OID pointer to the top of the mib tree that we're
     registering underneath */
  oid vmstat_variables_oid[] = {EXTENSIBLEMIB,11};
  
  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("ucd-snmp/vmstat", extensible_vmstat_variables, variable2, \
               vmstat_variables_oid);
  
  /* First check whether shared kstat contol is NULL, if so, try to open our own. */
  if (kstat_fd == NULL)
    {
      kstat_fd = kstat_open();
    }
  /* Then check whether either shared kstat was found or we succeeded in opening our own. */
  if (kstat_fd == NULL)
    {
      snmp_log(LOG_ERR, "vmstat_solaris2 (init): kstat_open() failed and no shared kstat control found.\n");
    }
  
  /* Get number of CPUs, needed for dimensions of arrays that hold CPU data */
  if (kstat_fd != NULL)
    num_cpu = countCPU(kstat_fd);
  
  /* For getMisc, calloc here at start of module since size is dependend on number of CPUs */
  swapin = (ulong *) calloc(num_cpu, sizeof(swapin));
  swapout = (ulong *) calloc(num_cpu, sizeof(swapout));
  blocks_read = (ulong *) calloc(num_cpu, sizeof(blocks_read));
  blocks_write = (ulong *) calloc(num_cpu, sizeof(blocks_write));
  interrupts = (ulong *) calloc(num_cpu, sizeof(interrupts));
  context_sw = (ulong *) calloc(num_cpu, sizeof(context_sw));
  
  /* For getCPU, dito */
  cpu_sum = (ulong *) calloc(num_cpu, sizeof(cpu_sum));
  cpu_state = (ulong (*)[CPU_STATES]) calloc(num_cpu, sizeof(*cpu_state));
  cpu_state_old = (ulong (*)[CPU_STATES]) calloc(num_cpu, sizeof(*cpu_state_old));
  /* Since MIB wants CPU_SYSTEM, see getCPU */
  cpu_perc = (float (*)[CPU_STATES+1]) calloc(num_cpu, sizeof(*cpu_perc));
  
  /* Check whether we got all the memory we wanted, otherwise fail */
  if ((swapin == NULL) || (swapout == NULL) || (blocks_read == NULL) ||
      (blocks_write == NULL) || (interrupts == NULL) || (context_sw == NULL) ||
      (cpu_sum == NULL) || (cpu_state == NULL) || (cpu_state_old == NULL) ||
      (cpu_perc == NULL))
    {
      snmp_log(LOG_ERR,"vmstat_solaris2: (init) could not allocate memory.\n");
      /* Is this ok ? */
      exit(-1);
    }
  
} /* init_vmstat_solaris2 ends here */

#ifndef HAVE_GETPAGESIZE
/* Returns the pagesize */
/* Normally this is in libc, but not on Solaris 2.4 */
int getpagesize(void)
{
  return (sysconf(_SC_PAGESIZE));
}
#endif

/* Data collection function getMisc starts here */
/* Get data from kernel and returns misc data / sec */
/* "what" is the data requested, see the vp switch statement */
long getMisc(int what)
{
  
  /* Variables start here */

  /* From sys/kstat.h (included from kstat.h): */
  /* Pointer to current kstat */
  kstat_t *ksp;
  
  /* Declared static so they don't die with the function */
  /* This way we can re-use them if they are new enough */
  /* Some variables declared global, see "Global Variables" section */
  static ulong swapin_avg;
  static ulong swapout_avg;
  static ulong blocks_read_avg;
  static ulong blocks_write_avg;
  static ulong interrupts_avg;
  static ulong context_sw_avg;
  
  /* From time.h, get seconds since start of UNIX time... */
  time_t timestamp_new;
  static time_t timestamp_old_1;
  
  /* From sys/sysinfo.h: */
  /* Structure which can hold all the CPU info kstat provides */ 
  cpu_stat_t cs;
  
  /* Counters */
  int cpu_slot = 0;
  int cpu_num = 0;
  
  /* Variables end here */

  /* Get time */
  time(&timestamp_new);
  
  /* If we have just gotten the data, return the values from last run (skip if) */
  /* This happens on a snmpwalk request.  No need to read the kstat again */
  /* if we just did it less than a second ago */
  /* +1 b/c we sleep(1) on the first run */
  
  if (timestamp_new > (timestamp_old_1 + 1))
    {
      
      /* Update timer */
      timestamp_old_1 = timestamp_new;
      
      /* Look thru all the cpu slots on the machine whether they holds a CPU */
      /* and if so, get the data from that CPU */
      /* Important: num_cpu might be 12.  Then cpu_num is from 0 to 11, not 1 to 12 ! */
      for (cpu_slot=0;cpu_num<num_cpu;cpu_slot++)
	{ 
	  /* If ksp is NULL we don't have a CPU :) */
	  /* For MP machines: We hit an empty CPU board, trying next one... */
	  /* kstat_lookup: look for a kstat by module, instance and name */
	  if ((ksp = kstat_lookup(kstat_fd, string_cpu_stat, cpu_slot, NULL)) != NULL)
	    {
	      /* Yeah, we found a CPU. */  
	      /* Read data from kstat into cs structure */
	      /* kc is the control structure, ksp the kstat we are reading */
	      /* and cs the buffer we are writing to. */
	      /* Memory allocation is done automagically by the kstat library. */
	      if (kstat_read(kstat_fd, ksp, &cs) == -1)
		{
		  snmp_log(LOG_ERR, "vmstat_solaris2 (getMisc:1): failure to init cs structure.\n");
		  return(-1);
		}
	      
	      /* Get pages swapped in */
	      swapin[cpu_num] = cs.cpu_vminfo.pgswapin;
	      /* Get pages swapped out */
	      swapout[cpu_num] = cs.cpu_vminfo.pgswapout;
	      /* Get number of blocks written */
	      blocks_write[cpu_num] = cs.cpu_sysinfo.bwrite;
	      /* Get number of blocks read */
	      blocks_read[cpu_num] = cs.cpu_sysinfo.bread;
	      /* Get number of Interrupts (since boot) */
	      interrupts[cpu_num] = cs.cpu_sysinfo.intr;
	      /* Get number of conext switches (since boot) */
	      context_sw[cpu_num] = cs.cpu_sysinfo.pswitch;
	      
	      /* Counter for number of CPUs found. */
	      /* cpu_slot might go from 0 to 15 (available CPU slots) while */
	      /* cpu_num keeps track about actual number of CPUs read. */
	      cpu_num++;
	      
	    } /* end else */
	} /* end for */
      
      /* Trying not to destroy the probed object with the probe... */
      /* 1 sec delay between getting values from cs structure. */
      sleep(1);
      
      /* Look thru all the cpu slots on the machine whether it holds a CPU */
      /* Important: num_cpu might be 12.  Then cpu_num is from 0 to 11, not 1 to 12 ! */
      /* This is the same loop like above before the sleep(1).  Could be improved to */
      /* cache the CPU slots that hold a CPU or similar */
      
      /* We have to start over again */
      cpu_num = 0;
      
      for (cpu_slot=0;cpu_num<num_cpu;cpu_slot++)
	{ 
	  if ((ksp = kstat_lookup(kstat_fd, string_cpu_stat, cpu_slot, NULL)) != NULL)
	    {
	      /* Yeah, we found a CPU. */
	      /* Update cs structure with new kstat values after we are awake again. */
	      if (kstat_read(kstat_fd, ksp, &cs) == -1)
		{
		  snmp_log(LOG_ERR, "vmstat_solaris2 (getMisc:2): failure to update cs structure.\n");
		  return(-1);
		}
	      
	      /* Get new samples after waiting for counters to increments */
	      /* thru system activity. */
	      /* Get new number of pages swapped in and calculate difference */
	      swapin[cpu_num] = (cs.cpu_vminfo.pgswapin - swapin[cpu_num]);
	      /* Get new number of pages swapped out and calculate difference */
	      swapout[cpu_num] = (cs.cpu_vminfo.pgswapout - swapout[cpu_num]);
	      /* Get new number of blocks written and calculate difference */
	      blocks_write[cpu_num] = cs.cpu_sysinfo.bwrite - blocks_write[cpu_num];
	      /* Get new number of blocks read and calculate difference */
	      blocks_read[cpu_num] = cs.cpu_sysinfo.bread - blocks_read[cpu_num];
	      /* Get new number of interrupts and calculate difference */
	      interrupts[cpu_num] = cs.cpu_sysinfo.intr - interrupts[cpu_num];
	      /* Get new number of context switches and calculate difference */
	      context_sw[cpu_num] = cs.cpu_sysinfo.pswitch - context_sw[cpu_num];
	      
	      /* Increment CPUs found count */
	      cpu_num++;
	      
	    } /* end else */
	} /* end for */
      
      /* Calculate averages for all CPUs and return single value */
      /* Since these are static variables we need to initialize them properly */
      swapin_avg = 0;
      swapout_avg = 0;
      blocks_write_avg = 0;
      blocks_read_avg =0;
      interrupts_avg = 0;
      context_sw_avg = 0;
      
      /* First sum up all values */
      for (cpu_num=0;cpu_num<num_cpu;cpu_num++)
	{
	  swapin_avg += swapin[cpu_num];
	  swapout_avg += swapout[cpu_num];
	  blocks_write_avg += blocks_write[cpu_num];
	  blocks_read_avg += blocks_read[cpu_num];
	  interrupts_avg += interrupts[cpu_num];
	  context_sw_avg +=context_sw[cpu_num];
	}

      /* swapin and swapout are in pages, MIB wants kB/s, we sleep(1) so we just need to get kB */
      /* getpagesize() returns pagesize in bytes */
      swapin_avg = swapin_avg * (getpagesize() / 1024);
      swapout_avg = swapout_avg * (getpagesize() / 1024);

      /* Then divide by number of CPUs, discarding fractions */
      swapin_avg /= num_cpu;
      swapout_avg /= num_cpu;
      blocks_write_avg /= num_cpu;
      blocks_read_avg /= num_cpu;
      interrupts_avg /= num_cpu;
      context_sw_avg /= num_cpu;
      
    } /* end if (timestap_new > (timestamp_old_1 + 1)) */
  
  /* Return the requested variable, casting to long */
  switch (what)
    {
    case SWAPIN:
      return((long) swapin_avg);
    case SWAPOUT:
      return((long) swapout_avg);
    case IOSENT:
      return((long) blocks_write_avg);
    case IORECEIVE:
      return((long) blocks_read_avg);
    case SYSINTERRUPTS:
      return((long) interrupts_avg);
    case SYSCONTEXT:
      return((long) context_sw_avg);
    default:
      snmp_log(LOG_ERR,"vmstat_solaris2 (getMisc): No data found.\n");
      return(-1);
    } /* end switch */

} /* end function getMisc */


/* getCPU: get percentages for CPU utilisation */
/* state: CPU_IDLE, CPU_USER, CPU_KERNEL + CPU_WAIT = CPU_SYSTEM -> 0, 1, 4 */
long getCPU(int state)
{
  
  /* Variables start here */
  
  /* From sys/kstat.h (included from kstat.h): */
  /* Pointer to current kstat */
  kstat_t *ksp;
  
  /* As always, we need s.th. to count on, aehm, by */
  int i=0;
  
  /* Some variables declared global, see "Global Variables" section */
  /* This array holds the averaged percentages for all CPU on this machine.  Thus it's declared */
  /* static so we can reuse it if it's new enough. */
  static float cpu_perc_avg[CPU_STATES+1];

  /* From time.h, get seconds since start of UNIX time... */
  time_t timestamp_new;
  static time_t timestamp_old_2;
  
  /* From sys/sysinfo.h: */
  /* Structure which can hold all the CPU info kstat provides */
  cpu_stat_t cs;
  
  /* Counters */
  int cpu_slot = 0;
  int cpu_num = 0;
  
  /* Variables end here */
  
  /* Get time */
  time(&timestamp_new);
  
  /* If we have just gotten the data, return the values from last run (skip if) */
  /* This happens on a snmpwalk request.  No need to read the kstat again */
  /* if we just did it less than a second ago */
  /* +1 b/c we sleep(1) */
  
  if (timestamp_new > (timestamp_old_2 + 1))
    {
      
      /* Update timer */
      timestamp_old_2 = timestamp_new;
      
      /* Look thru all the cpu slots on the machine whether they holds a CPU */
      /* and if so, get the data from that CPU */
      /* Important: num_cpu might be 12.  Then cpu_num is from 0 to 11, not 1 to 12 ! */
      for (cpu_slot=0;cpu_num<num_cpu;cpu_slot++)
	{ 
	  /* If ksp is NULL we don't have a CPU :) */
	  /* For MP machines: We hit an empty CPU board, trying next one... */
	  if ((ksp = kstat_lookup(kstat_fd, string_cpu_stat, cpu_slot, NULL)) != NULL)
	    {
	      /* Yeah, we found a CPU. */
	      /* Read data from kstat into cs structure */
	      /* kc is the control structure, ksp the kstat we are reading */
	      /* and cs the buffer we are writing to. */
	      /* Memory allocation is done automagically by the kstat library. */
	      
	      if (kstat_read(kstat_fd, ksp, &cs) == -1)
		{
		  snmp_log(LOG_ERR, "vmstat_solaris2 (getCPU): error getting cs.\n");
		  return(-1);
		}
	      
	      /* CPU_STATES defined in sys/sysinfo.h */
	      
	      for (i=0 ; i < CPU_STATES ; i++)
		{
		  cpu_state_old[cpu_num][i] = cs.cpu_sysinfo.cpu[i];
		}
	      
	      /* Counter for number of CPUs found. */
	      /* cpu_slot might go from 0 to 15 (available CPU slots) while */
	      /* cpu_num keeps track about actual number of CPUs read. */
	      cpu_num++;
	      
	    } /* end else */
	} /* end for */
      
      /* Trying not to destroy the probed object with the probe... */
      /* 1 sec delay between getting values from cs structure. */
      sleep(1);

      /* Look thru all the cpu slots on the machine whether it holds a CPU */
      /* Important: num_cpu might be 12.  Then cpu_num is from 0 to 11, not 1 to 12 ! */
      /* This is the same loop like above before the sleep(1).  Could be improved to */
      /* cache the CPU slots that hold a CPU or similar */ 
      
      /* We have to start over again */
      cpu_num = 0;
      

      /* Look thru all the cpu slots on the machine whether they holds a CPU */
      /* and if so, get the data from that CPU */
      /* Important: num_cpu might be 12.  Then cpu_num is from 0 to 11, not 1 to 12 ! */
      for (cpu_slot=0;cpu_num<num_cpu;cpu_slot++)
	{  

       	  /* If ksp is NULL we don't have a CPU :) */
	  /* For MP machines: We hit an empty CPU board, trying next one... */
	  if ((ksp = kstat_lookup(kstat_fd, string_cpu_stat, cpu_slot, NULL)) != NULL)
	    {
	      /* Yeah, we found a CPU. */
	      /* Read data from kstat into cs structure */
	      /* kc is the control structure, ksp the kstat we are reading */
	      /* and cs the buffer we are writing to. */
	      /* Memory allocation is done automagically by the kstat library. */
	      
	      /* Update cs structure with new kstat values after we are awake again. */
	      
	      if (kstat_read(kstat_fd, ksp, &cs) == -1)
		{
		  snmp_log(LOG_ERR, "vmstat_solaris2 (getCPU): error getting cs.\n");
		  return(-1);
		}
	       
	      /* CPU_STATES defined in sys/sysinfo.h */
	      /* Get new samples after waiting for counters to increments */
	      /* thru system activity. */
	      /* Reset CPU activity counter */
	      cpu_sum[cpu_num] = 0;
	      
	      
	      /* Get new CPU data */
	      for (i=0 ; i < CPU_STATES ; i++)
		{
		  cpu_state[cpu_num][i] = cs.cpu_sysinfo.cpu[i] - cpu_state_old[cpu_num][i];
		  cpu_sum[cpu_num] += cpu_state[cpu_num][i];
		}
	      
	      /* Calculate percentage values for CPU utilisation */
	      for (i=0 ; i < CPU_STATES ; i++)
		{
		  /* Cast from ulong to float */
		  cpu_perc[cpu_num][i]= (((float) cpu_state[cpu_num][i] / cpu_sum[cpu_num]) * 100);
		}
	      
	      /* MIB wants CPU_SYSTEM which is CPU_KERNEL + CPU_WAIT */
	      cpu_perc[cpu_num][CPU_SYSTEM] = cpu_perc[cpu_num][CPU_KERNEL] + cpu_perc[cpu_num][CPU_WAIT];
	      
	      /* Increment CPUs found count */
	      cpu_num++;
	      
	    } /* end else */
	} /* end for */

      /* Calculate avarages here FIXME */
      /* First sum up all values */
      /* Calculate percentage values for CPU utilisation */
      for (i=0 ; i < CPU_STATES ; i++)
	{
	  /* Reset counter */
	  cpu_perc_avg[i] = 0;
	  for (cpu_num=0;cpu_num<num_cpu;cpu_num++)
	    {
	      cpu_perc_avg[i] += cpu_perc[cpu_num][i];
	    } /* end for */
	  cpu_perc_avg[i] /= (float) num_cpu;
	} /* end for */
      
      cpu_perc_avg[CPU_SYSTEM] = cpu_perc_avg[CPU_KERNEL] + cpu_perc_avg[CPU_WAIT];
      
    } /* end if (timestamp_new > (timestamp_old_2 + 1)) */
  
  /* Returns the requested percentage value, dropping fractions b/c casting to long */
  return((long) cpu_perc_avg[state]);
  
} /* end function getCPU */


/* *var_extensible_vmstat starts here */
/* The guts of the module, this routine gets called to service a request */
unsigned char *var_extensible_vmstat(struct variable *vp,
                                     oid *name,
                                     size_t *length,
                                     int exact,
                                     size_t *var_len,
                                     WriteMethod **write_method)
{
  static long long_ret;
  static char errmsg[300];
  
  long_ret = 0;  /* set to 0 as default */

  /* generic check whether the options passed make sense and whether the */
  /* right variable is requested */
  if (header_generic(vp,name,length,exact,var_len, write_method) != MATCH_SUCCEEDED)
    {
      return(NULL);
    }

  /* The function that actually returns s.th. */
  switch (vp->magic) {
  case MIBINDEX:
    long_ret = 1;
    return((u_char *) (&long_ret));
  case ERRORNAME:    /* dummy name */
    sprintf(errmsg,"systemStats");
    *var_len = strlen(errmsg);
    return((u_char *) (errmsg));
  case SWAPIN:
    long_ret = getMisc(SWAPIN);
    return((u_char *) (&long_ret));
  case SWAPOUT:
    long_ret = getMisc(SWAPOUT);
    return((u_char *) (&long_ret));
  case IOSENT:
    long_ret = getMisc(IOSENT);
    return((u_char *) (&long_ret));
  case IORECEIVE:
    long_ret = getMisc(IORECEIVE);
    return((u_char *) (&long_ret));
  case SYSINTERRUPTS:
    long_ret = getMisc(SYSINTERRUPTS);
    return((u_char *) (&long_ret));
  case SYSCONTEXT:
    long_ret = getMisc(SYSCONTEXT);
    return((u_char *) (&long_ret));
  case CPUUSER:
    long_ret = getCPU(CPU_USER);
    return((u_char *) (&long_ret));
  case CPUSYSTEM:
    long_ret = getCPU(CPU_SYSTEM);
    return((u_char *) (&long_ret));
  case CPUIDLE:
    long_ret = getCPU(CPU_IDLE);
    return((u_char *) (&long_ret));
    /* reserved for future use */
    /*
      case ERRORFLAG:
      return((u_char *) (&long_ret));
      case ERRORMSG:
      return((u_char *) (&long_ret));
      */
    
  default:
    snmp_log(LOG_ERR,"vmstat_solaris2: Error in request, no match found.\n");
  }
  return(NULL);
} /* *var_extensible_vmstat ends here */

/* Functions end here */

/* Program ends here */
