/*
 *  vmstat_solaris2.c
 *  UCD SNMP module for sysStatus section of UCD-SNMP-MIB for SunOS/Solaris
 *  Jochen Kmietsch <jochen.kmietsch@gmx.de>
 *  Uses some ideas from xosview and top
 *  Some comments paraphrased from the SUN man pages 
 *  Currently only works correctly for single-CPU machines
 *  On MP machines it returns values for first CPU found
 *  Version 0.1 initial release Dec 1999 (snapshot 19991222215300)
 *
 */

/* Includes start here */

/* Standard includes */
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <time.h>
     
/* UCD-SNMP config details */
#include <config.h>

/* List of which modules are supported */
#include "mib_module_config.h"

/* kstat and sysinfo structs */
#include <kstat.h>
#include <sys/sysinfo.h>

/* Header file for this module */
#include "vmstat_solaris2.h"

/* Includes end here */

/* Global variables start here */

/* From kstat.h: */
/* Provides access to the kernel statistics library by */
/* initializing a kstat control structure and returning a pointer */
/* to this structure.  This pointer must be used as the kc argument in */
/* following function calls from libkstat */
/* Pointer to structure to be opened with kstat_open in main procedure */
/* We share this one with kernel_sunos5, where it's defined, and memory_solaris2 */
extern kstat_ctl_t *kstat_fd;
kstat_ctl_t *kctl;

/* Global variables end here */

/* Functions start here */

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

  /* Re-use kstat control from kernel_sunos5 */
  if ((kctl = kstat_fd) == NULL)
    {
      snmp_log(LOG_ERR,"vmstat_solaris2 (init): Could not open kstat control.\n");
    }
}
/* init_vmstat_solaris2 ends here */


/* Data collection function getMisc starts here */
/* Get data from kernel and returns misc data / sec */
/* "what" is the data requested, see the vp switch statement */
long getMisc(int what)
{
  /* From sys/kstat.h (included from kstat.h): */
  /* Pointer to current kstat */
  kstat_t *ksp;
  
  /* Declared static so they don't die with the function */
  /* This way we can re-use them if they are new enough */
  static ulong swapin;
  static ulong swapout;
  static ulong blocks_read;
  static ulong blocks_write;
  static ulong interrupts;
  static ulong context_sw;
  
  /* From time.h, get seconds since start of UNIX time... */
  time_t timestamp_new;
  static time_t timestamp_old_1;
    
  /* From sys/sysinfo.h: */
  /* Structure which can hold all the CPU info kstat provides */ 
  cpu_stat_t cs;
  
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
      
      /* If ksp is NULL we don't have a CPU :) */
      /* For MP machines: We hit an empty CPU board, trying next one... */
      /* Right now instance is -1, so return the first one found */
      /* kstat_lookup: look for a kstat by module, instance and name */
      if ((ksp = kstat_lookup(kctl, "cpu_stat", -1, NULL)) == NULL)
	{
	  snmp_log(LOG_ERR, "vmstat_solaris2 (getMisc): kstat not found.");
	}
      
      /* Read data from kstat into cs structure */
      /* kc is the control structure, ksp the kstat we are reading */
      /* and cs the buffer we are writing to. */
      /* Memory allocation is done automagically by the kstat library. */
      if (kstat_read(kctl, ksp, &cs) == -1)
	{
	  snmp_log(LOG_ERR, "vmstat_solaris2 (getMisc): failure to init cs structure.");
	}
      
      /* Get kb/s swapped in */
      /* cs returns pages, getpagesize size in bytes */
      swapin = ((cs.cpu_vminfo.pgswapin * getpagesize()) / 1024) ;
      /* Get kb/s swapped out */
      swapout = ((cs.cpu_vminfo.pgswapout * getpagesize()) / 1024) ;
      /* Get number of blocks written */
      blocks_write = cs.cpu_sysinfo.bwrite;
      /* Get number of blocks read */
      blocks_read = cs.cpu_sysinfo.bread;
      /* Get number of Interrupts (since boot) */
      interrupts = cs.cpu_sysinfo.intr;
      /* Get number of conext switches (since boot) */
      context_sw = cs.cpu_sysinfo.pswitch;
      
      /* Trying not to destroy the probed object with the probe... */
      /* 1 sec delay between getting values from cs structure. */
      sleep(1);
      
      /* Update cs structure with new kstat values after we are awake again. */
      if (kstat_read(kctl, ksp, &cs) == -1)
	{
	  snmp_log(LOG_ERR, "vmstat_solaris2 (getMisc): failure to update cs structure.");
	  return(NULL);
	}
      
      /* Get new samples after waiting for counters to increments */
      /* thru system activity. */
      /* Get new number of pages swapped in, convert to kB and calculate difference */
      swapin = ((cs.cpu_vminfo.pgswapin * getpagesize()) / 1024) - swapin ;
      /* Get new number of pages swapped out, convert to kB and calculate difference */
      swapout = ((cs.cpu_vminfo.pgswapin * getpagesize()) / 1024) - swapout ;
      /* Get new number of blocks written and calculate difference */
      blocks_write = cs.cpu_sysinfo.bwrite - blocks_write;
      /* Get new number of blocks read and calculate difference */
      blocks_read = cs.cpu_sysinfo.bread - blocks_read;
      /* Get new number of interrupts and calculate difference */
      interrupts = cs.cpu_sysinfo.intr - interrupts;
      /* Get new number of context switches and calculate difference */
      context_sw = cs.cpu_sysinfo.pswitch - context_sw;
      
    } /* end if (timestap_new > (timestamp_old_1 + 1)) */
  

  /* Return the requested variable, casting to long */
  switch (what)
    {
    case SWAPIN:
      return((long) swapin);
    case SWAPOUT:
      return((long) swapout);
    case IOSENT:
      return((long) blocks_write);
    case IORECEIVE:
      return((long) blocks_read);
    case SYSINTERRUPTS:
      return((long) interrupts);
    case SYSCONTEXT:
      return((long) context_sw);  
    default:
      snmp_log(LOG_ERR,"vmstat_solaris2 (getMisc): No data found.");
      return(-1);
    } /* end switch */

} /* end function getMisc */

/* getCPU: get percentages for CPU utilisation */
/* state: CPU_IDLE, CPU_USER, CPU_KERNEL + CPU_WAIT = CPU_SYSTEM -> 0, 1, 4 */

long getCPU(int state)
{
  /* From sys/kstat.h (included from kstat.h): */
  /* Pointer to current kstat */
  kstat_t *ksp;
  
  /* As always, we need s.th. to count on, aehm, by */
  int i=0;
  
  ulong cpu_sum = 0;
  ulong cpu_state[CPU_STATES];
  ulong cpu_state_old[CPU_STATES];
  /* Since MIB wants CPU_SYSTEM, see above */
  static float cpu_perc[CPU_STATES +1];

  /* From time.h, get seconds since start of UNIX time... */
  time_t timestamp_new;
  static time_t timestamp_old_2;
  
  /* From sys/sysinfo.h: */
  /* Structure which can hold all the CPU info kstat provides */
  cpu_stat_t cs;

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
      
      /* If ksp is NULL we don't have a CPU :) */
      /* For MP machines: We hit an empty CPU board, trying next one... */
      /* Right now instance is -1 so we return values for first CPU found */
      
      if ((ksp = kstat_lookup(kctl, "cpu_stat", -1, NULL)) == NULL)
	{
	  snmp_log(LOG_ERR, "vmstat_solaris2 (getCPU): kstat not found.");
	  return(0);
	}
      
      /* Yeah, we found a CPU. */
      /* Read data from kstat into cs structure */
      /* kc is the control structure, ksp the kstat we are reading */
      /* and cs the buffer we are writing to. */
      /* Memory allocation is done automagically by the kstat library. */
      
      if (kstat_read(kctl, ksp, &cs) == -1)
	{
	  snmp_log(LOG_ERR, "vmstat_solaris2 (getCPU): error getting cs.");
	  return(0);
	}
      
      /* CPU_STATES defined in sys/sysinfo.h */
      
      for (i=0 ; i < CPU_STATES ; i++)
	{
	  cpu_state_old[i] = cs.cpu_sysinfo.cpu[i];
	}
      
      /* Trying not to destroy the probed object with the probe... */
      /* 1 sec delay between getting values from cs structure. */
      sleep(1);
      
      /* Update cs structure with new kstat values after we are awake again. */
      kstat_read(kctl, ksp, &cs);
      
      /* Get new samples after waiting for counters to increments */
      /* thru system activity. */
      /* Reset CPU activity counter */
      cpu_sum = 0;
      
      /* Get new CPU data */
      for (i=0 ; i < CPU_STATES ; i++)
	{
	  cpu_state[i] = cs.cpu_sysinfo.cpu[i] - cpu_state_old[i];
	  cpu_sum += cpu_state[i];
	}
      
      /* Calculate percentage values for CPU utilisation */
      for (i=0 ; i < CPU_STATES ; i++)
	{
	  /* Cast from ulong to float */
	  cpu_perc[i]= (((float) cpu_state[i] / cpu_sum) * 100);
	}
      
      /* MIB wants CPU_SYSTEM which is CPU_KERNEL + CPU_WAIT */
      cpu_perc[CPU_SYSTEM] = cpu_perc[CPU_KERNEL] + cpu_perc[CPU_WAIT];

    } /* end if (timestamp_new > (timestamp_old_2 + 1)) */
  
  /* Returns the requested percentage value, dropping fractions b/c casting to long */
  return((long) cpu_perc[state]);
  
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
      snmp_log(LOG_ERR,"vmstat_solaris2 (var_extensible_vmstat): Header check failed.\n");
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
