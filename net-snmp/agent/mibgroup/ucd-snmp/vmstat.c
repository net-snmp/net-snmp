#include <config.h>

#if HAVE_LIMITS_H
#include <limits.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <ctype.h>
#include <signal.h>
#if HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#if HAVE_SYS_VMMETER_H
#if !defined(bsdi2) && !defined(netbsd1)
#include <sys/vmmeter.h>
#endif
#endif
#if HAVE_SYS_CONF_H
#include <sys/conf.h>
#endif
#if HAVE_SYS_FS_H
#include <sys/fs.h>
#else
#if HAVE_UFS_FS_H
#include <ufs/fs.h>
#else
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_SYS_VNODE_H
#include <sys/vnode.h>
#endif
#ifdef HAVE_UFS_UFS_QUOTA_H
#include <ufs/ufs/quota.h>
#endif
#ifdef HAVE_UFS_UFS_INODE_H
#include <ufs/ufs/inode.h>
#endif
#if HAVE_UFS_FFS_FS_H
#include <ufs/ffs/fs.h>
#endif
#endif
#endif
#if HAVE_MTAB_H
#include <mtab.h>
#endif
#include <sys/stat.h>
#include <errno.h>
#if HAVE_FSTAB_H
#include <fstab.h>
#endif
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if (!defined(HAVE_STATVFS)) && defined(HAVE_STATFS)
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#endif
#define statvfs statfs
#endif
#if HAVE_VM_SWAP_PAGER_H
#include <vm/swap_pager.h>
#endif
#if HAVE_SYS_FIXPOINT_H
#include <sys/fixpoint.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
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

#include "mibincl.h"
#include "mibdefs.h"
#include "struct.h"
#include "util_funcs.h"
#include "vmstat.h"
#include "auto_nlist.h"

static FindVarMethod var_extensible_vmstat;

void init_vmstat(void)
{
  struct variable2 extensible_vmstat_variables[] = {
    {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_vmstat,1,{MIBINDEX}},
    {ERRORNAME, ASN_OCTET_STR, RONLY, var_extensible_vmstat, 1, {ERRORNAME }},
    {SWAPIN, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPIN}},
    {SWAPOUT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SWAPOUT}},
    {IOSENT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {IOSENT}},
    {IORECEIVE, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {IORECEIVE}},
    {SYSINTERRUPTS, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SYSINTERRUPTS}},
    {SYSCONTEXT, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {SYSCONTEXT}},
    {CPUUSER, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUUSER}},
    {CPUSYSTEM, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUSYSTEM}},
    {CPUIDLE, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {CPUIDLE}},
    {CPURAWUSER, ASN_COUNTER, RONLY, var_extensible_vmstat, 1, {CPURAWUSER}},
    {CPURAWNICE, ASN_COUNTER, RONLY, var_extensible_vmstat, 1, {CPURAWNICE}},
    {CPURAWSYSTEM, ASN_COUNTER, RONLY, var_extensible_vmstat, 1, {CPURAWSYSTEM}},
    {CPURAWIDLE, ASN_COUNTER, RONLY, var_extensible_vmstat, 1, {CPURAWIDLE}},
/* Future use: */
/*
    {ERRORFLAG, ASN_INTEGER, RONLY, var_extensible_vmstat, 1, {ERRORFLAG }},
    {ERRORMSG, ASN_OCTET_STR, RONLY, var_extensible_vmstat, 1, {ERRORMSG }}
*/
  };

  /* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
  oid vmstat_variables_oid[] = { EXTENSIBLEMIB,11 };

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("ucd-snmp/vmstat", extensible_vmstat_variables, variable2, \
               vmstat_variables_oid);

}



#define VMSTAT_FILE "/proc/stat"
#define BUFFSIZE 1024
static char buff[BUFFSIZE];

void getstat(unsigned long *cuse, unsigned long *cice, unsigned long *csys,
	     unsigned long *cide, unsigned *pin, unsigned *pout,
	     unsigned *swpin, unsigned *swpout, unsigned *itot, unsigned *i1,
	     unsigned *ct) 
{
  int statfd;

  if ((statfd=open(VMSTAT_FILE, O_RDONLY, 0)) != -1) {
    char* b;
    buff[BUFFSIZE-1] = 0;  /* ensure null termination in buffer */
    read(statfd,buff,BUFFSIZE-1);
    close(statfd);
    *itot = 0; 
    *i1 = 1;   /* ensure assert below will fail if the sscanf bombs */
    b = strstr(buff, "cpu ");
    sscanf(b, "cpu  %lu %lu %lu %lu", cuse, cice, csys, cide);
    b = strstr(buff, "page ");
    sscanf(b, "page %u %u", pin, pout);
    b = strstr(buff, "swap ");
    sscanf(b, "swap %u %u", swpin, swpout);
    b = strstr(buff, "intr ");
    sscanf(b, "intr %u %u", itot, i1);
    b = strstr(buff, "ctxt ");
    sscanf(b, "ctxt %u", ct);
  }
  else {
    snmp_log_perror("/proc/stat");
  }
}

enum vmstat_index { swapin = 0,    swapout, 
		    iosent,        ioreceive, 
		    sysinterrupts, syscontext,
		    cpuuser,       cpusystem, cpuidle,
                    cpurawuser,    cpurawnice,
                    cpurawsystem,  cpurawidle };

unsigned vmstat (int iindex) 
{
  unsigned long cpu_use[2], cpu_nic[2], cpu_sys[2], cpu_idl[2];
  double duse,dsys,didl,ddiv,divo2;
  double druse,drnic,drsys,dridl;
  unsigned int pgpgin[2], pgpgout[2], pswpin[2], pswpout[2];
  unsigned int inter[2],ticks[2],ctxt[2];
  unsigned int hz;

  getstat(cpu_use,cpu_nic,cpu_sys,cpu_idl,
	  pgpgin,pgpgout,pswpin,pswpout,
          inter,ticks,ctxt);
  duse= *(cpu_use)+ *(cpu_nic);
  dsys= *(cpu_sys);
  didl= (*(cpu_idl));
  ddiv= (duse+dsys+didl);
  hz=sysconf(_SC_CLK_TCK); /* get ticks/s from system */
  divo2= ddiv/2;
  druse= *(cpu_use);
  drnic= *(cpu_nic);
  drsys= *(cpu_sys);
  dridl= (*(cpu_idl));

  switch (iindex) {
  case swapin:
    return (*(pswpin)*4*hz+divo2)/ddiv;
  case swapout:
    return (*(pswpout)*4*hz+divo2)/ddiv;
  case iosent:
    return (*(pgpgin)*hz+divo2)/ddiv;
  case ioreceive:
    return (*(pgpgout)*hz+divo2)/ddiv;
  case sysinterrupts:
    return (*(inter)*hz+divo2)/ddiv;
  case syscontext:
    return (*(ctxt)*hz+divo2)/ddiv;
  case cpuuser:
    return (100*duse/ddiv);
  case cpusystem:
    return (100*dsys/ddiv);
  case cpuidle:
    return (100*didl/ddiv);
  case cpurawuser:
    return druse;
  case cpurawnice:
    return drnic;
  case cpurawsystem:
    return drsys;
  case cpurawidle:
    return dridl;
  default:
    return -1;
  }
}

static
unsigned char *var_extensible_vmstat(struct variable *vp,
				     oid *name,
				     size_t *length,
				     int exact,
				     size_t *var_len,
				     WriteMethod **write_method)
{

  static long long_ret;
  static char errmsg[300];
#ifndef linux
  struct vmtotal total;
#endif

  long_ret = 0;  /* set to 0 as default */

  if (header_generic(vp,name,length,exact,var_len,write_method))
    return(NULL);
  switch (vp->magic) {
    case MIBINDEX:
      long_ret = 1;
      return((u_char *) (&long_ret));
    case ERRORNAME:    /* dummy name */
      sprintf(errmsg,"systemStats");
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
    case SWAPIN:
#ifdef linux
      long_ret = vmstat(swapin);
#endif
      return((u_char *) (&long_ret));
    case SWAPOUT:
#ifdef linux
      long_ret = vmstat(swapout);
#endif
      return((u_char *) (&long_ret));
    case IOSENT:
#ifdef linux
      long_ret = vmstat(iosent);
#endif
      return((u_char *) (&long_ret));
    case IORECEIVE:
#ifdef linux
	long_ret = vmstat(ioreceive);
#endif
      return((u_char *) (&long_ret));
    case SYSINTERRUPTS:
#ifdef linux
	long_ret = vmstat(sysinterrupts);
#endif
      return((u_char *) (&long_ret));
    case SYSCONTEXT:
#ifdef linux
      long_ret = vmstat(syscontext);
#endif
      return((u_char *) (&long_ret));
    case CPUUSER:
#ifdef linux
      long_ret = vmstat(cpuuser);
#endif
      return((u_char *) (&long_ret));
    case CPUSYSTEM:
#ifdef linux
      long_ret = vmstat(cpusystem);
#endif
      return((u_char *) (&long_ret));
    case CPUIDLE:
#ifdef linux
      long_ret = vmstat(cpuidle);
#endif
      return((u_char *) (&long_ret));
    case CPURAWUSER:
#ifdef linux
      long_ret = vmstat(cpurawuser);
#endif
      return((u_char *) (&long_ret));
    case CPURAWNICE:
#ifdef linux
      long_ret = vmstat(cpurawnice);
#endif
      return((u_char *) (&long_ret));
    case CPURAWSYSTEM:
#ifdef linux
      long_ret = vmstat(cpurawsystem);
#endif
      return((u_char *) (&long_ret));
    case CPURAWIDLE:
#ifdef linux
      long_ret = vmstat(cpurawidle);
#endif
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

