#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#include <signal.h>
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
#if HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#if HAVE_SYS_VMMETER_H
#if !(defined(bsdi2) || defined(netbsd1))
#include <sys/vmmeter.h>
#endif
#endif
#if HAVE_SYS_CONF_H
#include <sys/conf.h>
#endif
#if HAVE_SYS_SWAP_H
#include <sys/swap.h>
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
#if HAVE_SYS_STATFS_H
#include <sys/statfs.h>
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
#if STDC_HEADERS
#include <string.h>
#endif

#include "mibincl.h"
#include "struct.h"
#include "errormib.h"
#include "util_funcs.h"
#include "auto_nlist.h"

static time_t errorstatustime=0;
static int errorstatusprior=0;
static char errorstring[STRMAX];

void
setPerrorstatus(to)
  char *to;
{
  char buf[STRMAX];
  extern int errno;
  
  sprintf(buf,"%s:  %s",to,strerror(errno));
  perror(to);
  seterrorstatus(buf,5);
}

void
seterrorstatus(to,prior)
  char *to;
  int prior;
{
  if (errorstatusprior <= prior ||
      (ERRORTIMELENGTH < (time(NULL) - errorstatustime))) {
    strcpy(errorstring,to);
    errorstatusprior = prior;
    errorstatustime = time(NULL);
  }
}

void init_errormib(void) {

  /* define the structure we're going to ask the agent to register our
     information at */
  struct variable2 extensible_error_variables[] = {
    {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_errors, 1, {MIBINDEX}},
    {ERRORNAME, ASN_OCTET_STR, RONLY, var_extensible_errors, 1, {ERRORNAME}},
    {ERRORFLAG, ASN_INTEGER, RONLY, var_extensible_errors, 1, {ERRORFLAG}},
    {ERRORMSG, ASN_OCTET_STR, RONLY, var_extensible_errors, 1, {ERRORMSG}}
  };

  /* Define the OID pointer to the top of the mib tree that we're
     registering underneath */
  oid extensible_error_variables_oid[] = { EXTENSIBLEMIB,ERRORMIBNUM };

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("ucd_snmp/errormib", extensible_error_variables, \
               variable2, extensible_error_variables_oid);
}

  
unsigned char *var_extensible_errors(vp, name, length, exact, var_len, write_method)
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
    int			(**write_method) __P((int, u_char *, u_char, int, u_char *, oid *, int));
/* OUT - pointer to function to set variable, otherwise 0 */
{

  static long long_ret;
  static char errmsg[300];


  if (header_generic(vp,name,length,exact,var_len,write_method))
    return(NULL);

  errmsg[0] = 0;
  
  switch (vp->magic) {
    case MIBINDEX:
      long_ret = name[*length - 1];
      return((u_char *) (&long_ret));
    case ERRORNAME:
      strcpy(errmsg,"snmp");
      *var_len = strlen(errmsg);
      return((u_char *) errmsg);
    case ERRORFLAG:
      long_ret = (ERRORTIMELENGTH >= time(NULL)-errorstatustime) ? 1 : 0;
      return((u_char *) (&long_ret));
    case ERRORMSG:
      if ((ERRORTIMELENGTH >= time(NULL)-errorstatustime) ? 1 : 0) 
        strcpy(errmsg,errorstring);
      else
        errmsg[0] = 0;
      *var_len = strlen(errmsg);
      return((u_char *) errmsg);
  }
  return NULL;
}

