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
#include "struct.h"
#include "loadave.h"
#include "util_funcs.h"
#include "../kernel.h"
#include "read_config.h"
#include "auto_nlist.h"

double maxload[3];

void	init_loadave( )
{
}

void loadave_parse_config(word,cptr)
  char *word;
  char *cptr;
{
  int i;
  
  for(i=0;i<=2;i++) {
    if (cptr != NULL)
      maxload[i] = atof(cptr);
    else
      maxload[i] = maxload[i-1];
    cptr = skip_not_white(cptr);
    cptr = skip_white(cptr);
  }
}

void loadave_free_config __P((void)) {
  int i;
  
  for (i=0; i<=2;i++)
    maxload[i] = DEFMAXLOADAVE;
}

  
unsigned char *var_extensible_loadave(vp, name, length, exact, var_len, write_method)
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
#ifdef HAVE_SYS_FIXPOINT_H
  fix favenrun[3];
#endif
#if defined(ultrix) || defined(sun) || defined(__alpha)
#if defined(sun) || defined(__alpha)
  long favenrun[3];
#define FIX_TO_DBL(_IN) (((double) _IN)/((double) FSCALE))
#endif
  int i;
#endif
  double avenrun[3];
  
  if (!checkmib(vp,name,length,exact,var_len,write_method,3))
    return(NULL);

  switch (vp->magic) {
    case MIBINDEX:
      long_ret = name[*length-1];
      return((u_char *) (&long_ret));
    case ERRORNAME:
      sprintf(errmsg,"Load-%d",((name[*length-1] == 1) ? 1 :
                                ((name[*length-1] == 2) ? 5 : 15)));
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
  }
#ifdef HAVE_GETLOADAVG
  if (getloadavg(avenrun, sizeof(avenrun) / sizeof(avenrun[0])) == -1)
    return(0);
#elif defined(linux)
  { FILE *in = fopen("/proc/loadavg", "r");
    if (!in) {
      fprintf (stderr, "snmpd: cannot open /proc/loadavg\n");
      return NULL;
    }
    fscanf(in, "%lf %lf %lf", &avenrun[0], &avenrun[1], &avenrun[2]);
    fclose(in);
  }
#elif defined(ultrix) || defined(sun) || defined(__alpha)
  if (auto_nlist(LOADAVE_SYMBOL,(char *) favenrun, sizeof(favenrun)) == 0)
    return(0);
  for(i=0;i<3;i++)
    avenrun[i] = FIX_TO_DBL(favenrun[i]);
#else
  if (auto_nlist(LOADAVE_SYMBOL,(char *) avenrun, sizeof(double)*3) == 0)
    return NULL;
#endif
  switch (vp->magic) {
    case LOADAVE:
      sprintf(errmsg,"%.2f",avenrun[name[*length-1]-1]);
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
    case LOADMAXVAL:
      sprintf(errmsg,"%.2f",maxload[name[*length-1]-1]);
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
    case ERRORFLAG:
      long_ret = (maxload[name[*length-1]-1] != 0 &&
                  avenrun[name[*length-1]-1] >= maxload[name[*length-1]-1]) ? 1 : 0;
      return((u_char *) (&long_ret));
    case ERRORMSG:
      if (maxload[name[*length-1]-1] != 0 &&
          avenrun[name[*length-1]-1] >= maxload[name[*length-1]-1]) {
        sprintf(errmsg,"%d min Load Average too high (= %.2f)",
                (name[*length-1] == 1)?1:((name[*length-1] == 2)?5:15),
                avenrun[name[*length-1]-1]);
      } else {
        errmsg[0] = 0;
      }
      *var_len = strlen(errmsg);
      return((u_char *) errmsg);
  }
  return NULL;
}

