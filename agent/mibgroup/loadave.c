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
#include <nlist.h>
#if HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#if HAVE_SYS_VMMETER_H
#if !(defined(bsdi2) || defined(netbsd1))
#include <sys/vmmeter.h>
#endif
#endif
#if HAVE_SYS_CONF_H
#include <sys/conf.h>
#endif
#include <sys/param.h>
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
#include "loadave.h"
#include "util_funcs.h"
#include "../kernel.h"
#include "read_config.h"

#define  KNLookup(nl_which, buf, s)   (klookup((int) loadave_nl[nl_which].n_value, buf, s))

double maxload[3];

#ifndef linux
static struct nlist loadave_nl[] = {
#define NL_AVENRUN 0
#if !defined(hpux) && !defined(solaris2) && !defined(__sgi)
  { "_avenrun"},
#else
  { "avenrun"},
#endif
  { 0 }
};
#endif

void	init_loadave( )
{
#ifndef linux
    init_nlist( loadave_nl );
#endif
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

  oid newname[30];
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
  
  if (!checkmib(vp,name,length,exact,var_len,write_method,newname,3))
    return(NULL);

  switch (vp->magic) {
    case MIBINDEX:
      long_ret = newname[*length-1];
      return((u_char *) (&long_ret));
    case ERRORNAME:
      sprintf(errmsg,"Load-%d",((newname[*length-1] == 1) ? 1 :
                                ((newname[*length-1] == 2) ? 5 : 15)));
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
  }
#ifdef HAVE_GETLOADAVG
  if (getloadavg(avenrun, sizeof(avenrun) / sizeof(avenrun[0])) == -1)
    return(0);
#else
#if defined(ultrix) || defined(sun) || defined(__alpha)
  if (KNLookup(NL_AVENRUN,(char *) favenrun, sizeof(favenrun)) == 0)
    return(0);
  for(i=0;i<3;i++)
    avenrun[i] = FIX_TO_DBL(favenrun[i]);
#else
#ifdef linux
  { FILE *in = fopen("/proc/loadavg", "r");
    if (!in) {
      fprintf (stderr, "snmpd: cannot open /proc/loadavg\n");
      return NULL;
    }
    fscanf(in, "%lf %lf %lf", &avenrun[0], &avenrun[1], &avenrun[2]);
    fclose(in);
  }
#else
  if (KNLookup(NL_AVENRUN,(char *) avenrun, sizeof(double)*3) == 0)
    return NULL;
#endif /* !linux */
#endif /* !HAVE_GETLOADAVG */
#endif /* HAVE_GETLOADAVG */
  switch (vp->magic) {
    case LOADAVE:
      sprintf(errmsg,"%.2f",avenrun[newname[*length-1]-1]);
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
    case LOADMAXVAL:
      sprintf(errmsg,"%.2f",maxload[newname[*length-1]-1]);
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
    case ERRORFLAG:
      long_ret = (maxload[newname[*length-1]-1] != 0 &&
                  avenrun[newname[*length-1]-1] >= maxload[newname[*length-1]-1]) ? 1 : 0;
      return((u_char *) (&long_ret));
    case ERRORMSG:
      if (maxload[newname[*length-1]-1] != 0 &&
          avenrun[newname[*length-1]-1] >= maxload[newname[*length-1]-1]) {
        sprintf(errmsg,"%d min Load Average too high (= %.2f)",
                (newname[*length-1] == 1)?1:((newname[*length-1] == 2)?5:15),
                avenrun[newname[*length-1]-1]);
      } else {
        errmsg[0] = 0;
      }
      *var_len = strlen(errmsg);
      return((u_char *) errmsg);
  }
  return NULL;
}

