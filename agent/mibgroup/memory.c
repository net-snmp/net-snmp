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
#ifndef bsdi2
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
#include "mibdefs.h"

#include "memory.h"

int minimumswap;
static int pageshift;           /* log base 2 of the pagesize */

#ifdef linux
enum meminfo_row { meminfo_main = 0,
		   meminfo_swap };

enum meminfo_col { meminfo_total = 0, meminfo_used, meminfo_free,
		   meminfo_shared, meminfo_buffers, meminfo_cached
};
#define MEMINFO_FILE "/proc/meminfo"

static char buf[300];

/* This macro opens FILE only if necessary and seeks to 0 so that successive
   calls to the functions are more efficient.  It also reads the current
   contents of the file into the global buf.
*/
#define FILE_TO_BUF(FILE) {					\
    static int n, fd = -1;					\
    if (fd == -1 && (fd = open(FILE, O_RDONLY)) == -1) {	\
	close(fd);						\
	return 0;						\
    }								\
    lseek(fd, 0L, SEEK_SET);					\
    if ((n = read(fd, buf, sizeof buf - 1)) < 0) {		\
	close(fd);						\
	fd = -1;						\
	return 0;						\
    }								\
    buf[n] = '\0';						\
}

#define MAX_ROW 3	/* these are a little liberal for flexibility */
#define MAX_COL 7

unsigned** meminfo(void) {
    static unsigned *row[MAX_ROW + 1];		/* row pointers */
    static unsigned num[MAX_ROW * MAX_COL];	/* number storage */
    char *p;
    int i, j, k, l;
    
    FILE_TO_BUF(MEMINFO_FILE)
    if (!row[0])				/* init ptrs 1st time through */
	for (i=0; i < MAX_ROW; i++)		/* std column major order: */
	    row[i] = num + MAX_COL*i;		/* A[i][j] = A + COLS*i + j */
    p = buf;
    for (i=0; i < MAX_ROW; i++)			/* zero unassigned fields */
	for (j=0; j < MAX_COL; j++)
	    row[i][j] = 0;
    for (i=0; i < MAX_ROW && *p; i++) {		/* loop over rows */
	while(*p && !isdigit(*p)) p++;		/* skip chars until a digit */
	for (j=0; j < MAX_COL && *p; j++) {	/* scanf column-by-column */
	    l = sscanf(p, "%u%n", row[i] + j, &k);
	    p += k;				/* step over used buffer */
	    if (*p == '\n' || l < 1)		/* end of line/buffer */
		break;
	}
    }
/*    row[i+1] = NULL;	terminate the row list, currently unnecessary */
    return row;					/* NULL return ==> error */
}
unsigned memory(int index)
{
	unsigned **mem = meminfo();
	return mem[meminfo_main][index] / 1024;
}
unsigned memswap(int index)
{
	unsigned **mem = meminfo();
	return mem[meminfo_swap][index] / 1024;
}
#else
#define  KNLookup(nl_which, buf, s)   (klookup((int) memory_nl[nl_which].n_value, buf, s))
#define pagetok(size) ((size) << pageshift)

#define NL_TOTAL 0
#define NL_SWDEVT 1
#define NL_FSWDEVT 2
#define NL_NSWAPFS 3
#define NL_NSWAPDEV 4
#define NL_PHYSMEM 5

static struct nlist memory_nl[] = {
#if !defined(hpux) && !defined(solaris2)
  { "_total"},
  { "_swdevt"},
  { "_fswdevt"},
  { "_nswapfs"},
  { "_nswapdev"},
  { "_physmem"},
#else
  { "total"},
  { "swdevt"},
  { "fswdevt"},
  { "nswapfs"},
  { "nswapdev"},
  { "physmem"},
#endif
  { 0 }
};
#endif

void init_memory()
{
  int pagesize;
#ifndef linux
  init_nlist( memory_nl );

#ifndef bsdi2
  if (KNLookup(NL_NSWAPDEV,(int *) &nswapdev, sizeof(nswapdev))
      == NULL)
    return;
  if (KNLookup(NL_NSWAPFS,(int *) &nswapfs, sizeof(nswapfs))
      == NULL)
    return;
#endif
  pagesize = 1 << PGSHIFT;
  pageshift = 0;
  while (pagesize > 1) {
    pageshift++;
    pagesize >>= 1;
  }
  pageshift -= 10;
#endif
}

#define SWAPGETLEFT 0
#define SWAPGETTOTAL 1

int nswapdev=10;            /* taken from <machine/space.h> */
int nswapfs=10;            /* taken from <machine/space.h> */

int getswap(rettype)
  int rettype;
{
  int spaceleft=0, spacetotal=0, i, fd;

#ifdef linux
	spaceleft = memswap(meminfo_free);
	spacetotal = memswap(meminfo_total);
#else
#ifdef bsdi2
  struct swapstats swapst;
  size_t size = sizeof(swapst);
  static int mib[] = { CTL_VM, VM_SWAPSTATS };
  if (sysctl(mib, 2, &swapst, &size, NULL, 0) < 0) return (0);
  spaceleft = swapst.swap_free / 2;
  spacetotal = swapst.swap_total / 2;	
#else
  struct swdevt swdevt[100];
  struct fswdevt fswdevt[100];
  FILE *file;
  struct extensible ex;
  
  if (KNLookup(NL_SWDEVT,(int *) swdevt, sizeof(struct swdevt)*nswapdev)
      == NULL)
    return(0);
  for (i=0; i < nswapdev; i++) {
    if (swdevt[i].sw_enable) {
#ifdef STRUCT_SWDEVT_HAS_SW_NBLKSENABLED
      spacetotal += swdevt[i].sw_nblksenabled;
#else
      spacetotal += swdevt[i].sw_nblks;
#endif
      spaceleft += (swdevt[i].sw_nfpgs * 4);
    }
  }
  if (KNLookup(NL_FSWDEVT,(int *) fswdevt, sizeof(struct fswdevt)*nswapfs)
      == NULL)
    return(0);
  for (i=0; i < nswapfs; i++) {
    if (fswdevt[i].fsw_enable) {
      spacetotal += (fswdevt[i].fsw_limit * 2048);  /* 2048=bytes per page? */
      spaceleft += (fswdevt[i].fsw_limit * 2048 -
                    ((fswdevt[i].fsw_allocated - fswdevt[i].fsw_min) * 37));
      /* 37 = calculated value I know it makes no sense, nor is it accurate */
    }
  }
  /* this is a real hack.  I need to get the hold info from swapinfo, but
     I can't figure out how to read it out of the kernel directly
     -- Wes */
  strcpy(ex.command,"/etc/swapinfo -h");
  if (fd = get_exec_output(&ex)) {
    file = fdopen(fd,"r");
    for (i=1;i <= 2 && fgets(ex.output,STRMAX,file) != NULL; i++);
    if (fgets(ex.output,STRMAX,file) != NULL) {
      spaceleft -= atoi(&ex.output[14]);
    }
    fclose(file);
    close(fd);
  } else {
    return(NULL);
  }
#endif
#endif
  switch
    (rettype) {
    case SWAPGETLEFT:
      return(spaceleft);
    case SWAPGETTOTAL:
      return(spacetotal);
  }
}

unsigned char *var_extensible_mem(vp, name, length, exact, var_len, write_method)
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

  oid newname[30];
  int count, result,i, rtest=0;
  register int interface;
  struct myproc *proc;
  static long long_ret;
  static char errmsg[300];
#ifndef linux
  struct vmtotal total;
#endif

  if (!checkmib(vp,name,length,exact,var_len,write_method,newname,1))
    return(NULL);
#ifndef linux
#ifdef bsdi2
    /* sum memory statistics */
    {
	size_t size = sizeof(total);
	static int mib[] = { CTL_VM, VM_TOTAL };
	if (sysctl(mib, 2, &total, &size, NULL, 0) < 0) return (0);
    }
#else
  if (KNLookup(NL_TOTAL, (int *)&total, sizeof(total)) == NULL) {
    return(0);
  }
#endif
#endif
  switch (vp->magic) {
    case MIBINDEX:
      long_ret = 1;
      return((u_char *) (&long_ret));
    case ERRORNAME:    /* dummy name */
      sprintf(errmsg,"swap");
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
    case MEMTOTALSWAP:
      long_ret = getswap(SWAPGETTOTAL);
      return((u_char *) (&long_ret));
    case MEMUSEDSWAP:
      long_ret = getswap(SWAPGETLEFT);
      return((u_char *) (&long_ret));
    case MEMSWAPMINIMUM:
      long_ret = minimumswap;
      return((u_char *) (&long_ret));
    case MEMTOTALREAL:
#ifdef linux
	long_ret = memory(meminfo_total);
#else
#ifdef bsdi2
      {	
	size_t size = sizeof(long_ret);
	static int mib[] = { CTL_HW, HW_PHYSMEM };
	if (sysctl(mib, 2, &long_ret, &size, NULL, 0) < 0) 
	  long_ret = 0; else long_ret = long_ret / 1024;
      }	
#else
      /* long_ret = pagetok((int) total.t_rm); */
      if(KNLookup(NL_PHYSMEM,(int *) &result,sizeof(result)) == NULL)
        return NULL;
      long_ret = result*1000;
#endif
#endif
      return((u_char *) (&long_ret));
    case MEMUSEDREAL:
#ifdef linux
	long_ret = memory(meminfo_used);
#else
      long_ret = pagetok((int) total.t_arm);
#endif
      return((u_char *) (&long_ret));
#ifndef linux
    case MEMTOTALSWAPTXT:
#ifndef bsdi2
      long_ret = pagetok(total.t_vmtxt);
#endif
      return((u_char *) (&long_ret));
    case MEMUSEDSWAPTXT:
#ifndef bsdi2
      long_ret = pagetok(total.t_avmtxt);
#endif
      return((u_char *) (&long_ret));
    case MEMTOTALREALTXT:
#ifndef bsdi2
      long_ret = pagetok(total.t_rmtxt);
#endif
      return((u_char *) (&long_ret));
    case MEMUSEDREALTXT:
#ifndef bsdi2
      long_ret = pagetok(total.t_armtxt);
#endif
      return((u_char *) (&long_ret));
#endif
    case MEMTOTALFREE:
#ifdef linux
	long_ret = memory(meminfo_free);
#else
      long_ret = pagetok(total.t_free);
#endif
      return((u_char *) (&long_ret));
    case ERRORFLAG:
      long_ret = getswap(SWAPGETLEFT);
      long_ret = (long_ret > minimumswap)?0:1;
      return((u_char *) (&long_ret));
    case ERRORMSG:
      long_ret = getswap(SWAPGETLEFT);
      if ((long_ret > minimumswap)?0:1)
        sprintf(errmsg,"Running out of swap space (%d)",getswap(SWAPGETLEFT));
      else
        errmsg[0] = 0;
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
  }
  return NULL;
}

