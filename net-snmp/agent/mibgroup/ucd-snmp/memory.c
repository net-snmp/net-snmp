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
#if HAVE_ASM_PAGE_H
#include <asm/page.h>
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
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
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
#include "memory.h"
#include "auto_nlist.h"
#include "read_config.h"
#include "agent_read_config.h"

int minimumswap;
#ifndef linux
static int pageshift;           /* log base 2 of the pagesize */
#endif

#define DEFAULTMINIMUMSWAP 16000  /* kilobytes */

static FindVarMethod var_extensible_mem;

void init_memory(void)
{
#ifndef linux
  int pagesize;
 auto_nlist(PHYSMEM_SYMBOL,0,0);
 auto_nlist(TOTAL_MEMORY_SYMBOL,0,0);
 auto_nlist(MBSTAT_SYMBOL,0,0);
 auto_nlist(SWDEVT_SYMBOL,0,0);
 auto_nlist(FSWDEVT_SYMBOL,0,0);
 auto_nlist(NSWAPFS_SYMBOL,0,0);
 auto_nlist(NSWAPDEV_SYMBOL,0,0);

#ifndef bsdi2
  if (auto_nlist(NSWAPDEV_SYMBOL,(char *) &nswapdev, sizeof(nswapdev)) == 0)
    return;
  if (auto_nlist(NSWAPFS_SYMBOL,(char *) &nswapfs, sizeof(nswapfs)) == 0)
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
  {      
  struct variable2 extensible_mem_variables[] = {
    {MIBINDEX, ASN_INTEGER, RONLY, var_extensible_mem,1,{MIBINDEX}},
    {ERRORNAME, ASN_OCTET_STR, RONLY, var_extensible_mem, 1, {ERRORNAME }},
    {MEMTOTALSWAP, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALSWAP}},
    {MEMAVAILSWAP, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMAVAILSWAP}},
    {MEMTOTALREAL, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALREAL}},
    {MEMAVAILREAL, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMAVAILREAL}},
    {MEMTOTALSWAPTXT, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALSWAPTXT}},
    {MEMUSEDSWAPTXT, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDSWAPTXT}},
    {MEMTOTALREALTXT, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALREALTXT}},
    {MEMUSEDREALTXT, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMUSEDREALTXT}},
    {MEMTOTALFREE, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMTOTALFREE}},
    {MEMSWAPMINIMUM, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMSWAPMINIMUM}},
    {MEMSHARED, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMSHARED}},
    {MEMBUFFER, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMBUFFER}},
    {MEMCACHED, ASN_INTEGER, RONLY, var_extensible_mem, 1, {MEMCACHED}},
    {ERRORFLAG, ASN_INTEGER, RONLY, var_extensible_mem, 1, {ERRORFLAG }},
    {ERRORMSG, ASN_OCTET_STR, RONLY, var_extensible_mem, 1, {ERRORMSG }}
  };

/* Define the OID pointer to the top of the mib tree that we're
   registering underneath */
  oid mem_variables_oid[] = { EXTENSIBLEMIB,MEMMIBNUM };

  /* register ourselves with the agent to handle our mib tree */
  REGISTER_MIB("ucd-snmp/memory", extensible_mem_variables, variable2, \
               mem_variables_oid);

  snmpd_register_config_handler("swap", memory_parse_config,
                                memory_free_config,"min-avail");
  }
}

void memory_parse_config(const char *token, char *cptr)
{
  minimumswap = atoi(cptr);
}

void memory_free_config (void) 
{
    minimumswap = DEFAULTMINIMUMSWAP;
}

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

unsigned** meminfo(void) 
{
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

unsigned memory(int iindex)
{
	unsigned **mem = meminfo();
        if (mem != NULL)
          return mem[meminfo_main][iindex] / 1024;
        else
          return -1;
}

unsigned memswap(int iindex)
{
	unsigned **mem = meminfo();
        if (mem != NULL)
          return mem[meminfo_swap][iindex] / 1024;
        else
          return -1;
}
#else
#define pagetok(size) ((size) << pageshift)
#endif

#define SWAPGETLEFT 0
#define SWAPGETTOTAL 1

int nswapdev=10;            /* taken from <machine/space.h> */
int nswapfs=10;            /* taken from <machine/space.h> */

int getswap(int rettype)
{
  int spaceleft=0, spacetotal=0;

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
  int i, fd;
  char *cp;
  
  if (auto_nlist(SWDEVT_SYMBOL,(char *) swdevt, sizeof(struct swdevt)*nswapdev)
      == 0)
    return(0);
  DEBUGMSGTL(("ucd-snmp/memory", "%d fs swap devices: \n", nswapfs));
  for (i=0; i < nswapdev; i++) {
    DEBUGMSGTL(("ucd-snmp/memory", "swdevt[%d]: %d\n",i, swdevt[i].sw_enable));
    if (swdevt[i].sw_enable) {
#ifdef STRUCT_SWDEVT_HAS_SW_NBLKSENABLED
      DEBUGMSGTL(("ucd-snmp/memory", "  swdevt.sw_nblksenabled:     %d\n", swdevt[i].sw_nblksenabled));
      spacetotal += swdevt[i].sw_nblksenabled;
#else
      DEBUGMSGTL(("ucd-snmp/memory", "  swdevt.sw_nblks:     %d\n", swdevt[i].sw_nblks));
      spacetotal += swdevt[i].sw_nblks;
#endif
      spaceleft += (swdevt[i].sw_nfpgs * 4);
      DEBUGMSGTL(("ucd-snmp/memory", "  swdevt.sw_nfpgs:     %d\n", swdevt[i].sw_nfpgs));
    }
  }
  if (auto_nlist(FSWDEVT_SYMBOL,(char *) fswdevt, sizeof(struct fswdevt)*nswapfs)
      == 0)
    return(0);
  DEBUGMSGTL(("ucd-snmp/memory", "%d fs swap devices: \n", nswapfs));
  for (i=0; i < nswapfs; i++) {
    DEBUGMSGTL(("ucd-snmp/memory", "fswdevt[%d]: %d\n",i, fswdevt[i].fsw_enable));
    if (fswdevt[i].fsw_enable) {
      spacetotal += (fswdevt[i].fsw_limit * 2048);  /* 2048=bytes per page? */
      spaceleft += (fswdevt[i].fsw_limit * 2048 -
                    ((fswdevt[i].fsw_allocated - fswdevt[i].fsw_min) * 37));
      DEBUGMSGTL(("ucd-snmp/memory", "  fswdevt[i].fsw_limit:     %d\n", fswdevt[i].fsw_limit));
      DEBUGMSGTL(("ucd-snmp/memory", "  fswdevt[i].fsw_allocated: %d\n", fswdevt[i].fsw_allocated));
      DEBUGMSGTL(("ucd-snmp/memory", "  fswdevt[i].fsw_min:       %d\n", fswdevt[i].fsw_min));
      DEBUGMSGTL(("ucd-snmp/memory", "  fswdevt[i].fsw_reserve:   %d\n", fswdevt[i].fsw_reserve));
      /* 37 = calculated value I know it makes no sense, nor is it accurate */
    }
  }
  /* this is a real hack.  I need to get the hold info from swapinfo, but
     I can't figure out how to read it out of the kernel directly
     -- Wes */
#ifndef hpux10
  strcpy(ex.command,"/etc/swapinfo -h");
#else
  strcpy(ex.command,"/usr/sbin/swapinfo -r");
#endif
  if ((fd = get_exec_output(&ex))) {
    file = fdopen(fd,"r");
    for (i=1;i <= 2 && fgets(ex.output,sizeof(ex.output),file) != NULL; i++);
    if (fgets(ex.output,sizeof(ex.output),file) != NULL) {
      cp = skip_white(ex.output);  /* not there should be any */
      cp = skip_not_white(cp);     /* skip over "reserve" */
      cp = skip_white(cp);
      cp = skip_not_white(cp);     /* avail swap, a '-' in most cases */
      cp = skip_white(cp);
      spaceleft -= atoi(cp);       /* reserved swap */
    }
    fclose(file);
    wait_on_exec(&ex);
  } else {
    return(0);
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
  return 0;
}

static
unsigned char *var_extensible_mem(struct variable *vp,
				  oid *name,
				  size_t *length,
				  int exact,
				  size_t *var_len,
				  WriteMethod **write_method)
{

#ifndef linux
  int result;
#endif
  static long long_ret;
  static char errmsg[300];
#ifndef linux
  struct vmtotal total;
#endif

  long_ret = 0;  /* set to 0 as default */

  if (header_generic(vp,name,length,exact,var_len,write_method))
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
  if (auto_nlist(TOTAL_MEMORY_SYMBOL, (char *)&total, sizeof(total)) == 0) {
    return(0);
  }
#endif
#endif
  switch (vp->magic) {
    case MIBINDEX:
      long_ret = 0;
      return((u_char *) (&long_ret));
    case ERRORNAME:    /* dummy name */
      sprintf(errmsg,"swap");
      *var_len = strlen(errmsg);
      return((u_char *) (errmsg));
    case MEMTOTALSWAP:
      long_ret = getswap(SWAPGETTOTAL);
      return((u_char *) (&long_ret));
    case MEMAVAILSWAP:
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
      if(auto_nlist(PHYSMEM_SYMBOL,(char *) &result,sizeof(result)) == 0)
        return NULL;
      long_ret = result*1000;
#endif
#endif
      return((u_char *) (&long_ret));
    case MEMAVAILREAL:
#ifdef linux
	long_ret = memory(meminfo_free);
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
	long_ret = memory(meminfo_free) + memswap(meminfo_free);
#else
      long_ret = pagetok(total.t_free);
#endif
      return((u_char *) (&long_ret));
    case MEMCACHED:
#ifdef linux
	long_ret = memory(meminfo_cached);
#endif
      return((u_char *) (&long_ret));
    case MEMBUFFER:
#ifdef linux
	long_ret = memory(meminfo_buffers);
#endif
      return((u_char *) (&long_ret));
    case MEMSHARED:
#ifdef linux
	long_ret = memory(meminfo_shared);
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

