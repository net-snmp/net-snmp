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

#include "memory.h"

/* nlist symbols */
#define SUM_SYMBOL      "cnt"
#define BUFSPACE_SYMBOL "bufspace"

/* Default swap warning limit (kb) */
#define DEFAULTMINIMUMSWAP 16000

/* Swap warning limit */
long minimumswap;

/* Swap info */
long swapTotal;
long swapUsed;
long swapFree;

void memory_parse_config(word, cptr)
  char *word;
  char *cptr;
{
  minimumswap = atoi(cptr);
}
 
void memory_free_config __P((void)) 
{
  minimumswap = DEFAULTMINIMUMSWAP;
}

/* Executes swapinfo and parses last line */
/* This is just way too ugly ;) */

void getSwap()
{
  struct extensible ext;
  int fd;
  FILE *file;

  strcpy(ext.command, "/usr/sbin/swapinfo -k");

  if (fd = get_exec_output(&ext)) 
  {
      file = fdopen(fd,"r");

      while (fgets(ext.output,STRMAX,file) != NULL);
      
      fclose(file);
      close(fd);
      wait_on_exec(&ext);

      sscanf(ext.output, "%*s%*d%ld%ld", &swapUsed, &swapFree);

      swapTotal = swapUsed + swapFree;
  }
}

/*
 * swapmode is based on a program called swapinfo written
 * by Kevin Lahey <kml@rokkaku.atl.ga.us>.
 *
 * BUT I CAN'T MAKE IT WORK!!!!!
 *
 */

#include <sys/rlist.h>
#include <sys/conf.h>

#define NSWDEV_SYMBOL     "nswdev"
#define DMMAX_SYMBOL      "dmmax"
#define SWAPLIST_SYMBOL   "swaplist"
#define SWDEVT_SYMBOL     "swdevt"

void swapmode()
{
    char *header;
    int hlen, nswdev, dmmax;
    int i, div;
    struct swdevt *sw;
    long blocksize;
    struct rlist head;
    struct rlist *swaplist;
    static kvm_t *kd = NULL;

    if (kd == NULL)
	kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, NULL);

    auto_nlist(NSWDEV_SYMBOL, (char *)&nswdev, sizeof (nswdev));
    auto_nlist(DMMAX_SYMBOL, (char *)&dmmax, sizeof (dmmax));
    auto_nlist(SWAPLIST_SYMBOL, (char *)&swaplist, sizeof (swaplist));

    sw = (struct swdevt *)malloc(nswdev * sizeof(*sw));
    if (sw == NULL) return;

    auto_nlist(SWDEVT_SYMBOL, (char *)sw, nswdev * sizeof(*sw));

    /* Count up free swap space. */
    swapFree = 0;
    while (swaplist) 
    {
	kvm_read(kd, (u_long)swaplist, &head, sizeof(head));

	swapFree += head.rl_end - head.rl_start + 1;

	swaplist = head.rl_next;
    }

    /* Count up total swap space */
    swapTotal = 0;
    for (i = 0; i < nswdev; i++) 
	if ((sw[i].sw_flags & SW_FREED)) 
	    swapTotal += sw[i].sw_nblks - dmmax;
    
    /* Calculate used swap space */
    swapUsed = swapTotal - swapFree;

    /* Convert to kb */
    header = getbsize(&hlen, &blocksize);
    div = blocksize / 512;

    swapTotal /= div;
    swapUsed /= div;
    swapFree /= div;

    free(sw); 
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
    static long long_ret;
    static char errmsg[300];

    static struct vmmeter mem;
    static struct vmtotal total;
    size_t total_size = sizeof (total);
    int total_mib[] = { CTL_VM, VM_METER };

    long phys_mem;
    size_t phys_mem_size = sizeof(phys_mem);
    int phys_mem_mib[] = { CTL_HW, HW_USERMEM };

    long bufspace;
 
    if (header_generic(vp,name,length,exact,var_len,write_method))
	return(NULL);

    /* Memory info */
    auto_nlist(SUM_SYMBOL, (char *)&mem, sizeof (mem));
    sysctl(total_mib, 2, &total, &total_size, NULL, 0);

    /* Swap info */
    /* swapmode(); Should be used if I ever get it to work */
    getSwap();

    /* Physical memory */
    sysctl(phys_mem_mib, 2, &phys_mem, &phys_mem_size, NULL, 0);

    /* Buffer space */
    auto_nlist(BUFSPACE_SYMBOL, (char *)&bufspace, sizeof (bufspace));

    long_ret = 0;  /* set to 0 as default */

/* Page-to-kb macro */
#define ptok(p) ((p) * (mem.v_page_size >> 10))

    switch (vp->magic) {
    case MIBINDEX:
	long_ret = 0;
	return((u_char *) (&long_ret));
    case ERRORNAME:    /* dummy name */
	sprintf(errmsg,"swap");
	*var_len = strlen(errmsg);
	return((u_char *) (errmsg));
    case MEMTOTALSWAP:
	long_ret = swapTotal;
	return((u_char *) (&long_ret));
    case MEMUSEDSWAP: /* FREE swap memory */
	long_ret = swapFree;
	return((u_char *) (&long_ret));
    case MEMTOTALREAL:
	long_ret = phys_mem >> 10;
	return((u_char *) (&long_ret));
    case MEMUSEDREAL: /* FREE real memory */
	long_ret = ptok(mem.v_free_count);
	return((u_char *) (&long_ret));
    case MEMTOTALSWAPTXT:
	long_ret = -1;
	return((u_char *) (&long_ret));
    case MEMUSEDSWAPTXT:
	long_ret = -1;
	return((u_char *) (&long_ret));
    case MEMTOTALREALTXT:
	long_ret = -1;
	return((u_char *) (&long_ret));
    case MEMUSEDREALTXT:
	long_ret = -1;
	return((u_char *) (&long_ret));
    case MEMTOTALFREE:
	long_ret = ptok((int)total.t_free);
	return((u_char *) (&long_ret));
    case MEMSWAPMINIMUM:
	long_ret = minimumswap;
	return((u_char *) (&long_ret));
    case MEMSHARED:
	long_ret = ptok(total.t_vmshr + 
			total.t_avmshr + 
			total.t_rmshr + 
			total.t_armshr);
	return((u_char *) (&long_ret));
    case MEMBUFFER:
	long_ret = bufspace >> 10;
	return((u_char *) (&long_ret));
    case MEMCACHED:
	long_ret = ptok(mem.v_cache_count);
	return((u_char *) (&long_ret));
    case ERRORFLAG:
	long_ret = (swapFree > minimumswap)?0:1;
	return((u_char *) (&long_ret));
    case ERRORMSG:
	if (swapFree < minimumswap)
	    sprintf(errmsg,"Running out of swap space (%d)", swapFree);
	else
	    errmsg[0] = 0;
	*var_len = strlen(errmsg);
	return((u_char *) (errmsg));
    }
    return NULL;
}

