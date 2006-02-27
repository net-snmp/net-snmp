#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/auto_nlist.h>
#include <net-snmp/agent/hardware/memory.h>

#include <unistd.h>
#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <kvm.h>

#if HAVE_SYS_VMPARAM_H
#include <sys/vmparam.h>
#else
#include <vm/vm_param.h>
#endif

/*
 * Retained from UCD implementation
 */

#define SUM_SYMBOL       "cnt"
#define BUFSPACE_SYMBOL  "bufspace"

quad_t    swapTotal;
quad_t    swapUsed;
quad_t    swapFree;

#ifndef freebsd4
/*
 * Executes swapinfo and parses last line 
 * This is just way too ugly ;) 
 */

void
swapmode(void)
{
    struct extensible ext;
    int             fd;
    FILE           *file;

    strcpy(ext.command, "/usr/sbin/swapinfo -k");

    if ((fd = get_exec_output(&ext)) != -1) {
        file = fdopen(fd, "r");

        while (fgets(ext.output, sizeof(ext.output), file) != NULL);

        fclose(file);
        wait_on_exec(&ext);

        sscanf(ext.output, "%*s%*d%qd%qd", &swapUsed, &swapFree);

        swapTotal = swapUsed + swapFree;
    }
}
#else
/*
 * swapmode is based on a program called swapinfo written
 * by Kevin Lahey <kml@rokkaku.atl.ga.us>.
 */

#include <sys/conf.h>

void
swapmode(void)
{
    int             pagesize;
    int             i, n;
    static kvm_t   *kd = NULL;
    struct kvm_swap kswap[16];

    if (kd == NULL)
        kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, NULL);

    n = kvm_getswapinfo(kd, kswap, sizeof(kswap) / sizeof(kswap[0]), 0);

    swapUsed = swapTotal = swapFree = 0;
    /*
     * Count up free swap space. 
     */
    for (i = 0; i < n; ++i)
        swapFree += kswap[i].ksw_total - kswap[i].ksw_used;

    /*
     * Count up total swap space 
     */
    for (i = 0; i < n; i++)
        swapTotal += kswap[i].ksw_total;

    /*
     * Calculate used swap space 
     */
    swapUsed = swapTotal - swapFree;
}
#endif


    /*
     * Load the latest memory usage statistics
     */
int netsnmp_mem_arch_load( netsnmp_cache *cache, void *magic ) {

    netsnmp_memory_info *mem;

    struct vmmeter vmem;
    struct vmtotal total;
    size_t         total_size  = sizeof(total);
    int            total_mib[] = { CTL_VM, VM_METER };

    u_long         phys_mem;
    size_t         phys_mem_size  = sizeof(phys_mem);
    int            phys_mem_mib[] = { CTL_HW, HW_USERMEM };
#ifdef BUFSPACE_SYMBOL
    long           bufspace;
    auto_nlist(BUFSPACE_SYMBOL, (char *) &bufspace, sizeof(bufspace));
#endif
    auto_nlist(SUM_SYMBOL,      (char *) &vmem,     sizeof(vmem));
    sysctl(total_mib,    2, &total,    &total_size,    NULL, 0);
    sysctl(phys_mem_mib, 2, &phys_mem, &phys_mem_size, NULL, 0);
    swapmode();


    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MEMORY, 1 );
    if (!mem) {
        snmp_log_perror("No Memory info entry");
    } else {
        mem->units = vmem.v_page_size;
        mem->size  = phys_mem/vmem.v_page_size;
        mem->free  = vmem.v_free_count;
        mem->other = total.t_vmshr + total.t_avmshr +
                     total.t_rmshr + total.t_armshr;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_SWAP, 1 );
    if (!mem) {
        snmp_log_perror("No Swap info entry");
    } else {
#ifndef freebsd4
        mem->units = 1024;
#else
        mem->units = getpagesize();
#endif
        mem->size  = swapTotal;
        mem->free  = swapFree;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MISC, 1 );
    if (!mem) {
        snmp_log_perror("No Buffer, etc info entry");
    } else {
        mem->units = vmem.v_page_size;
        mem->size  = bufspace/vmem.v_page_size;
        mem->free  = total.t_free;
#ifdef openbsd2
        mem->other = -1;
#else
#ifdef darwin
        mem->other = vmem.v_lookups;
#else
        mem->other = vmem.v_cache_count;
#endif
#endif
    }

    /*
     * XXX - TODO: extract individual memory/swap information
     *    (Into separate netsnmp_memory_info data structures)
     */

    return 0;
}
