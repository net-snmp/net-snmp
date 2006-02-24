#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/memory.h>

#include <sys/pstat.h>

/*
 * Retained from UCD implementation
 */
int
get_swapinfo(struct swapinfo *swap)
{

    struct pst_swapinfo pss;
    int             i = 0;

    while (pstat_getswap(&pss, sizeof(pss), (size_t) 1, i) != -1) {
        if (pss.pss_idx == (unsigned) i) {
            swap->total_swap += pss.pss_nblksenabled;
            swap->free_swap += 4 * pss.pss_nfpgs;       /* nfpgs is in 4-byte blocks - who knows why? */
            i++;
        } else
            return;
    }
}                               /* end get_swapinfo */



    /*
     * Load the latest memory usage statistics
     */
int netsnmp_mem_arch_load( netsnmp_cache *cache, void *magic ) {

    struct swapinfo swap;
    struct pst_static pst;
    struct pst_dynamic psd;
    netsnmp_memory_info *mem;

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MEMORY, 1 );
    if (!mem) {
        snmp_log_perror("No Memory info entry");
    } else {
        if (pstat_getstatic(&pst, sizeof(pst), (size_t) 1, 0) == -1) {
            snmp_log(LOG_ERR, "memory_hpux: pstat_getstatic failed!\n");
            return -1;
        }
        if (pstat_getdynamic(&psd, sizeof(psd), (size_t) 1, 0) == -1) {
            snmp_log(LOG_ERR, "memory_hpux: pstat_getdynamic failed!\n");
            return -1;
        }
        mem->units = pst.page_size;
        mem->size  = pst.physical_memory;
        mem->free  = psd.psd_free;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_SWAP, 1 );
    if (!mem) {
        snmp_log_perror("No Swap info entry");
    } else {
        getswapinfo(&swap);
        mem->units = 1024;
        mem->size = swap.total_swap;
        mem->free = swap.free_swap;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_STEXT, 1 );
    if (!mem) {
        snmp_log_perror("No Swap text entry");
    } else {
        mem->units = pst.page_size;
        mem->size  = psd.psd_vmtxt;
        mem->free  = psd.psd_avmtxt;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_RTEXT, 1 );
    if (!mem) {
        snmp_log_perror("No real text entry");
    } else {
        mem->units = pst.page_size;
        mem->size  = psd.psd_rmtxt;
        mem->free  = psd.psd_armtxt;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MISC, 1 );
    if (!mem) {
        snmp_log_perror("No Buffer, etc info entry");
    } else {
        mem->units = 1024;
        mem->size = -1;
        mem->free = (pst.page_size/1024)*psd.psd_free + swap.free_swap;
        mem->other = -1;
    }

    /*
     * XXX - TODO: extract individual memory/swap information
     *    (Into separate netsnmp_memory_info data structures)
     */

    return 0;
}
