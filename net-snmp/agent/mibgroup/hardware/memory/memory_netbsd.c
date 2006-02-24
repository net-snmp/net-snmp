#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/memory.h>

#include <unistd.h>

/*
 * Retained from UCD implementation
 */



    /*
     * Load the latest memory usage statistics
     */
int netsnmp_mem_arch_load( netsnmp_cache *cache, void *magic ) {

    netsnmp_memory_info *mem;

    struct uvmexp  uvmexp;
    int            uvmexp_size  = sizeof(uvmexp);
    int            uvmexp_mib[] = { CTL_VM, VM_UVMEXP };

    struct vmtotal total;
    size_t         total_size  = sizeof(total);
    int            total_mib[] = { CTL_VM, VM_METER };

    long            phys_mem;
    size_t          phys_mem_size  = sizeof(phys_mem);
    int             phys_mem_mib[] = { CTL_HW, HW_USERMEM };

    sysctl(uvmexp_mib,   2, &uvmexp,   &uvmexp_size,   NULL, 0);
    sysctl(total_mib,    2, &total,    &total_size,    NULL, 0);
    sysctl(phys_mem_mib, 2, &phys_mem, &phys_mem_size, NULL, 0);


    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MEMORY, 1 );
    if (!mem) {
        snmp_log_perror("No Memory info entry");
    } else {
        mem->units = uvmexp.pagesize;  /* ??? */
        mem->size  = phys_mem;
        mem->free  = uvmexp.free;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_SWAP, 1 );
    if (!mem) {
        snmp_log_perror("No Swap info entry");
    } else {
        mem->units = uvmexp.pagesize;
        mem->size  = uvmexp.swpages;
        mem->free  = uvmexp.swpages - uvmexp.swpginuse;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MISC, 1 );
    if (!mem) {
        snmp_log_perror("No Buffer, etc info entry");
    } else {
        mem->units = uvmexp.pagesize;
        mem->size  = -1
        mem->free  = total.t_free;
        mem->other = -1
    }

    /*
     * XXX - TODO: extract individual memory/swap information
     *    (Into separate netsnmp_memory_info data structures)
     */

    return 0;
}
