#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/memory.h>

#include <unistd.h>
#include <libperfstat.h>
#include <sys/stat.h>


    /*
     * Load the latest memory usage statistics
     */
int netsnmp_mem_arch_load( netsnmp_cache *cache, void *magic ) {

    netsnmp_memory_info *mem;
    perfstat_memory_total_t pstat_mem;

    if (perfstat_memory_total((perfstat_id_t *)NULL, &pstat_mem,
                        sizeof(perfstat_memory_total_t), 1) < 1) {
        snmp_log(LOG_ERR, "memory_aix: perfstat_memory_total failed!\n");
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MEMORY, 1 );
    if (!mem) {
        snmp_log_perror("No Memory info entry");
    } else {
        mem->units = getpagesize();
        mem->size = pstat_mem.real_total;
        mem->free = pstat_mem.real_free;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_SWAP, 1 );
    if (!mem) {
        snmp_log_perror("No Swap info entry");
    } else {
        mem->units = getpagesize();
        mem->size = pstat_mem.pgsp_total;
        mem->free = pstat_mem.pgsp_free;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MISC, 1 );
    if (!mem) {
        snmp_log_perror("No Buffer, etc info entry");
    } else {
        mem->units = getpagesize();
        mem->size = -1;
        mem->free = pstat_mem.real_free + pstat_mem.pgsp_free;
        mem->other = -1;
    }

    /*
     * XXX - TODO: extract individual memory/swap information
     *    (Into separate netsnmp_memory_info data structures)
     */
    return 0;
}
