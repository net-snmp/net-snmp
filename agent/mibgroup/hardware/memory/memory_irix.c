#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/memory.h>

#if HAVE_SYS_SYSGET_H
#include <sys/sysget.h>
#endif

#if HAVE_SYS_SYSMP_H
#include <sys/sysmp.h>
#endif

    /*
     * Load the latest memory usage statistics
     */
int netsnmp_mem_arch_load( netsnmp_cache *cache, void *magic ) {

    netsnmp_memory_info *mem;
    struct rminfo meminfo; /* struct for getting memory info, see sys/sysmp.h */
    int pagesz, rminfosz;

    /*
     * Retrieve the memory information from the underlying O/S...
     */
    pagesz = getpagesize();
    rminfosz = (int)sysmp(MP_SASZ, MPSA_RMINFO);
    if (sysmp(MP_SAGET, MPSA_RMINFO, &meminfo, rminfosz) < 0) {
        snmp_log_perror("sysmp");
        return;
    }

    /*
     * ... and save this in a standard form.
     */
    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_PHYSMEM, 1 );
    if (!mem) {
        snmp_log_perror("No Physical Memory info entry");
    } else {
        if (!mem->descr)
             mem->descr = strdup("Physical memory");
        mem->units = pagesz;
        mem->size  = meminfo.physmem;
        mem->free  = meminfo.availrmem;
        mem->other = -1;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_VIRTMEM, 1 );
    if (!mem) {
        snmp_log_perror("No Virtual Memory info entry");
    } else {
        if (!mem->descr)
             mem->descr = strdup("Virtual memory");
        mem->units = pagesz;
        mem->size  = meminfo.freemem;
        mem->free  = meminfo.availsmem;
        mem->other = -1;
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_SWAP, 1 );
    if (!mem) {
        snmp_log_perror("No Swap info entry");
    } else {
        if (!mem->descr)
             mem->descr = strdup("Swap space");
        mem->units = pagesz;
        mem->size  = meminfo.freemem - meminfo.physmem;
        mem->free  = meminfo.availsmem - meminfo.availrmem;
        mem->other = -1;
    }

    return 0;
}

