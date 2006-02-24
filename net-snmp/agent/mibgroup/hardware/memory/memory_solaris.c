#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/memory.h>

#include <unistd.h>
#include <kstat.h>
#include <sys/stat.h>
#include <sys/swap.h>

/*
 * Retained from UCD implementation
 */
long
getTotalSwap(void)
{
    long            total_mem;

    size_t          num;
    int             i, n;
    swaptbl_t      *s;
    char           *strtab;

    total_mem = 0;

    num = swapctl(SC_GETNSWP, 0);
    s = malloc(num * sizeof(swapent_t) + sizeof(struct swaptable));
    if (s) {
        strtab = (char *) malloc((num + 1) * MAXSTRSIZE);
        if (strtab) {
            for (i = 0; i < (num + 1); i++) {
                s->swt_ent[i].ste_path = strtab + (i * MAXSTRSIZE);
            }
            s->swt_n = num + 1;
            n = swapctl(SC_LIST, s);

            for (i = 0; i < n; i++)
                total_mem += s->swt_ent[i].ste_pages;

            free(strtab);
        }
        free(s);
    }

    return (total_mem);
}

/*
 * returns -1 if malloc fails.
 */
long
getFreeSwap(void)
{
    long            free_mem = -1;

    size_t          num;
    int             i, n;
    swaptbl_t      *s;
    char           *strtab;

    num = swapctl(SC_GETNSWP, 0);
    s = malloc(num * sizeof(swapent_t) + sizeof(struct swaptable));
    if (s) {
        strtab = (char *) malloc((num + 1) * MAXSTRSIZE);
        if (strtab) {
            free_mem = 0;
            for (i = 0; i < (num + 1); i++) {
                s->swt_ent[i].ste_path = strtab + (i * MAXSTRSIZE);
            }
            s->swt_n = num + 1;
            n = swapctl(SC_LIST, s);

            for (i = 0; i < n; i++)
                free_mem += s->swt_ent[i].ste_free;

            free(strtab);
        }
        free(s);
    }

    return (free_mem);
}

long
getTotalFree(void)
{
    unsigned long   free_mem, allocated, reserved, available, used_size;
    struct anoninfo ai;

    if (-1 == swapctl(SC_AINFO, &ai)) {
        snmp_log_perror("swapctl(SC_AINFO)");
	return 0;
    }
    allocated = ai.ani_max - ai.ani_free;
    reserved = (ai.ani_resv - allocated);
    available = (ai.ani_max - ai.ani_resv);     /* K-byte */
    free_mem = used_size = reserved + allocated;
    free_mem = available;
    return (free_mem);
}



    /*
     * Load the latest memory usage statistics
     */
int netsnmp_mem_arch_load( netsnmp_cache *cache, void *magic ) {

#ifndef _SC_PHYS_PAGES
    extern kstat_ctl_t *kstat_fd;   /* defined in kernel_sunos5.c */
    kstat_t        *ksp1;
    kstat_named_t  *kn;
#endif
    netsnmp_memory_info *mem;

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MEMORY, 1 );
    if (!mem) {
        snmp_log_perror("No Memory info entry");
    } else {
        mem->units = getpagesize();
#ifdef _SC_PHYS_PAGES
        mem->size  = sysconf(_SC_PHYS_PAGES);
#else
        ksp1 = kstat_lookup(kstat_fd, "unix", 0, "system_pages");
        kstat_read(kstat_fd, ksp1, 0);
        kn = kstat_data_lookup(ksp1, "physmem");
        mem->size = kn->value.ul;
#endif
#ifdef _SC_AVPHYS_PAGES
        mem->free = sysconf(_SC_AVPHYS_PAGES);
#else
        mem->free = getTotalFree() - getFreeSwap();
#endif
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_SWAP, 1 );
    if (!mem) {
        snmp_log_perror("No Swap info entry");
    } else {
        mem->units = getpagesize();
        mem->size = getTotalSwap();
        mem->free = getFreeSwap();
    }

    mem = netsnmp_memory_get_byIdx( NETSNMP_MEM_TYPE_MISC, 1 );
    if (!mem) {
        snmp_log_perror("No Buffer, etc info entry");
    } else {
        mem->units = getpagesize();
        mem->size = -1;
        mem->free = getTotalFree();
        mem->other = -1;
    }

    /*
     * XXX - TODO: extract individual memory/swap information
     *    (Into separate netsnmp_memory_info data structures)
     */

    return 0;
}
