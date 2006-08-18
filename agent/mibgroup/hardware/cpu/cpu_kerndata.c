/*
 *   getkerndata() interface
 *     e.g. Dynix
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/cpu.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <sys/sysctl.h>
#include <sys/vmmeter.h>
#include <vm/vm_param.h>
#include <vm/vm_extern.h>

ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ

#define CPU_SYMBOL  "cp_time"
#define MEM_SYMBOL  "cnt"

    /*
     * Initialise the list of CPUs on the system
     *   (including descriptions)
     */
void init_cpu_nlist( void ) {
    netsnmp_cpu_info     *cpu = netsnmp_cpu_get_byIdx( -1, 1 );
    strcpy(cpu->name, "Overall CPU statistics");

    /* XXX - per-CPU structures ? */
}


    /*
     * Load the latest CPU usage statistics
     */
int netsnmp_cpu_arch_load( netsnmp_cache *cache, void *magic ) {
    long   cpu_stats[CPUSTATES];
    struct vmmeter mem_stats;
    netsnmp_cpu_info *cpu = netsnmp_cpu_get_byIdx( -1, 1 );

    auto_nlist( CPU_SYMBOL, (char *) cpu_stats, sizeof(cpu_stats));
    auto_nlist( MEM_SYMBOL, (char *)&mem_stats, sizeof(mem_stats));

    cpu->user_ticks = (unsigned long)cpu_stats[0];
    cpu->nice_ticks = (unsigned long)cpu_stats[1];
    cpu->sys_ticks  = (unsigned long)cpu_stats[2];
    cpu->idle_ticks = (unsigned long)cpu_stats[3];
        /* intrpt_ticks, wait_ticks, kern_ticks, sirq_ticks unused */

        /*
         * Interrupt/Context Switch statistics
         *   XXX - Do these really belong here ?
         */
    cpu->swapIn  = (unsigned long)mem_stats.v_swpin;
    cpu->swapOut = (unsigned long)mem_stats.v_swpout;
    cpu->nInterrupts  = (unsigned long)mem_stats.v_intr;
    cpu->nCtxSwitches = (unsigned long)mem_stats.v_swtch;

#ifdef PER_CPU_INFO
    for ( i = 0; i < n; i++ ) {
        cpu = netsnmp_cpu_get_byIdx( i, 1 );
        /* XXX - per-CPU statistics */
    }
#endif

    return 0;
}
