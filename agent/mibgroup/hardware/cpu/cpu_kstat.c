/*
 *   kstat() interface
 *     e.g. Solaris
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/cpu.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

#include <kstat.h>
#include <sys/sysinfo.h>

extern kstat_ctl_t  *kstat_fd;
extern int           cpu_num;

    /*
     * Initialise the list of CPUs on the system
     *   (including descriptions)
     */
void init_cpu_nlist( void ) {
    int               i, n=0, clock, state_begin;
    char              ctype[15], ftype[15], state[10];
    kstat_t          *ksp;
    kstat_ctl_t      *kc;
    netsnmp_cpu_info *cpu = netsnmp_cpu_get_byIdx( -1, 1 );
    strcpy(cpu->name, "Overall CPU statistics");

    if (kstat_fd == NULL)
        kstat_fd = kstat_open();
    kstat_chain_update( kstat_fd );

    if (ksp = kstat_fd->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
        if (ksp->ks_flags & KSTAT_FLAG_INVALID)
            continue;
        if ((strcmp(ksp->ks_module, "cpu_info") == 0) &&
            (strcmp(ksp->ks_class,  "misc"    ) == 0)) {
            kstat_read(kc, ksp, NULL );
            n++;
            clock = 999999;
            memset(ctype, 0, sizeof(ctype));
            memset(ftype, 0, sizeof(ftype));
            memset(state, 0, sizeof(state));
            for (i=0; i<ksp->ks_ndata; i++) {
                ks_data = ksp->ks_data[i];
                if ( strcmp( ks_data->name, "state" ) == 0 ) {
                    strncpy( state, ks_data->value.c, sizeof(state));
                    state[sizeof(state)-1] = '\0';
                } else if ( strcmp( ks_data->name, "state_begin" ) == 0 ) {
                    state_begin = ks_data->value.i32;
                } else if ( strcmp( ks_data->name, "cpu_type" ) == 0 ) {
                    strncpy( ctype, ks_data->value.c, sizeof(ctype));
                    state[sizeof(ctype)-1] = '\0';
                } else if ( strcmp( ks_data->name, "fpu_type" ) == 0 ) {
                    strncpy( ftype, ks_data->value.c, sizeof(ftype));
                    state[sizeof(ftype)-1] = '\0';
                } else if ( strcmp( ks_data->name, "clock_MHz" ) == 0 ) {
                    clock = ks_data->value.i32;
                }
            }
            i   = kdp->ks_instance;
            cpu = netsnmp_cpu_get_byIdx( i, 1 );
            sprintf( cpu->name,  "cpu%d", i );
            sprintf( cpu->descr, "CPU %d Sun %d MHz %s with %s FPU %s",
                                 i, clock, ctype, ftype, state  );
        }
    }
    cpu_num = i;
}


    /*
     * Load the latest CPU usage statistics
     */
int netsnmp_cpu_arch_load( netsnmp_cache *cache, void *magic ) {
    int               i=0;
    kstat_t          *ksp;
    cpu_stat_t        cs;
    netsnmp_cpu_info *cpu = netsnmp_cpu_get_byIdx( -1, 0 );
    netsnmp_cpu_info *cpu2;

        /* Clear overall stats, ready for summing individual CPUs */
    cpu->user_ticks = 0;
    cpu->idle_ticks = 0;
    cpu->kern_ticks = 0;
    cpu->wait_ticks = 0;
    cpu->sys2_ticks = 0;
    cpu->swapIn       = 0;
    cpu->swapOut      = 0;
    cpu->nInterrupts  = 0;
    cpu->nCtxSwitches = 0;

    kstat_chain_update( kstat_fd );
    if (ksp = kstat_fd->kc_chain; ksp != NULL; ksp = ksp->ks_next) {
        if (ksp->ks_flags & KSTAT_FLAG_INVALID)
            continue;
        if (strcmp(ksp->ks_module, "cpu_stat") == 0) {
            cpu2 = netsnmp_cpu_get_byIdx( i++, 0 );
            if ((ksp->ks_type != KSTAT_TYPE_RAW) ||
                (ksp->ks_data_size != sizeof(cs))||
                (kstat_read(kstat_fd, ksp, &cs) == -1)) {
                break;   /* or continue ? */
            }

            cpu2->user_ticks = (unsigned long)cs.cpu_sysinfo.cpu[CPU_USER];
            cpu2->idle_ticks = (unsigned long)cs.cpu_sysinfo.cpu[CPU_IDLE];
            cpu2->kern_ticks = (unsigned long)cs.cpu_sysinfo.cpu[CPU_KERNEL];
            cpu2->wait_ticks = (unsigned long)cs.cpu_sysinfo.cpu[CPU_WAIT];
              /* or cs.cpu_sysinfo.wait[W_IO]+cs.cpu_sysinfo.wait[W_PIO] */
            cpu2->sys2_ticks = (unsigned long)cpu2->kern_ticks+cpu2->wait_ticks;
                /* nice_ticks, intrpt_ticks, sirq_ticks unused */

                /* sum these for the overall stats */
            cpu->user_ticks += (unsigned long)cs.cpu_sysinfo.cpu[CPU_USER];
            cpu->idle_ticks += (unsigned long)cs.cpu_sysinfo.cpu[CPU_IDLE];
            cpu->kern_ticks += (unsigned long)cs.cpu_sysinfo.cpu[CPU_KERNEL];
            cpu->wait_ticks += (unsigned long)cs.cpu_sysinfo.cpu[CPU_WAIT];
              /* or cs.cpu_sysinfo.wait[W_IO]+cs.cpu_sysinfo.wait[W_PIO] */
            cpu->sys2_ticks += (unsigned long)cpu2->kern_ticks+cpu2->wait_ticks;

                /*
                 * Interrupt/Context Switch statistics
                 *   XXX - Do these really belong here ?
                 */
            cpu->swapIn       += (unsigned long)cs.cpu_vminfo.swapin;
            cpu->swapOut      += (unsigned long)cs.cpu_vminfo.swapout;
            cpu->nInterrupts  += (unsigned long)cs.cpu_sysinfo.intr;
            cpu->nCtxSwitches += (unsigned long)cs.cpu_sysinfo.pswitch;
        }
    }
    return 0;
}
