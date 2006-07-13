/*
 *  Host Resources MIB - storage group implementation - hr_storage.c
 *
 */

#include <net-snmp/net-snmp-config.h>

#if defined(freebsd5)
/* undefine these in order to use getfsstat */
#undef HAVE_STATVFS
#undef STRUCT_STATVFS_HAS_F_FRSIZE
#endif

#include <sys/types.h>
#include <sys/param.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <windows.h>
#  include <errno.h>
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#ifndef mingw32
#if HAVE_UTMPX_H
#include <utmpx.h>
#else
#include <utmp.h>
#endif
#endif /* mingw32 */
#ifndef dynix
#if HAVE_SYS_VM_H
#include <sys/vm.h>
#if (!defined(KERNEL) || defined(MACH_USER_API)) && defined(HAVE_SYS_VMMETER_H) /*OS X does not #include <sys/vmmeter.h> if (defined(KERNEL) && !defined(MACH_USER_API)) */
#include <sys/vmmeter.h>
#endif
#else
#if HAVE_VM_VM_H
#include <vm/vm.h>
#if HAVE_MACHINE_TYPES_H
#include <machine/types.h>
#endif
#if HAVE_SYS_VMMETER_H
#include <sys/vmmeter.h>
#endif
#if HAVE_VM_VM_PARAM_H
#include <vm/vm_param.h>
#endif
#else
#if HAVE_SYS_VMPARAM_H
#include <sys/vmparam.h>
#endif
#if HAVE_SYS_VMMAC_H
#include <sys/vmmac.h>
#endif
#if HAVE_SYS_VMMETER_H
#include <sys/vmmeter.h>
#endif
#if HAVE_SYS_VMSYSTM_H
#include <sys/vmsystm.h>
#endif
#endif                          /* vm/vm.h */
#endif                          /* sys/vm.h */
#if defined(HAVE_UVM_UVM_PARAM_H) && defined(HAVE_UVM_UVM_EXTERN_H)
#include <uvm/uvm_param.h>
#include <uvm/uvm_extern.h>
#elif defined(HAVE_VM_VM_PARAM_H) && defined(HAVE_VM_VM_EXTERN_H)
#include <vm/vm_param.h>
#include <vm/vm_extern.h>
#endif
#if HAVE_KVM_H
#include <kvm.h>
#endif
#if HAVE_FCNTL_H
#include <fcntl.h>
#endif
#if HAVE_SYS_POOL_H
#if defined(MBPOOL_SYMBOL) && defined(MCLPOOL_SYMBOL)
#define __POOL_EXPOSE
#include <sys/pool.h>
#else
#undef HAVE_SYS_POOL_H
#endif
#endif
#if HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif
#if HAVE_SYS_SYSCTL_H
#include <sys/sysctl.h>
#if defined(CTL_HW) && defined(HW_PAGESIZE)
#define USE_SYSCTL
#endif
#if defined(CTL_VM) && (defined(VM_METER) || defined(VM_UVMEXP)) && !defined(darwin8)
#define USE_SYSCTL_VM
#endif
#endif
#endif                          /* ifndef dynix */

#if defined(darwin8) /* This is to use host_statistics on OS X */
#include <mach/mach.h>
#endif

#include "host_res.h"
#include "hr_storage.h"
#include "hr_filesys.h"
#include <net-snmp/agent/auto_nlist.h>

#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#if HAVE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#endif
#if HAVE_SYS_STATVFS_H
#include <sys/statvfs.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if HAVE_SYS_MOUNT_H
#ifdef __osf__
#undef m_next
#undef m_data
#endif
#include <sys/mount.h>
#endif
#ifdef HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#include <sys/stat.h>

#if defined(hpux10) || defined(hpux11)
#include <sys/pstat.h>
#endif
#if defined(solaris2)
#if HAVE_SYS_SWAP_H
#include <sys/swap.h>
#endif
#endif

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include <net-snmp/utilities.h>
#include <net-snmp/output_api.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/hardware/memory.h>

#if solaris2
#include "kernel_sunos5.h"
#endif

#include <net-snmp/agent/agent_read_config.h>
#include <net-snmp/library/read_config.h>

#define HRSTORE_MONOTONICALLY_INCREASING

        /*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


#ifdef solaris2

extern struct mnttab *HRFS_entry;
#define HRFS_mount	mnt_mountp
#define HRFS_statfs	statvfs
#define HRFS_HAS_FRSIZE STRUCT_STATVFS_HAS_F_FRSIZE

#elif defined(WIN32)
/* fake block size */
#define FAKED_BLOCK_SIZE 512

extern struct win_statfs *HRFS_entry;
#define HRFS_statfs	win_statfs
#define HRFS_mount	f_driveletter

#elif defined(HAVE_STATVFS) && defined(__NetBSD__)

extern struct statvfs *HRFS_entry;
extern int      fscount;
#define HRFS_statfs	statvfs
#define HRFS_mount	f_mntonname
#define HRFS_HAS_FRSIZE STRUCT_STATVFS_HAS_F_FRSIZE

#elif defined(HAVE_STATVFS)  && defined(STRUCT_STATVFS_HAS_MNT_DIR)

extern struct mntent *HRFS_entry;
extern int      fscount;
#define HRFS_statfs	statvfs
#define HRFS_mount	mnt_dir
#define HRFS_HAS_FRSIZE STRUCT_STATVFS_HAS_F_FRSIZE

#elif defined(HAVE_GETFSSTAT)

extern struct statfs *HRFS_entry;
extern int      fscount;
#define HRFS_statfs	statfs
#define HRFS_mount	f_mntonname
#define HRFS_HAS_FRSIZE STRUCT_STATFS_HAS_F_FRSIZE

#else

extern struct mntent *HRFS_entry;
#define HRFS_mount	mnt_dir
#define HRFS_statfs	statfs
#define HRFS_HAS_FRSIZE STRUCT_STATFS_HAS_F_FRSIZE

#endif
	
#if defined(darwin8) /* This is to use host_statistics() on OS X */
mach_port_t myHost;
#endif

static int      physmem, pagesize;
static void parse_storage_config(const char *, char *);

        /*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/
int             Get_Next_HR_Store(void);
void            Init_HR_Store(void);
int             header_hrstore(struct variable *, oid *, size_t *, int,
                               size_t *, WriteMethod **);
int             header_hrstoreEntry(struct variable *, oid *, size_t *,
                                    int, size_t *, WriteMethod **);

#ifdef linux
int             linux_mem(int, int);
#endif

#ifdef solaris2
void            sol_get_swapinfo(int *, int *);
#endif

#define	HRSTORE_MEMSIZE		1
#define	HRSTORE_INDEX		2
#define	HRSTORE_TYPE		3
#define	HRSTORE_DESCR		4
#define	HRSTORE_UNITS		5
#define	HRSTORE_SIZE		6
#define	HRSTORE_USED		7
#define	HRSTORE_FAILS		8

struct variable4 hrstore_variables[] = {
    {HRSTORE_MEMSIZE, ASN_INTEGER, RONLY, var_hrstore, 1, {2}},
    {HRSTORE_INDEX, ASN_INTEGER, RONLY, var_hrstore, 3, {3, 1, 1}},
    {HRSTORE_TYPE, ASN_OBJECT_ID, RONLY, var_hrstore, 3, {3, 1, 2}},
    {HRSTORE_DESCR, ASN_OCTET_STR, RONLY, var_hrstore, 3, {3, 1, 3}},
    {HRSTORE_UNITS, ASN_INTEGER, RONLY, var_hrstore, 3, {3, 1, 4}},
    {HRSTORE_SIZE, ASN_INTEGER, RONLY, var_hrstore, 3, {3, 1, 5}},
    {HRSTORE_USED, ASN_INTEGER, RONLY, var_hrstore, 3, {3, 1, 6}},
    {HRSTORE_FAILS, ASN_COUNTER, RONLY, var_hrstore, 3, {3, 1, 7}}
};
oid             hrstore_variables_oid[] = { 1, 3, 6, 1, 2, 1, 25, 2 };


void
init_hr_storage(void)
{
#ifdef USE_SYSCTL
    int             mib[2];
    size_t          len;
#elif defined(hpux10) || defined(hpux11)
    struct pst_static pst_buf;
#endif

#ifdef USE_SYSCTL
    mib[0] = CTL_HW;
    mib[1] = HW_PHYSMEM;
    len = sizeof(physmem);
    if (sysctl(mib, 2, &physmem, &len, NULL, 0) == -1)
        snmp_log_perror("sysctl: physmem");
    mib[1] = HW_PAGESIZE;
    len = sizeof(pagesize);
    if (sysctl(mib, 2, &pagesize, &len, NULL, 0) == -1)
        snmp_log_perror("sysctl: pagesize");
    physmem /= pagesize;
#elif defined(hpux10) || defined(hpux11)
    if (pstat_getstatic(&pst_buf, sizeof(struct pst_static), 1, 0) < 0) {
        snmp_log_perror("pstat_getstatic");
    } else {
        physmem = pst_buf.physical_memory;
        pagesize = pst_buf.page_size;
    }
#else                           /* !USE_SYSCTL && !hpux10 && !hpux11 */
#ifndef WIN32
#ifdef HAVE_GETPAGESIZE
    pagesize = getpagesize();
#elif defined(_SC_PAGESIZE)
    pagesize = sysconf(_SC_PAGESIZE);
#elif defined(PGSHIFT)
    pagesize = 1 << PGSHIFT;
#elif defined(PAGE_SHIFT)
    pagesize = 1 << PAGE_SHIFT;
#elif defined(PAGE_SIZE)
    pagesize = PAGE_SIZE;
#elif defined(linux)
    {
        struct stat     kc_buf;
        if (stat("/proc/kcore", &kc_buf) == -1)
	    snmp_log_perror("/proc/kcore");
        pagesize = kc_buf.st_size / 1024;       /* 4K too large ? */
    }
#else
    pagesize = PAGESIZE;
#endif
#else /* WIN32 */
	pagesize = 4096; /* Yes...Yes it does. */
#endif
#ifdef _SC_PHYS_PAGES
    physmem = sysconf(_SC_PHYS_PAGES);
#else
#ifdef dynix
    physmem = sysconf(_SC_PHYSMEM);
#else
    auto_nlist(PHYSMEM_SYMBOL, (char *) &physmem, sizeof(physmem));
#endif
#endif
#endif                          /* !USE_SYSCTL && !hpux10 && !hpux11 */
#ifdef TOTAL_MEMORY_SYMBOL
    auto_nlist(TOTAL_MEMORY_SYMBOL, 0, 0);
#endif
#ifdef MBSTAT_SYMBOL
    auto_nlist(MBSTAT_SYMBOL, 0, 0);
#endif

#if defined(darwin8)
    myHost = mach_host_self();
#endif

    REGISTER_MIB("host/hr_storage", hrstore_variables, variable4,
                 hrstore_variables_oid);

    snmpd_register_config_handler("storageUseNFS", parse_storage_config, NULL,
	"1 | 2\t\t(1 = enable, 2 = disable)");
}

static int storageUseNFS = 0;	/* initially disabled */

static void
parse_storage_config(const char *token, char *cptr)
{
    char *val;
    int ival;
    char *st;

    val = strtok_r(cptr, " \t", &st);
    if (!val) {
        config_perror("Missing FLAG parameter in storageUseNFS");
        return;
    }
    ival = atoi(val);
    if (ival < 1 || ival > 2) {
        config_perror("storageUseNFS must be 1 or 2");
        return;
    }
    storageUseNFS = (ival == 1) ? 1 : 0;
}

/*
 * header_hrstore(...
 * Arguments:
 * vp     IN      - pointer to variable entry that points here
 * name    IN/OUT  - IN/name requested, OUT/name found
 * length  IN/OUT  - length of IN/OUT oid's 
 * exact   IN      - TRUE if an exact match was requested
 * var_len OUT     - length of variable or 0 if function returned
 * write_method
 * 
 */

int
header_hrstore(struct variable *vp,
               oid * name,
               size_t * length,
               int exact, size_t * var_len, WriteMethod ** write_method)
{
#define HRSTORE_NAME_LENGTH	9
    oid             newname[MAX_OID_LEN];
    int             result;

    DEBUGMSGTL(("host/hr_storage", "var_hrstore: "));
    DEBUGMSGOID(("host/hr_storage", name, *length));
    DEBUGMSG(("host/hr_storage", " %d\n", exact));

    memcpy((char *) newname, (char *) vp->name, vp->namelen * sizeof(oid));
    newname[HRSTORE_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return (MATCH_FAILED);
    memcpy((char *) name, (char *) newname,
           (vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);    /* default to 'long' results */
    return (MATCH_SUCCEEDED);
}

int
header_hrstoreEntry(struct variable *vp,
                    oid * name,
                    size_t * length,
                    int exact,
                    size_t * var_len, WriteMethod ** write_method)
{
#define HRSTORE_ENTRY_NAME_LENGTH	11
    oid             newname[MAX_OID_LEN];
    int             storage_idx, LowIndex = -1;
    int             result;

    DEBUGMSGTL(("host/hr_storage", "var_hrstoreEntry: "));
    DEBUGMSGOID(("host/hr_storage", name, *length));
    DEBUGMSG(("host/hr_storage", " %d\n", exact));

    memcpy((char *) newname, (char *) vp->name,
           (int) vp->namelen * sizeof(oid));
    /*
     * Find "next" storage entry 
     */

    Init_HR_Store();
    for (;;) {
        storage_idx = Get_Next_HR_Store();
        DEBUGMSG(("host/hr_storage", "(index %d ....", storage_idx));
        if (storage_idx == -1)
            break;
        newname[HRSTORE_ENTRY_NAME_LENGTH] = storage_idx;
        DEBUGMSGOID(("host/hr_storage", newname, *length));
        DEBUGMSG(("host/hr_storage", "\n"));
        result = snmp_oid_compare(name, *length, newname, vp->namelen + 1);
        if (exact && (result == 0)) {
            LowIndex = storage_idx;
            /*
             * Save storage status information 
             */
            break;
        }
        if ((!exact && (result < 0)) &&
            (LowIndex == -1 || storage_idx < LowIndex)) {
            LowIndex = storage_idx;
            /*
             * Save storage status information 
             */
#ifdef HRSTORE_MONOTONICALLY_INCREASING
            break;
#endif
        }
    }

    if (LowIndex == -1) {
        DEBUGMSGTL(("host/hr_storage", "... index out of range\n"));
        return (MATCH_FAILED);
    }

    memcpy((char *) name, (char *) newname,
           ((int) vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);    /* default to 'long' results */

    DEBUGMSGTL(("host/hr_storage", "... get storage stats "));
    DEBUGMSGOID(("host/hr_storage", name, *length));
    DEBUGMSG(("host/hr_storage", "\n"));
    return LowIndex;
}

oid             storage_type_id[] = { 1, 3, 6, 1, 2, 1, 25, 2, 1, 1 };  /* hrStorageOther */
int             storage_type_len =
    sizeof(storage_type_id) / sizeof(storage_type_id[0]);

        /*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

static const char *hrs_descr[] = {
    NULL,
    "Memory Buffers",           /* HRS_TYPE_MBUF */
    "Real Memory",              /* HRS_TYPE_MEM */
    "Swap Space"                /* HRS_TYPE_SWAP */
};



u_char         *
var_hrstore(struct variable *vp,
            oid * name,
            size_t * length,
            int exact, size_t * var_len, WriteMethod ** write_method)
{
    int             store_idx = 0;
#if !defined(linux)
#if defined(solaris2)
    int             freemem;
    int             swap_total, swap_used;
#elif defined(hpux10) || defined(hpux11)
    struct pst_dynamic pst_buf;
#elif defined(darwin8)
    vm_statistics_data_t vm_stat;
    int count = HOST_VM_INFO_COUNT;
#elif defined(TOTAL_MEMORY_SYMBOL) || defined(USE_SYSCTL_VM)
#ifdef VM_UVMEXP
    struct uvmexp   uvmexp_totals;
#endif
    struct vmtotal  memory_totals;
#endif
#if HAVE_KVM_GETSWAPINFO
    struct kvm_swap swapinfo;
    static kvm_t *kd = NULL;
#endif
#if HAVE_SYS_POOL_H
    struct pool     mbpool, mclpool;
    int             i;
#endif
#ifdef MBSTAT_SYMBOL
    struct mbstat   mbstat;
#endif
#endif                          /* !linux */
    static char     string[1024];
    struct HRFS_statfs stat_buf;

    if (vp->magic == HRSTORE_MEMSIZE) {
        if (header_hrstore(vp, name, length, exact, var_len, write_method)
            == MATCH_FAILED)
            return NULL;
    } else {

really_try_next:
	store_idx = header_hrstoreEntry(vp, name, length, exact, var_len,
					write_method);
	if (store_idx == MATCH_FAILED)
	    return NULL;

	if (store_idx > HRS_TYPE_FIXED_MAX) {
	    if (HRFS_statfs(HRFS_entry->HRFS_mount, &stat_buf) < 0) {
		snmp_log_perror(HRFS_entry->HRFS_mount);
		goto try_next;
	    }
	}
#if !defined(linux) && !defined(solaris2)
        else
            switch (store_idx) {
            case HRS_TYPE_MEM:
            case HRS_TYPE_SWAP:
#ifdef USE_SYSCTL_VM
                {
                    int             mib[2];
                    size_t          len = sizeof(memory_totals);
                    mib[0] = CTL_VM;
                    mib[1] = VM_METER;
                    sysctl(mib, 2, &memory_totals, &len, NULL, 0);
#ifdef VM_UVMEXP
                    mib[1] = VM_UVMEXP;
		    len = sizeof(uvmexp_totals);
                    sysctl(mib, 2, &uvmexp_totals, &len, NULL, 0);
#endif
                }
#elif defined(darwin8)
		host_statistics(myHost,HOST_VM_INFO,&vm_stat,&count);
#elif defined(hpux10) || defined(hpux11)
                pstat_getdynamic(&pst_buf, sizeof(struct pst_dynamic), 1, 0);
#elif defined(TOTAL_MEMORY_SYMBOL)
                auto_nlist(TOTAL_MEMORY_SYMBOL, (char *) &memory_totals,
                           sizeof(struct vmtotal));
#endif
#if HAVE_KVM_GETSWAPINFO
		if (kd == NULL)
		    kd = kvm_openfiles(NULL, NULL, NULL, O_RDONLY, NULL);
		if (!kd) {
		    snmp_log_perror("kvm_openfiles");
		    goto try_next;
		}
		if (kvm_getswapinfo(kd, &swapinfo, 1, 0) < 0) {
		    snmp_log_perror("kvm_getswapinfo");
		    goto try_next;
		}
#endif
                break;
#if !defined(hpux10) && !defined(hpux11)
            case HRS_TYPE_MBUF:
#if HAVE_SYS_POOL_H
                auto_nlist(MBPOOL_SYMBOL, (char *) &mbpool,
                           sizeof(mbpool));
                auto_nlist(MCLPOOL_SYMBOL, (char *) &mclpool,
                           sizeof(mclpool));
#endif
#ifdef MBSTAT_SYMBOL
                auto_nlist(MBSTAT_SYMBOL, (char *) &mbstat,
                           sizeof(mbstat));
#endif
                break;
#endif      /* !hpux10 && !hpux11 */
            default:
                break;
            }
#endif                          /* !linux && !solaris2 */
    }



    switch (vp->magic) {
    case HRSTORE_MEMSIZE:
        long_return = physmem * (pagesize / 1024);
        return (u_char *) & long_return;

    case HRSTORE_INDEX:
        long_return = store_idx;
        return (u_char *) & long_return;
    case HRSTORE_TYPE:
        if (store_idx > HRS_TYPE_FIXED_MAX)
            if (storageUseNFS && Check_HR_FileSys_NFS())
                storage_type_id[storage_type_len - 1] = 10;     /* Network Disk */
            else
                storage_type_id[storage_type_len - 1] = 4;      /* Assume fixed */
        else
            switch (store_idx) {
            case HRS_TYPE_MEM:
                storage_type_id[storage_type_len - 1] = 2;      /* RAM */
                break;
            case HRS_TYPE_SWAP:
                storage_type_id[storage_type_len - 1] = 3;      /* Virtual Mem */
                break;
            case HRS_TYPE_MBUF:
                storage_type_id[storage_type_len - 1] = 1;      /* Other */
                break;
            default:
                storage_type_id[storage_type_len - 1] = 1;      /* Other */
                break;
            }
        *var_len = sizeof(storage_type_id);
        return (u_char *) storage_type_id;
    case HRSTORE_DESCR:
        if (store_idx > HRS_TYPE_FIXED_MAX) {
            strncpy(string, HRFS_entry->HRFS_mount, sizeof(string)-1);
            string[ sizeof(string)-1 ] = 0;
            *var_len = strlen(string);
            return (u_char *) string;
        } else {
            /* store_idx = store_idx - 1; */
            *var_len = strlen(hrs_descr[store_idx]);
            return (u_char *) hrs_descr[store_idx];
        }
    case HRSTORE_UNITS:
        if (store_idx > HRS_TYPE_FIXED_MAX)
#if HRFS_HAS_FRSIZE
            long_return = stat_buf.f_frsize;
#else
            long_return = stat_buf.f_bsize;
#endif
        else
            switch (store_idx) {
            case HRS_TYPE_MEM:
            case HRS_TYPE_SWAP:
#if defined(USE_SYSCTL) || defined(solaris2)
                long_return = pagesize;
#elif defined(NBPG)
                long_return = NBPG;
#else
                long_return = 1024;     /* Report in Kb */
#endif
                break;
            case HRS_TYPE_MBUF:
#ifdef MSIZE
                long_return = MSIZE;
#elif defined(linux)
                long_return = 1024;
#else
                long_return = 256;
#endif
                break;
            default:
#if NO_DUMMY_VALUES
                goto try_next;
#endif
                long_return = 1024;     /* As likely as any! */
                break;
            }
        return (u_char *) & long_return;
    case HRSTORE_SIZE:
        if (store_idx > HRS_TYPE_FIXED_MAX)
            long_return = stat_buf.f_blocks;
        else
            switch (store_idx) {
#if defined(linux)
            case HRS_TYPE_MEM:
            case HRS_TYPE_SWAP:
                long_return = linux_mem(store_idx, HRSTORE_SIZE);
                break;
#elif defined(solaris2)
            case HRS_TYPE_MEM:
                long_return = physmem;
                break;
            case HRS_TYPE_SWAP:
                sol_get_swapinfo(&swap_total, &swap_used);
                long_return = swap_total;
                break;
#elif defined(hpux10) || defined(hpux11)
            case HRS_TYPE_MEM:
                long_return = pst_buf.psd_rm;
                break;
            case HRS_TYPE_SWAP:
                long_return = pst_buf.psd_vm;
                break;
#elif defined(darwin8)
            case HRS_TYPE_MEM:
                long_return = physmem;
                break;
            case HRS_TYPE_SWAP:
                long_return = -1;
	        break;
#if defined(MBSTAT_SYMBOL)
           case HRS_TYPE_MBUF:
                long_return = mbstat.m_mbufs;
                break;
#endif
#elif defined(TOTAL_MEMORY_SYMBOL) || defined(USE_SYSCTL_VM)
            case HRS_TYPE_MEM:
                long_return = memory_totals.t_rm;
                break;
            case HRS_TYPE_SWAP:
#if HAVE_KVM_GETSWAPINFO
		long_return = swapinfo.ksw_total;
#elif defined(VM_UVMEXP)
                long_return = uvmexp_totals.swpages;
#else
                long_return = memory_totals.t_vm;
#endif
                break;
#else               /* !linux && !solaris2 && !hpux10 && !hpux11 && ... */
            case HRS_TYPE_MEM:
                long_return = physmem;
                break;
            case HRS_TYPE_SWAP:
#if NO_DUMMY_VALUES
                goto try_next;
#endif
                long_return = 0;
                break;
#endif              /* !linux && !solaris2 && !hpux10 && !hpux11 && ... */
            case HRS_TYPE_MBUF:
#ifdef linux
                long_return = linux_mem(store_idx, HRSTORE_SIZE);
#elif HAVE_SYS_POOL_H
                long_return = 0;
                for (i = 0;
                     i <
                     sizeof(mbstat.m_mtypes) / sizeof(mbstat.m_mtypes[0]);
                     i++)
                    long_return += mbstat.m_mtypes[i];
#elif defined(MBSTAT_SYMBOL) && defined(STRUCT_MBSTAT_HAS_M_MBUFS)
                long_return = mbstat.m_mbufs;
#elif defined(NO_DUMMY_VALUES)
                goto try_next;
#else
                long_return = 0;
#endif
                break;
            default:
#if NO_DUMMY_VALUES
                goto try_next;
#endif
                long_return = 1024;
                break;
            }
        return (u_char *) & long_return;
    case HRSTORE_USED:
        if (store_idx > HRS_TYPE_FIXED_MAX)
            long_return = (stat_buf.f_blocks - stat_buf.f_bfree);
        else
            switch (store_idx) {
#if defined(linux)
            case HRS_TYPE_MBUF:
            case HRS_TYPE_MEM:
            case HRS_TYPE_SWAP:
                long_return = linux_mem(store_idx, HRSTORE_USED);
                break;
#elif defined(solaris2)
            case HRS_TYPE_MEM:
                getKstatInt("unix", "system_pages", "freemem", &freemem);
                long_return = physmem - freemem;
                break;
            case HRS_TYPE_SWAP:
                sol_get_swapinfo(&swap_total, &swap_used);
                long_return = swap_used;
                break;
#elif defined(hpux10) || defined(hpux11)
            case HRS_TYPE_MEM:
                long_return = pst_buf.psd_arm;
                break;
            case HRS_TYPE_SWAP:
                long_return = pst_buf.psd_avm;
                break;
#elif defined(darwin8)
	    case HRS_TYPE_MEM:
		long_return = vm_stat.active_count + vm_stat.inactive_count + vm_stat.wire_count;
		break;
	    case HRS_TYPE_SWAP:
		long_return = -1;
		break;
#if defined(MBSTAT_SYMBOL)
           case HRS_TYPE_MBUF:
                long_return = mbstat.m_mbufs;
                break;
#endif
#elif defined(TOTAL_MEMORY_SYMBOL) || defined(USE_SYSCTL_VM)
            case HRS_TYPE_MEM:
                long_return = memory_totals.t_arm;
                break;
            case HRS_TYPE_SWAP:
#if HAVE_KVM_GETSWAPINFO
		long_return = swapinfo.ksw_used;
#elif defined(VM_UVMEXP)
		long_return = uvmexp_totals.swpginuse;
#else
                long_return = memory_totals.t_avm;
#endif
                break;
#endif              /* linux || solaris2 || hpux10 || hpux11 || ... */

#if !defined(linux) && !defined(solaris2) && !defined(hpux10) && !defined(hpux11)
            case HRS_TYPE_MBUF:
#if HAVE_SYS_POOL_H
                long_return =
		    (mbpool.pr_nget - mbpool.pr_nput) * mbpool.pr_size +
		    (mclpool.pr_nget - mclpool.pr_nput) * mclpool.pr_size;
#ifdef MSIZE
		long_return /= MSIZE;
#else
		long_return /= 256;
#endif
#elif defined(MBSTAT_SYMBOL) && defined(STRUCT_MBSTAT_HAS_M_CLUSTERS)
                long_return = mbstat.m_clusters - mbstat.m_clfree;      /* unlikely, but... */
#elif defined(NO_DUMMY_VALUES)
                goto try_next;
#else
                long_return = 0;
#endif
                break;
#endif                      /* !linux && !solaris2 && !hpux10 && !hpux11 && ... */
            default:
#if NO_DUMMY_VALUES
                goto try_next;
#endif
                long_return = 1024;
                break;
            }
        return (u_char *) & long_return;
    case HRSTORE_FAILS:
        if (store_idx > HRS_TYPE_FIXED_MAX)
#if NO_DUMMY_VALUES
	    goto try_next;
#else
            long_return = 0;
#endif
        else
            switch (store_idx) {
            case HRS_TYPE_MEM:
            case HRS_TYPE_SWAP:
#if NO_DUMMY_VALUES
                goto try_next;
#endif
                long_return = 0;
                break;
#if !defined(linux) && !defined(solaris2) && !defined(hpux10) && !defined(hpux11)  && defined(MBSTAT_SYMBOL)
            case HRS_TYPE_MBUF:
                long_return = mbstat.m_drops;
                break;
#endif                          /* !linux && !solaris2 && !hpux10 && !hpux11 && MBSTAT_SYMBOL */
            default:
#if NO_DUMMY_VALUES
                goto try_next;
#endif
                long_return = 0;
                break;
            }
        return (u_char *) & long_return;
    default:
        DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_hrstore\n",
                    vp->magic));
    }
    return NULL;

  try_next:
    if (!exact)
        goto really_try_next;

    return NULL;
}


        /*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

static int      FS_storage;
static int      HRS_index;

void
Init_HR_Store(void)
{
#if !defined(solaris2) && !defined(hpux10) && !defined(hpux11)
    HRS_index = 0;
#else
    HRS_index = HRS_TYPE_MBUF;
#endif

    Init_HR_FileSys();
    FS_storage = 0;             /* Start with file-based storage */
}

int
Get_Next_HR_Store(void)
{
    /*
     * Fixed-style 'other' storage types
     */
    long_return = -1;
    if (FS_storage == 0) {
        ++HRS_index;
        if (HRS_index <= HRS_TYPE_FIXED_MAX)
            return HRS_index;
        else {
            FS_storage = 1;
            HRS_index = 0;
        }
    }

    /*
     * File-based storage 
     */
    HRS_index = Get_Next_HR_FileSys();

    if (HRS_index >= 0)
        return HRS_index + HRS_TYPE_FIXED_MAX;

    return -1;
}

#ifdef linux
int
linux_mem(int mem_type, int size_or_used)
{
    netsnmp_memory_info *mem;

    netsnmp_memory_load();
    switch (mem_type) {
    case HRS_TYPE_MEM:
        mem = netsnmp_memory_get_byIdx( -1, 0 );
        break;
    case HRS_TYPE_SWAP:
        mem = netsnmp_memory_get_byIdx( -2, 0 );
        break;
    case HRS_TYPE_MBUF:
            /*
             * The previous code reported total memory
             * as "Memory Buffer" size
             */
        if (size_or_used == HRSTORE_SIZE)
            mem = netsnmp_memory_get_byIdx( -1, 0 );
        else
            mem = netsnmp_memory_get_byIdx( -3, 0 );
        return (mem ? mem->size : -1);
    default:
        return -1;
    }

    if (mem)
        return (size_or_used == HRSTORE_SIZE ?  mem->size
                                             : (mem->size - mem->free));
    return -1;
}
#endif

#ifdef solaris2
void
sol_get_swapinfo(int *totalP, int *usedP)
{
    struct anoninfo ainfo;

    if (swapctl(SC_AINFO, &ainfo) < 0) {
        *totalP = *usedP = 0;
        return;
    }

    *totalP = ainfo.ani_max;
    *usedP = ainfo.ani_resv;
}
#endif                          /* solaris2 */

#ifdef WIN32
char *win_realpath(const char *file_name, char *resolved_name)
{
	char szFile[_MAX_PATH + 1];
	char *pszRet;
 	
	pszRet = _fullpath(szFile, resolved_name, MAX_PATH);
 	
	return pszRet;  
}

static int win_statfs (const char *path, struct win_statfs *buf)
{
    HINSTANCE h;
    FARPROC f;
    int retval = 0;
    char tmp [MAX_PATH], resolved_path [MAX_PATH];
    GetFullPathName(path, MAX_PATH, resolved_path, NULL);
    /* TODO - Fix this! The realpath macro needs defined
     * or rewritten into the function.
     */
    
    win_realpath(path, resolved_path);
    
    if (!resolved_path)
    	retval = - 1;
    else {
    	/* check whether GetDiskFreeSpaceExA is supported */
        h = LoadLibraryA ("kernel32.dll");
        if (h)
			f = GetProcAddress (h, "GetDiskFreeSpaceExA");
        else
        	f = NULL;
		
        if (f) {
			ULARGE_INTEGER bytes_free, bytes_total, bytes_free2;
            if (!f (resolved_path, &bytes_free2, &bytes_total, &bytes_free)) {
				errno = ENOENT;
				retval = - 1;
			} else {
				buf -> f_bsize = FAKED_BLOCK_SIZE;
				buf -> f_bfree = (bytes_free.QuadPart) / FAKED_BLOCK_SIZE;
				buf -> f_files = buf -> f_blocks = (bytes_total.QuadPart) / FAKED_BLOCK_SIZE;
				buf -> f_ffree = buf -> f_bavail = (bytes_free2.QuadPart) / FAKED_BLOCK_SIZE;
			}
		} else {
			DWORD sectors_per_cluster, bytes_per_sector;
			if (h) FreeLibrary (h);
			if (!GetDiskFreeSpaceA (resolved_path, &sectors_per_cluster,
					&bytes_per_sector, &buf -> f_bavail, &buf -> f_blocks)) {
                errno = ENOENT;
                retval = - 1;
            } else {
                buf -> f_bsize = sectors_per_cluster * bytes_per_sector;
                buf -> f_files = buf -> f_blocks;
                buf -> f_ffree = buf -> f_bavail;
                buf -> f_bfree = buf -> f_bavail;
            }
		}
		if (h) FreeLibrary (h);
	}

	/* get the FS volume information */
	if (strspn (":", resolved_path) > 0) resolved_path [3] = '\0'; /* we want only the root */    
	if (GetVolumeInformation (resolved_path, NULL, 0, &buf -> f_fsid, &buf -> f_namelen, 
									NULL, tmp, MAX_PATH)) {
		if (strcasecmp ("NTFS", tmp) == 0) {
			buf -> f_type = NTFS_SUPER_MAGIC;
		} else {
			buf -> f_type = MSDOS_SUPER_MAGIC;
		}
	} else {
		errno = ENOENT;
		retval = - 1;
	}
	return retval;
}
#endif	/* WIN32 */
