/*
 *  Host Resources MIB - storage group implementation - hr_storage.c
 *
 */

#include <config.h>

#include <sys/param.h>
#if HAVE_SYS_VM_H
#include <sys/vm.h>
#else
#if HAVE_VM_VM_H
#include <vm/vm.h>
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
#endif /* vm/vm.h */
#endif /* sys/vm.h */
#ifdef HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif

#include "host_res.h"
#include "hr_storage.h"
#include "hr_filesys.h"
#include "auto_nlist.h"

#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#if HAVE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#if HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif
#ifdef HAVE_SYS_MBUF_H
#include <sys/mbuf.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_MACHINE_PARAM_H
#include <machine/param.h>
#endif
#include <sys/stat.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "../../../snmplib/system.h"

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

#elif defined(HAVE_GETFSSTAT)

extern struct statfs *HRFS_entry;
extern int fscount;
#define HRFS_statfs	statfs
#define HRFS_mount	f_mntonname

#else

extern struct mntent *HRFS_entry;
#define HRFS_mount	mnt_dir
#define HRFS_statfs	statfs

#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/
int Get_Next_HR_Store __P((void));
void  Init_HR_Store __P((void));
int header_hrstore __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));
int header_hrstoreEntry __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));

int linux_mem __P((int, int));

void	init_hr_storeage __P((void))
{
    auto_nlist(PHYSMEM_SYMBOL,0,0);
#ifdef TOTAL_MEMORY_SYMBOL
    auto_nlist(TOTAL_MEMORY_SYMBOL,0,0);
#endif
    auto_nlist(MBSTAT_SYMBOL,0,0);
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

int
header_hrstore(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRSTORE_NAME_LENGTH	9
    oid newname[MAX_NAME_LEN];
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_hrstore: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
    newname[HRSTORE_NAME_LENGTH] = 0;
    result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;

    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */
    return(MATCH_SUCCEEDED);
}

int
header_hrstoreEntry(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRSTORE_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int storage_idx, LowIndex = -1;
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("var_hrstoreEntry: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
	/* Find "next" storage entry */

    Init_HR_Store();
    for ( ;; ) {
        storage_idx = Get_Next_HR_Store();
        DEBUGP("(index %d ....", storage_idx);
        if ( storage_idx == -1 )
	    break;
	newname[HRSTORE_ENTRY_NAME_LENGTH] = storage_idx;
        if (snmp_get_do_debugging()) {
          sprint_objid (c_oid, newname, *length);
          DEBUGP("%s\n", c_oid);
        }
        result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowIndex = storage_idx;
	    /* Save storage status information */
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowIndex == -1 || storage_idx < LowIndex )) {
	    LowIndex = storage_idx;
	    /* Save storage status information */
#ifdef HRSTORE_MONOTONICALLY_INCREASING
            break;
#endif
	}
    }

    if ( LowIndex == -1 ) {
        DEBUGP ("... index out of range\n");
        return(MATCH_FAILED);
    }

    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP ("... get storage stats %s\n", c_oid);
    }
    return LowIndex;
}

oid storage_type_id[] = { 1,3,6,1,2,1, 25, 2, 1, 1 };		/* hrStorageOther */
int storage_type_len = sizeof(storage_type_id)/sizeof(storage_type_id[0]);

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/

static char *hrs_descr[] = {
	NULL,
	"Real Memory",		/* HRS_TYPE_MEM */
	"Swap Space",		/* HRS_TYPE_SWAP */
	"Memory Buffers"	/* HRS_TYPE_MBUF */
};



u_char	*
var_hrstore(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
    int store_idx=0;
#ifndef linux
    int physmem;
#ifndef solaris2
#ifdef TOTAL_MEMORY_SYMBOL
    struct vmtotal memory_totals;
#endif
    struct mbstat  mbstat;
#endif
#else
    struct stat  kc_buf;
#endif
    static char string[100];
    struct HRFS_statfs stat_buf;

    if ( vp->magic == HRSTORE_MEMSIZE ) {
        if (header_hrstore(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	    return NULL;
#ifndef linux
	auto_nlist(PHYSMEM_SYMBOL, (char *)&physmem, sizeof (int));
#endif
    }
    else {
        
        store_idx = header_hrstoreEntry(vp, name, length, exact, var_len, write_method);
        if ( store_idx == MATCH_FAILED )
	    return NULL;

	if ( store_idx < HRS_TYPE_FS_MAX ) {
	    if ( HRFS_statfs( HRFS_entry->HRFS_mount, &stat_buf) < 0 )
		return NULL;
	}
#if !defined(linux) && !defined(solaris2)
	else switch ( store_idx ) {
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
#ifdef TOTAL_MEMORY_SYMBOL
			auto_nlist(TOTAL_MEMORY_SYMBOL, (char *)&memory_totals, sizeof (struct vmtotal));
#endif
			break;
		case HRS_TYPE_MBUF:
			auto_nlist(MBSTAT_SYMBOL, (char *)&mbstat, sizeof (struct mbstat));
			break;
		default:
			break;
	}
#endif
    }
        


    switch (vp->magic){
	case HRSTORE_MEMSIZE:
#ifndef linux
#ifdef PGSHIFT
	    long_return = physmem << PGSHIFT;
#elif defined(PAGE_SHIFT)
	    long_return = physmem << PAGE_SHIFT;
#elif defined(PAGE_SIZE)
	    long_return = physmem * PAGE_SIZE;
#else
	    long_return = physmem * PAGESIZE;
#endif
#else
	    stat("/proc/kcore", &kc_buf);
	    long_return = kc_buf.st_size/1024;	/* 4K too large ? */
#endif
	    return (u_char *)&long_return;

	case HRSTORE_INDEX:
	    long_return = store_idx;
	    return (u_char *)&long_return;
	case HRSTORE_TYPE:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		storage_type_id[storage_type_len-1] = 4;	/* Assume fixed */
	    else switch ( store_idx ) {
		case HRS_TYPE_MEM:
			storage_type_id[storage_type_len-1] = 2;	/* RAM */
			break;
		case HRS_TYPE_SWAP:
			storage_type_id[storage_type_len-1] = 3;	/* Virtual Mem */
			break;
		case HRS_TYPE_MBUF:
			storage_type_id[storage_type_len-1] = 1;	/* Other */
			break;
		default:
			storage_type_id[storage_type_len-1] = 1;	/* Other */
			break;
	    }
            *var_len = sizeof(storage_type_id);
	    return (u_char *)storage_type_id;
	case HRSTORE_DESCR:
	    if (store_idx<HRS_TYPE_FS_MAX) {
	        strcpy(string, HRFS_entry->HRFS_mount);
	        *var_len = strlen(string);
	        return (u_char *) string;
	    }
	    else {
	        store_idx = store_idx-HRS_TYPE_FS_MAX;
	        *var_len = strlen( hrs_descr[store_idx] );
	        return (u_char *)hrs_descr[store_idx];
	    }
	case HRSTORE_UNITS:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		long_return = stat_buf.f_bsize;
	    else switch ( store_idx ) {
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
#ifdef NBPG
			long_return = NBPG;
#else
			long_return = 1024;	/* Report in Kb */
#endif
			break;
		case HRS_TYPE_MBUF:
#ifdef MSIZE
			long_return = MSIZE;
#else
			long_return = 256;
#endif
			break;
		default:
			long_return = 1024;	/* As likely as any! */
			break;
	    }
	    return (u_char *)&long_return;
	case HRSTORE_SIZE:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		long_return = stat_buf.f_blocks;
	    else switch ( store_idx ) {
#if !defined(linux) && !defined(solaris2)
#ifdef TOTAL_MEMORY_SYMBOL
		case HRS_TYPE_MEM:
			long_return = memory_totals.t_rm;
			break;
		case HRS_TYPE_SWAP:
			long_return = memory_totals.t_vm;
			break;
#else
		case HRS_TYPE_MEM:
			long_return = physmem * PAGE_SIZE / 1024;
			break;
		case HRS_TYPE_SWAP:
			break;
#endif
		case HRS_TYPE_MBUF:
			long_return = mbstat.m_mbufs;
			break;
#else	/* linux */
#ifdef linux
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
			long_return = linux_mem( store_idx, HRSTORE_SIZE);
			break;
#endif
#endif
		default:
			long_return = 1024;
			break;
	    }
	    return (u_char *)&long_return;
	case HRSTORE_USED:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		long_return = (stat_buf.f_blocks - stat_buf.f_bfree);
	    else switch ( store_idx ) {
#if !defined(linux) && !defined(solaris2)
#ifdef TOTAL_MEMORY_SYMBOL
		case HRS_TYPE_MEM:
			long_return = memory_totals.t_arm;
			break;
		case HRS_TYPE_SWAP:
			long_return = memory_totals.t_avm;
			break;
#endif
		case HRS_TYPE_MBUF:
			long_return = mbstat.m_clusters - mbstat.m_clfree;	/* unlikely, but... */
			break;
#else	/* linux */
#ifdef linux
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
			long_return = linux_mem( store_idx, HRSTORE_USED);
			break;
#endif
#endif
		default:
			long_return = 1024;
			break;
	    }
	    return (u_char *)&long_return;
	case HRSTORE_FAILS:
	    if ( store_idx < HRS_TYPE_FS_MAX )
		long_return = 0;
	    else switch ( store_idx ) {
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
			long_return = 0;
			break;
#if !defined(linux) && !defined(solaris2)
		case HRS_TYPE_MBUF:
			long_return = mbstat.m_drops;
			break;
#endif
		default:
			long_return = 0;
			break;
	    }
	    return (u_char *)&long_return;
	default:
	    ERROR_MSG("");
    }
    return NULL;
}


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/

static int FS_storage;
static int HRS_index;

void
Init_HR_Store __P((void))
{
   HRS_index = -1;
   Init_HR_FileSys();
   FS_storage = 1;	/* Start with file-based storage */
}

int
Get_Next_HR_Store()
{
		/* File-based storage */
    long_return = -1;
    if ( FS_storage == 1 ) {
	HRS_index = Get_Next_HR_FileSys();

        if ( HRS_index >= 0 ) 
            return HRS_index;
	FS_storage = 0;		/* End of filesystems */
	HRS_index = HRS_TYPE_FS_MAX;
    }

		/* 'Other' storage types */
    ++HRS_index;
#ifndef solaris2
    if ( HRS_index < HRS_TYPE_MAX )
	return HRS_index;
    else
#endif
	return -1;
}

#ifdef linux
int
linux_mem( mem_type, size_or_used )
    int mem_type;
    int size_or_used;
{
    FILE *fp;
    char buf[100];
    int size = -1, used = -1;

    if ((fp = fopen( "/proc/meminfo", "r")) == NULL )
	return -1;

    while ( fgets( buf, 100, fp ) != NULL ) {
	if (( !strncmp( buf, "Mem:", 4 ) && mem_type == HRS_TYPE_MEM ) ||
	    ( !strncmp( buf, "Swap:", 5 ) && mem_type == HRS_TYPE_SWAP )) {
		sscanf( buf, "%*s %d %d", &size, &used );
		break;
	}
    }

    fclose(fp);
    return ( size_or_used == HRSTORE_SIZE ? size : used )/1024;

}
#endif
