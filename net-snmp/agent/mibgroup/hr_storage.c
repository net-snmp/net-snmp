/*
 *  Host Resources MIB - storage group implementation - hr_storage.c
 *
 */

#include <config.h>

#include <nlist.h>

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

#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#if HAVE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
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

#define HRSTORE_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/


#ifndef linux
static struct nlist hrstore_nl[] = {
#define N_PHYSMEM     0
#define N_MEMTOTAL    1
#define N_MBUFSTAT    2
#if !defined(hpux) && !defined(solaris2)
        { "_physmem"},
        { "_total"},
        { "_mbstat"},
#else
        { "physmem"},
        { "total"},
        { "mbstat"},
#endif
        { 0 },
};
#endif


#ifdef solaris2
extern struct mnttab *HRFS_entry;
#else
extern struct mntent *HRFS_entry;
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/
int Get_Next_HR_Store __P((void));
void  Init_HR_Store __P((void));

int linux_mem __P((int, int));

void	init_hr_storeage( )
{
#ifndef linux
    init_nlist( hrstore_nl );
#endif
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
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
#define HRSTORE_NAME_LENGTH	9
    oid newname[MAX_NAME_LEN];
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_hrstore: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
    newname[HRSTORE_NAME_LENGTH] = 0;
    result = compare(name, *length, newname, (int)vp->namelen + 1);
    if ((exact && (result != 0)) || (!exact && (result >= 0)))
        return(MATCH_FAILED);
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
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
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
#define HRSTORE_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int storage_idx, LowIndex = -1;
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_hrstoreEntry: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
	/* Find "next" storage entry */

    Init_HR_Store();
    for ( ;; ) {
        storage_idx = Get_Next_HR_Store();
#ifdef DODEBUG
printf ("(index %d ....", storage_idx);
#endif
        if ( storage_idx == -1 )
	    break;
	newname[HRSTORE_ENTRY_NAME_LENGTH] = storage_idx;
#ifdef DODEBUG
sprint_objid (c_oid, newname, *length);
printf ("%s\n", c_oid);
#endif
        result = compare(name, *length, newname, (int)vp->namelen + 1);
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
#ifdef DODEBUG
        printf ("... index out of range\n");
#endif
        return(MATCH_FAILED);
    }

    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

#ifdef DODEBUG
    sprint_objid (c_oid, name, *length);
    printf ("... get storage stats %s\n", c_oid);
#endif
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
    int     (**write_method)();
{
    int store_idx;
#ifndef linux
    int physmem;
#ifndef solaris2
    struct vmtotal memory_totals;
    struct mbstat  mbstat;
#endif
#else
    struct stat  kc_buf;
#endif
    static char string[100];
#ifdef solaris2
    struct statvfs stat_buf;
#else
    struct statfs stat_buf;
#endif

    if ( vp->magic == HRSTORE_MEMSIZE ) {
        if (header_hrstore(vp, name, length, exact, var_len, write_method) == MATCH_FAILED )
	    return NULL;
#ifndef linux
	KNLookup(hrstore_nl, N_PHYSMEM, (char *)&physmem, sizeof (int));
#endif
    }
    else {
        
        store_idx = header_hrstoreEntry(vp, name, length, exact, var_len, write_method);
        if ( store_idx == MATCH_FAILED )
	    return NULL;

	if ( store_idx < HRS_TYPE_FS_MAX ) {
#ifdef solaris2
	    if ( statvfs( HRFS_entry->mnt_mountp, &stat_buf) < 0 )
#else
	    if ( statfs( HRFS_entry->mnt_dir, &stat_buf) < 0 )
#endif
		return NULL;
	}
#if !defined(linux) && !defined(solaris2)
	else switch ( store_idx ) {
		case HRS_TYPE_MEM:
		case HRS_TYPE_SWAP:
			KNLookup(hrstore_nl, N_MEMTOTAL, (char *)&memory_totals, sizeof (struct vmtotal));
			break;
		case HRS_TYPE_MBUF:
			KNLookup(hrstore_nl, N_MBUFSTAT, (char *)&mbstat, sizeof (struct mbstat));
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
	    return (u_char *)&storage_type_id;
	case HRSTORE_DESCR:
	    if (store_idx<HRS_TYPE_FS_MAX) {
#ifdef solaris2
	        strcpy(string, HRFS_entry->mnt_mountp);
#else
	        strcpy(string, HRFS_entry->mnt_dir);
#endif
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
		case HRS_TYPE_MEM:
			long_return = memory_totals.t_rm;
			break;
		case HRS_TYPE_SWAP:
			long_return = memory_totals.t_vm;
			break;
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
		case HRS_TYPE_MEM:
			long_return = memory_totals.t_arm;
			break;
		case HRS_TYPE_SWAP:
			long_return = memory_totals.t_avm;
			break;
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
