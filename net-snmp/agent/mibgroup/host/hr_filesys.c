/*
 *  Host Resources MIB - File System device group implementation - hr_filesys.c
 *
 */

#include <config.h>

#include "host_res.h"
#include "hr_filesys.h"
#include "hr_utils.h"

#if HAVE_MNTENT_H
#include <mntent.h>
#endif
#if HAVE_SYS_MNTENT_H
#include <sys/mntent.h>
#endif
#if HAVE_SYS_MNTTAB_H
#include <sys/mnttab.h>
#endif
#if HAVE_SYS_VFS_H
#include <sys/vfs.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_MOUNT_H
#include <sys/mount.h>
#endif

#include <ctype.h>
#if STDC_HEADERS
#include <string.h>
#include <stdlib.h>
#else
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#endif

#define HRFS_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

#ifdef solaris2

struct mnttab  HRFS_entry_struct;
struct mnttab *HRFS_entry = &HRFS_entry_struct;
#define	HRFS_name	mnt_special
#define	HRFS_mount	mnt_mountp
#define	HRFS_type	mnt_fstype
#define	HRFS_statfs	statvfs

#elif defined(HAVE_GETFSSTAT)
static struct statfs *fsstats;
static int fscount;
struct statfs *HRFS_entry;
#define HRFS_statfs	statfs
#ifdef MFSNAMELEN
#define HRFS_type	f_fstypename
#else
#define HRFS_type	f_type
#endif
#define HRFS_mount	f_mntonname
#define HRFS_name	f_mntfromname

#else

struct mntent *HRFS_entry;
#define	HRFS_name	mnt_fsname
#define	HRFS_mount	mnt_dir
#define	HRFS_type	mnt_type
#define	HRFS_statfs	statfs

#endif

#define	FULL_DUMP	0
#define	PART_DUMP	1

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

extern void  Init_HR_FileSys __P((void));
extern int   Get_Next_HR_FileSys __P((void));
char *cook_device __P((char *));
static u_char * when_dumped __P(( char* filesys, int level, int* length ));
int header_hrfilesys __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));

void	init_hr_filesys( )
{
	/* No initialisation needed */
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

int
header_hrfilesys(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRFSYS_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int fsys_idx, LowIndex=-1;
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP("var_hrfilesys: %s %d\n", c_oid, exact);
    }
    
    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
	/* Find "next" file system entry */

    Init_HR_FileSys();
    for ( ;; ) {
        fsys_idx = Get_Next_HR_FileSys();
        if ( fsys_idx == -1 )
	    break;
	newname[HRFSYS_ENTRY_NAME_LENGTH] = fsys_idx;
        result = compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowIndex = fsys_idx;
            break;
	}
        if ((!exact && (result < 0)) &&
		(LowIndex == -1 || fsys_idx < LowIndex )) {
	    LowIndex = fsys_idx;
#ifdef HRFS_MONOTONICALLY_INCREASING
	    break;
#endif
	}
    }

    if ( LowIndex == -1 ) {
        DEBUGP("... index out of range\n");
        return(MATCH_FAILED);
    }

    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP("... get filesys stats %s\n", c_oid);
    }
    return LowIndex;
}


oid fsys_type_id[] = { 1,3,6,1,2,1, 25, 3, 9, 1 };		/* hrFSOther */
int fsys_type_len = sizeof(fsys_type_id)/sizeof(fsys_type_id[0]);

	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrfilesys(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
    int  fsys_idx;
    static char string[100];
    char *mnt_type;

    fsys_idx = header_hrfilesys(vp, name, length, exact, var_len, write_method);
    if ( fsys_idx == MATCH_FAILED )
	return NULL;
        

    switch (vp->magic){
	case HRFSYS_INDEX:
	    long_return = fsys_idx;
	    return (u_char *)&long_return;
	case HRFSYS_MOUNT:
	    sprintf(string, HRFS_entry->HRFS_mount);
	    *var_len = strlen(string);
	    return (u_char *) string;
	case HRFSYS_RMOUNT:
#if HAVE_GETFSSTAT
#if defined(MFSNAMELEN)
	    if (!strcmp( HRFS_entry->HRFS_type, MOUNT_NFS))
#else
	    if (HRFS_entry->HRFS_type == MOUNT_NFS)
#endif
#else
	    if (!strcmp( HRFS_entry->HRFS_type, MNTTYPE_NFS))
#endif
	        sprintf(string, HRFS_entry->HRFS_name);
	    else
		string[0] = '\0';
	    *var_len = strlen(string);
	    return (u_char *) string;

	case HRFSYS_TYPE:
			/*
			 * Not sufficient to identity the file
			 *   type precisely, but it's a start.
			 */
#if HAVE_GETFSSTAT && !defined(MFSNAMELEN)
	    switch (HRFS_entry->HRFS_type) {
	    case MOUNT_UFS: fsys_type_id[fsys_type_len-1] = 3; break;
	    case MOUNT_NFS: fsys_type_id[fsys_type_len-1] = 14; break;
	    case MOUNT_MFS: fsys_type_id[fsys_type_len-1] = 8; break;
	    case MOUNT_MSDOS: fsys_type_id[fsys_type_len-1] = 5; break;
	    case MOUNT_LFS: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_LOFS: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_FDESC: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_PORTAL: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_NULL: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_UMAP: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_KERNFS: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_PROCFS: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_AFS: fsys_type_id[fsys_type_len-1] = 16; break;
	    case MOUNT_CD9660: fsys_type_id[fsys_type_len-1] = 12; break;
	    case MOUNT_UNION: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_DEVFS: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_EXT2FS: fsys_type_id[fsys_type_len-1] = 1; break;
	    case MOUNT_TFS: fsys_type_id[fsys_type_len-1] = 15; break;
	    }
#else
	    mnt_type = HRFS_entry->HRFS_type;
	    if ( mnt_type == NULL )
			fsys_type_id[fsys_type_len-1] = 2;	/* unknown */
#ifdef MNTTYPE_HFS
	    else if (!strcmp( mnt_type, MNTTYPE_HFS))
#ifdef BerkelyFS
			fsys_type_id[fsys_type_len-1] = 3;
#else /* SysV */
			fsys_type_id[fsys_type_len-1] = 4;
#endif
#endif
#ifdef MNTTYPE_UFS
	    else if (!strcmp( mnt_type, MNTTYPE_UFS))
			fsys_type_id[fsys_type_len-1] = 4;	/* or 3? XXX */
#endif
#ifdef MNTTYPE_SYSV
	    else if (!strcmp( mnt_type, MNTTYPE_SYSV))
			fsys_type_id[fsys_type_len-1] = 4;
#endif
#ifdef MNTTYPE_PC
	    else if (!strcmp( mnt_type, MNTTYPE_PC))
			fsys_type_id[fsys_type_len-1] = 5;
#endif
#ifdef MNTTYPE_MSDOS
	    else if (!strcmp( mnt_type, MNTTYPE_MSDOS))
			fsys_type_id[fsys_type_len-1] = 5;
#endif
#ifdef MNTTYPE_CDFS
	    else if (!strcmp( mnt_type, MNTTYPE_CDFS))
#ifdef RockRidge
			fsys_type_id[fsys_type_len-1] = 13;
#else /* ISO 9660 */
			fsys_type_id[fsys_type_len-1] = 12;
#endif
#endif
#ifdef MNTTYPE_ISO9660
	    else if (!strcmp( mnt_type, MNTTYPE_ISO9660))
			fsys_type_id[fsys_type_len-1] = 12;
#endif
#ifdef MNTTYPE_NFS
	    else if (!strcmp( mnt_type, MNTTYPE_NFS))
			fsys_type_id[fsys_type_len-1] = 14;
#endif
#ifdef MNTTYPE_NFS3
	    else if (!strcmp( mnt_type, MNTTYPE_NFS3))
			fsys_type_id[fsys_type_len-1] = 14;
#endif
	    else
			fsys_type_id[fsys_type_len-1] = 1;	/* Other */
#endif /* HAVE_GETFSSTAT */

            *var_len = sizeof(fsys_type_id);
	    return (u_char *)fsys_type_id;

	case HRFSYS_ACCESS:
#if HAVE_GETFSSTAT
	    long_return = HRFS_entry->f_flags & MNT_RDONLY ? 2 : 1;
#else
	    if ( hasmntopt( HRFS_entry, "ro" ) != NULL )
	        long_return = 2;	/* Read Only */
	    else
	        long_return = 1;	/* Read-Write */
#endif
	    return (u_char *)&long_return;
	case HRFSYS_BOOT:
          if (
		    HRFS_entry->HRFS_mount[0] == '/' &&
		    HRFS_entry->HRFS_mount[1] == 0
            )
              long_return = 1;		/* root is probably bootable! */
	    else
		long_return = 2;		/* others probably aren't */
	    return (u_char *)&long_return;
	case HRFSYS_STOREIDX:
	    long_return = fsys_idx;		/* Use the same indices */
	    return (u_char *)&long_return;
	case HRFSYS_FULLDUMP:
	    return when_dumped( HRFS_entry->HRFS_name, FULL_DUMP, var_len );
	case HRFSYS_PARTDUMP:
	    return when_dumped( HRFS_entry->HRFS_name, PART_DUMP, var_len );
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

static int HRFS_index;
#ifndef HAVE_GETFSSTAT
static FILE *fp;
#endif

void
Init_HR_FileSys __P((void))
{
#if HAVE_GETFSSTAT
    fscount = getfsstat(NULL, 0, MNT_NOWAIT);
    fsstats = malloc(fscount*sizeof(*fsstats));
    HRFS_index = getfsstat(fsstats, fscount*sizeof(*fsstats), MNT_NOWAIT);
    HRFS_index = 0;
#else
   HRFS_index = 1;
   if ( fp != NULL )
	fclose(fp);
   fp = fopen( ETC_MNTTAB, "r");
#endif
}

char *HRFS_ignores[] = {
#ifdef MNTTYPE_IGNORE
	MNTTYPE_IGNORE,
#endif
#ifdef MNTTYPE_SWAP
	MNTTYPE_SWAP,
#endif
#ifdef MNTTYPE_PROC
	MNTTYPE_PROC,
#endif
	"autofs",
	0
};

int
Get_Next_HR_FileSys __P((void))
{
#if HAVE_GETFSSTAT
    if (HRFS_index >= fscount) return -1;
    HRFS_entry = fsstats+HRFS_index;
    return HRFS_index++;
#else
    char **cpp;
		/*
		 * XXX - According to RFC 1514, hrFSIndex must
		 *   "remain constant at least from one re-initialization
		 *    of the agent to the next re-initialization."
		 *
		 *  This simple-minded counter doesn't handle filesystems
		 *    being un-mounted and re-mounted.
		 *  Options for fixing this include:
		 *       - keeping a history of previous indices used
		 *       - calculating the index from filesystem
		 *		specific information
		 *
		 *  Note: this index is also used as hrStorageIndex
		 *     which is assumed to be less than HRS_TYPE_FS_MAX
		 *     This assumption may well be broken if the second
		 *     option above is followed.  Consider indexing the
		 *     non-filesystem-based storage entries first in this
		 *     case, and assume hrStorageIndex > HRS_TYPE_FS_MIN
		 *     (for file-system based storage entries)
		 *
		 *  But at least this gets us started.
		 */

    if ( fp == NULL )
	return -1;

#ifdef solaris2
    if (getmntent( fp, HRFS_entry) != 0)
	return -1;
#else
    HRFS_entry = getmntent( fp );
    if ( HRFS_entry == NULL )
	return -1;
#endif /* solaris2 */

    for ( cpp = HRFS_ignores ; *cpp != NULL ; ++cpp )
	if ( !strcmp( HRFS_entry->HRFS_type, *cpp ))
	    return Get_Next_HR_FileSys();

    return HRFS_index++;
#endif /* HAVE_GETFSSTAT */
}

void
End_HR_FileSys __P((void))
{
#ifdef HAVE_GETFSSTAT
    free(fsstats);
    fsstats = NULL;
#else
    if ( fp != NULL )
	fclose(fp);
#endif
}


static u_char *
when_dumped( filesys, level, length )
    char *filesys;
    int   level;
    int  *length;
{
    time_t dumpdate = 0, tmp;
    FILE *dump_fp;
    char line[100];
    char *cp1, *cp2, *cp3;

		/*
		 * Look for the relevent entries in /etc/dumpdates
		 *
		 * This is complicated by the fact that disks are
		 *   mounted using block devices, but dumps are
		 *   done via the raw character devices.
		 * Thus the device names in /etc/dumpdates and
		 *   /etc/mnttab don't match.
		 *   These comparisons are therefore made using the
		 *   final portion of the device name only.
		 */

    cp1=strrchr( filesys, '/' );	/* Find the last element of the current FS */

    if ((dump_fp = fopen("/etc/dumpdates", "r")) == NULL )
	return date_n_time (NULL, length);

    while ( fgets( line, 100, dump_fp ) != NULL ) {
        cp2=strchr( line, ' ' );	/* Start by looking at the device name only */
	if ( cp2!=NULL ) {
	    *cp2 = '\0';
	    cp3=strrchr( line, '/' );  /* and find the last element */

	    if ( strcmp( cp1, cp3 ) != 0 )	/* Wrong FS */
		continue;

	    ++cp2;
	    while (isspace(*cp2))
		++cp2;			/* Now find the dump level */

	    if ( level == FULL_DUMP ) {
		if ( *(cp2++) != '0' )
		    continue;		/* Not interested in partial dumps */
		while (isspace(*cp2))
		    ++cp2;

		dumpdate = ctime_to_timet( cp2 );
		fclose( dump_fp );
		return date_n_time (&dumpdate, length);
	    }
	    else {	/* Partial Dump */
		if ( *(cp2++) == '0' )
		    continue;		/* Not interested in full dumps */
		while (isspace(*cp2))
		    ++cp2;

		tmp = ctime_to_timet( cp2 );
		if ( tmp > dumpdate )
		    dumpdate=tmp;	/* Remember the 'latest' partial dump */
	    }
	}
    }

    fclose(dump_fp);

    return date_n_time (&dumpdate, length);
}


#define RAW_DEVICE_PREFIX	"/dev/rdsk"
#define COOKED_DEVICE_PREFIX	"/dev/dsk"

char *
cook_device( dev )
    char *dev;
{
    static char cooked_dev[MAXPATHLEN];

    if ( !strncmp( dev, RAW_DEVICE_PREFIX, strlen(RAW_DEVICE_PREFIX))) {
	strcpy( cooked_dev, COOKED_DEVICE_PREFIX );
	strcat( cooked_dev, dev+strlen(RAW_DEVICE_PREFIX) );
    }
    else
	strcpy( cooked_dev, dev );

    return( cooked_dev );
}


int
Get_FSIndex( dev )
    char *dev;
{
    int index;

    Init_HR_FileSys();

    while ((index=Get_Next_HR_FileSys()) != -1 )
	if (!strcmp( HRFS_entry->HRFS_name,  cook_device(dev)))
	{
	    End_HR_FileSys();
	    return index;
	}

    End_HR_FileSys();
    return -1;
}

int
Get_FSSize( dev )
    char *dev;
{
    struct HRFS_statfs statfs_buf;

    Init_HR_FileSys();

    while (Get_Next_HR_FileSys() != -1 )
	if (!strcmp( HRFS_entry->HRFS_name,  cook_device(dev)))
	{
	    End_HR_FileSys();

	    if (HRFS_statfs( HRFS_entry->HRFS_mount, &statfs_buf) != -1 )
	        return (statfs_buf.f_blocks*statfs_buf.f_bsize)/1024;
	    else
		return -1;
	}

    End_HR_FileSys();
    return -1;
}
