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

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
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
#else
struct mntent *HRFS_entry;
#endif

#define	FULL_DUMP	0
#define	PART_DUMP	1

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

extern void  Init_HR_FileSys();
extern int   Get_Next_HR_FileSys();
static u_char * when_dumped __P(( char* filesys, int level, int* length ));

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
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
#define HRFSYS_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int fsys_idx, LowIndex=-1;
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_hrfilesys: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
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
    printf ("... get filesys stats %s\n", c_oid);
#endif
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
    int     (**write_method)();
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
#ifdef solaris2
	    sprintf(string, HRFS_entry->mnt_mountp);
#else
	    sprintf(string, HRFS_entry->mnt_dir);
#endif
	    *var_len = strlen(string);
	    return (u_char *) string;
	case HRFSYS_RMOUNT:
#ifdef solaris2
	    if (!strcmp( HRFS_entry->mnt_fstype, MNTTYPE_NFS))
	        sprintf(string, HRFS_entry->mnt_special);
#else
	    if (!strcmp( HRFS_entry->mnt_type, MNTTYPE_NFS))
	        sprintf(string, HRFS_entry->mnt_fsname);
#endif
	    else
		string[0] = '\0';
	    *var_len = strlen(string);
	    return (u_char *) string;

	case HRFSYS_TYPE:
			/*
			 * Not sufficient to identity the file
			 *   type precisely, but it's a start.
			 */
#ifdef solaris2
	    mnt_type = HRFS_entry->mnt_fstype;
#else
	    mnt_type = HRFS_entry->mnt_type;
#endif
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

            *var_len = sizeof(fsys_type_id);
	    return (u_char *)&fsys_type_id;

	case HRFSYS_ACCESS:
	    if ( hasmntopt( HRFS_entry, "ro" ) != NULL )
	        long_return = 2;	/* Read Only */
	    else
	        long_return = 1;	/* Read-Write */
	    return (u_char *)&long_return;
	case HRFSYS_BOOT:
	    if ( HRFS_entry->mnt_dir[0] == '/' && HRFS_entry->mnt_dir[1] == 0  )
		long_return = 1;		/* root is probably bootable! */
	    else
		long_return = 2;		/* others probably aren't */
	    return (u_char *)&long_return;
	case HRFSYS_STOREIDX:
	    long_return = fsys_idx;		/* Use the same indices */
	    return (u_char *)&long_return;
	case HRFSYS_FULLDUMP:
#ifdef solaris2
	    return when_dumped( HRFS_entry->mnt_special, FULL_DUMP, var_len );
#else
	    return when_dumped( HRFS_entry->mnt_fsname, FULL_DUMP, var_len );
#endif
	case HRFSYS_PARTDUMP:
#ifdef solaris2
	    return when_dumped( HRFS_entry->mnt_special, PART_DUMP, var_len );
#else
	    return when_dumped( HRFS_entry->mnt_fsname, PART_DUMP, var_len );
#endif
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
static FILE *fp;

void
Init_HR_FileSys()
{
   HRFS_index = 1;
   if ( fp != NULL )
	fclose(fp);
   fp = fopen( ETC_MNTTAB, "r");
}

int
Get_Next_HR_FileSys()
{
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
    getmntent( fp, HRFS_entry);
#else
    HRFS_entry = getmntent( fp );
#endif

    if ( HRFS_entry == NULL )
	return -1;
    
#ifdef MNTTYPE_IGNORES
    if (!strcmp( HRFS_entry->mnt_type, MNTTYPE_IGNORE))
	return Get_Next_HR_FileSys();
#endif

#ifdef linux
    if (!strcmp( HRFS_entry->mnt_type, MNTTYPE_PROC) ||
        !strcmp( HRFS_entry->mnt_type, MNTTYPE_SWAP))
	return Get_Next_HR_FileSys();
#endif

    return HRFS_index++;
}

void
End_HR_FileSys()
{
   if ( fp != NULL )
	fclose(fp);
}


u_char *
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


int
Get_FSIndex( dev )
    char *dev;
{
    int index;

    Init_HR_FileSys();

    while ((index=Get_Next_HR_FileSys()) != -1 )
#ifdef solaris2
	if (!strcmp( HRFS_entry->mnt_special, dev))
#else
	if (!strcmp( HRFS_entry->mnt_fsname, dev))
#endif
	{
	    End_HR_FileSys();
	    return index;
	}

    End_HR_FileSys();
    return -1;
}

		/*
		 *  This is used by hrPartitionSize
		 *    due to the assumption that each
		 *    disk is a signle partition
		 */
int
Get_FSSize( dev )
    char *dev;
{
#ifdef solaris2
    struct statvfs statfs_buf;
#else
    struct statfs statfs_buf;
#endif

    Init_HR_FileSys();

    while (Get_Next_HR_FileSys() != -1 )
#ifdef solaris2
	if (!strcmp( HRFS_entry->mnt_special, dev))
#else
	if (!strcmp( HRFS_entry->mnt_fsname, dev))
#endif
	{
	    End_HR_FileSys();

#ifdef solaris2
	    if (statvfs( HRFS_entry->mnt_mountp, &statfs_buf) != -1 )
#else
	    if (statfs( HRFS_entry->mnt_dir, &statfs_buf) != -1 )
#endif
	        return (statfs_buf.f_blocks*statfs_buf.f_bsize)/1024;
	    else
		return -1;
	}

    End_HR_FileSys();
    return -1;
}
