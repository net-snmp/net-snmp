/*
 *  Host Resources MIB - disk device group implementation - hr_disk.c
 *
 */

#include <config.h>

#include "host_res.h"
#include "hr_disk.h"

#if HAVE_KVM_OPENFILES
#include <fcntl.h>
#if HAVE_KVM_H
#include <kvm.h>
#endif
#endif
#if HAVE_DIRENT_H
#include <dirent.h>
#else
# define dirent direct
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#if HAVE_SYS_DISKIO_H	/* HP-UX only ? */
#include <sys/diskio.h>
#endif

#define HRD_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

void  Init_HR_Disk();
int   Get_Next_HR_Disk();
void  Save_HR_Disk();
char *describe_disk();


       int HRD_index;
#ifdef HAVE_SYS_DISKIO_H
static disk_describe_type HRD_info;
static capacity_type      HRD_cap;

static char HRD_savedModel[16];
static int  HRD_savedIntf_type;
static int  HRD_savedDev_type;
static int  HRD_savedFlags;
static long HRD_savedCapacity;
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_hrdisk( )
{
    init_device[ HRDEV_DISK ] = &Init_HR_Disk;	
    next_device[ HRDEV_DISK ] = &Get_Next_HR_Disk;
    save_device[ HRDEV_DISK ] = &Save_HR_Disk;	
#ifdef HRD_MONOTONICALLY_INCREASING
    dev_idx_inc[ HRDEV_DISK ] = 1;
#endif

    device_descr[ HRDEV_DISK ] = &describe_disk;	
}

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

int
header_hrdisk(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method)(); /* OUT - pointer to function to set variable, otherwise 0 */
{
#define HRDISK_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int disk_idx, LowIndex = -1;
    int result;
#ifdef DODEBUG
    char c_oid[MAX_NAME_LEN];

    sprint_objid (c_oid, name, *length);
    printf ("var_hrdisk: %s %d\n", c_oid, exact);
#endif

    bcopy((char *)vp->name, (char *)newname, (int)vp->namelen * sizeof(oid));
	/* Find "next" disk entry */

    Init_HR_Disk();
    for ( ;; ) {
        disk_idx = Get_Next_HR_Disk();
        if ( disk_idx == -1 )
	    break;
	newname[HRDISK_ENTRY_NAME_LENGTH] = disk_idx;
        result = compare(name, *length, newname, (int)vp->namelen + 1);
        if (exact && (result == 0)) {
	    LowIndex = disk_idx;
#ifdef HAVE_SYS_DISKIO_H
	    HRD_savedIntf_type = HRD_info.intf_type; 
	    HRD_savedDev_type = HRD_info.dev_type;
	    HRD_savedFlags = HRD_info.flags;
	    HRD_savedCapacity = HRD_cap.lba;
#endif
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowIndex == -1 ||  disk_idx < LowIndex )) {
	    LowIndex = disk_idx;
#ifdef HAVE_SYS_DISKIO_H
	    HRD_savedIntf_type = HRD_info.intf_type; 
	    HRD_savedDev_type = HRD_info.dev_type;
	    HRD_savedFlags = HRD_info.flags;
	    HRD_savedCapacity = HRD_cap.lba;
#endif
#ifdef HRD_MONOTONICALLY_INCREASING
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

    newname[HRDISK_ENTRY_NAME_LENGTH] = LowIndex;
    bcopy((char *)newname, (char *)name, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

#ifdef DODEBUG
    sprint_objid (c_oid, name, *length);
    printf ("... get disk stats %s\n", c_oid);
#endif
    return LowIndex;
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrdisk(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method)();
{
    int  disk_idx;
    static char *string[100];

    disk_idx = header_hrdisk(vp, name, length, exact, var_len, write_method);
    if ( disk_idx == MATCH_FAILED )
	return NULL;
        

    switch (vp->magic){
	case HRDISK_ACCESS:
#ifdef HAVE_SYS_DISKIO_H
	    if ( HRD_savedFlags & WRITE_PROTECT_FLAG )
		long_return = 2;	/* read only */
	    else
#endif
		long_return = 1;	/* read-write */
	    return (u_char *)&long_return;
	case HRDISK_MEDIA:
#ifdef HAVE_SYS_DISKIO_H
	    switch ( HRD_savedDev_type ) {
		case DISK_DEV_TYPE:
			if ( HRD_savedIntf_type == PC_FDC_INTF )
	    		    long_return = 4;	/* Floppy Disk */
			else
	    		    long_return = 3;	/* Hard Disk */
			break;
		case CDROM_DEV_TYPE:
	    		long_return = 5;	/* Optical RO */
			break;
		case WORM_DEV_TYPE:
	    		long_return = 6;	/* Optical WORM */
			break;
		case MO_DEV_TYPE:
	    		long_return = 7;	/* Optical R/W */
			break;
		default:
	    		long_return = 2;	/* Unknown */
			break;
	    }
#else
	    long_return = 2;	/* Unknown */
#endif
	    return (u_char *)&long_return;
	case HRDISK_REMOVEABLE:
#ifdef HAVE_SYS_DISKIO_H
	    if (( HRD_savedIntf_type == PC_FDC_INTF   ) ||
		( HRD_savedDev_type  == WORM_DEV_TYPE ) ||
		( HRD_savedDev_type  == MO_DEV_TYPE   ) ||
		( HRD_savedDev_type  == CDROM_DEV_TYPE ))
		    long_return = 1;	/* true */
	    else
#endif
		    long_return = 2;	/* false */
	    return (u_char *)&long_return;
	case HRDISK_CAPACITY:
#ifdef HAVE_SYS_DISKIO_H
	    long_return = HRD_savedCapacity;
#else
	    long_return = 1044;		/* XXX */
#endif
	    return (u_char *)&long_return;
	default:
	    ERROR("");
    }
    return NULL;
}


	/*********************
	 *
	 *  Internal implementation functions
	 *
	 *********************/


static DIR* dp;

void
Init_HR_Disk()
{
    HRD_index = -1;
    closedir(dp);
				/* Ick!
				 *   Not all disks will be under /dev/rdsk
				 *
				 *   We really need to walk through kernel
				 *    device structures, but the documentation
				 *    for that is abysmal (as in nonexistent)!
				 *
				 *   This is a start, but too slow to be useable
				 */
    dp = opendir("/dev/rdsk/");
}

int
Get_Next_HR_Disk()
{
    struct dirent *de_p;
    char string[100];
    int fd, result;

#ifdef HAVE_SYS_DISKIO_H	/* and dodgy even then! */
#ifdef DTS_ABYSMALLY_SLOW
    while (( de_p = readdir( dp )) != NULL ) {
	if ( de_p->d_name[0] == '.' )
	    continue;
	sprintf(string, "/dev/rdsk/%s", de_p->d_name);
#else
			/*
			 * I know this is unacceptable site-specific,
			 *    but scanning the whole directory was soooo
			 *    slow, that the agent simply couldn't keep up!
			 *
			 * Regard this as a 'prooof of concept' (with the
			 *    emphasis on "concept" rather than "proof"!)
			 */
    while ( ++HRD_index < 7 ) {
	sprintf(string, "/dev/rdsk/%s%d%s", "c201d", HRD_index, "s0");
#endif /* SLOW! */

	fd = open( string, O_RDONLY  );

	if (fd != -1 ) {
	    result = ioctl( fd, DIOC_DESCRIBE, &HRD_info );
	    if ( result != -1 )
	        result = ioctl( fd, DIOC_CAPACITY, &HRD_cap );
	    close(fd);
	    if ( result != -1 ) {
		return ((HRDEV_DISK << HRDEV_TYPE_SHIFT) + HRD_index );
	    }
	}
    }
#else	/* !HAVE_SYS_DISKIO_H */
    while ( ++HRD_index < 7 ) {
	return ((HRDEV_DISK << HRDEV_TYPE_SHIFT) + HRD_index );
    }
#endif
    closedir(dp);
    return -1;
}

void
Save_HR_Disk( idx )
   int idx;
{
#ifdef HAVE_SYS_DISKIO_H
    strcpy( HRD_savedModel,  HRD_info.model_num );   
#endif
}

char *
describe_disk( idx )
    int idx;
{
#ifdef HAVE_SYS_DISKIO_H
    return( HRD_savedModel );
#else
   return( "some sort of disk");
#endif
}
