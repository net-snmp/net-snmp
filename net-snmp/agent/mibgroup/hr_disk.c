/*
 *  Host Resources MIB - disk device group implementation - hr_disk.c
 *
 */

#include <config.h>

#include "host_res.h"
#include "hr_disk.h"

#include <fcntl.h>
#if HAVE_KVM_H
#include <kvm.h>
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
#ifdef HAVE_LINUX_HDREG_H
#include <linux/hdreg.h>
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


       int HRD_type_index;
       int HRD_index;
static char HRD_savedModel[40];
static long HRD_savedCapacity = 1044;
static int  HRD_savedFlags;

#ifdef HAVE_SYS_DISKIO_H
static disk_describe_type HRD_info;
static capacity_type      HRD_cap;

static int  HRD_savedIntf_type;
static int  HRD_savedDev_type;
#endif

#ifdef HAVE_LINUX_HDREG_H
static struct hd_driveid HRD_info;

static long HRD_savedCapacity;
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_hr_disk( )
{
    init_device[ HRDEV_DISK ] = &Init_HR_Disk;	
    next_device[ HRDEV_DISK ] = &Get_Next_HR_Disk;
    save_device[ HRDEV_DISK ] = &Save_HR_Disk;	
#ifdef HRD_MONOTONICALLY_INCREASING
    dev_idx_inc[ HRDEV_DISK ] = 1;
#endif

    device_descr[ HRDEV_DISK ] = &describe_disk;	
    HRD_savedModel[0] = '\0';
    HRD_savedCapacity = 0;
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
#ifdef HAVE_LINUX_HDREG_H
	    HRD_savedCapacity = HRD_info.lba_capacity / 2 ;
	    HRD_savedFlags = HRD_info.config;
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
#ifdef HAVE_LINUX_HDREG_H
	    HRD_savedCapacity = HRD_info.lba_capacity / 2 ;
	    HRD_savedFlags = HRD_info.config;
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
#else
#ifdef HAVE_LINUX_HDREG_H
	    if ( HRD_savedFlags & 0x80 )
		    long_return = 1;	/* true */
	    else
#endif
#endif
		    long_return = 2;	/* false */
	    return (u_char *)&long_return;
	case HRDISK_CAPACITY:
	    long_return = HRD_savedCapacity;
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


#ifdef linux
			/* To hold sprintf-style strings for disk devices */ 
char *disk_device_strings[ ] =
    {
	"/dev/hd%c",		/* IDE    drives */
	"/dev/sd%c",		/* SCSI   drives */
	"/dev/fd%c"		/* Floppy drives */
    };
#define NUMBER_DISK_TYPES	3
#define MAX_DISKS_PER_TYPE	7	/* SCSI disks */
#define	HRDISK_TYPE_SHIFT	3	/* log2 MAX_DISKS_PER_TYPE+1 */

    char disk_device_id[ ] =
	{ 'a', 'a', '0' };		/* Initial setting for the incremental part */
#else
#ifdef hpux
			/* To hold sprintf-style strings for disk devices */ 
char *disk_device_strings[ ] =
    {
	"/dev/rdsk/c201d%ds0"		/* SCSI   drives */
    };
#define NUMBER_DISK_TYPES	1
#define MAX_DISKS_PER_TYPE	7
#define	HRDISK_TYPE_SHIFT	3	/* log2 MAX_DISKS_PER_TYPE+1 */
    int  disk_device_id[ ] =
	{ 0 };				/* Initial setting for the incremental part */
#else
			/* To hold sprintf-style strings for disk devices */ 
char *disk_device_strings[ ] =
    {
	NULL
    }
#define NUMBER_DISK_TYPES	0
#define MAX_DISKS_PER_TYPE	7
#define	HRDISK_TYPE_SHIFT	3	/* log2 MAX_DISKS_PER_TYPE+1 */

    int  disk_device_id[ ] =
	{ 0 };

#endif
#endif

  

void
Init_HR_Disk()
{
    HRD_type_index = 0;
    HRD_index = 0;
}

int
Get_Next_HR_Disk()
{
    char string[100];
    int fd, result;

    while ( HRD_type_index < NUMBER_DISK_TYPES ) {

	while ( HRD_index < MAX_DISKS_PER_TYPE ) {
		/* Construct the device name in "string" */
	    sprintf(string, disk_device_strings[ HRD_type_index ], 
			    disk_device_id[ HRD_type_index ] + HRD_index );

#ifdef DODEBUG
	    printf ("Get_Next_HR_Disk: %s (%d/%d)\n",
		string, HRD_type_index, HRD_index );
#endif
	
#ifdef HAVE_SYS_DISKIO_H
	    fd = open( string, O_RDONLY  );
	    if (fd != -1 ) {
		result = ioctl( fd, DIOC_DESCRIBE, &HRD_info );
		if ( result != -1 )
	            result = ioctl( fd, DIOC_CAPACITY, &HRD_cap );
		close(fd);
		if ( result != -1 ) {
		    return ((HRDEV_DISK << HRDEV_TYPE_SHIFT) +
			    (HRD_type_index << HRDISK_TYPE_SHIFT ) +
			     HRD_index++ );
		}
	    }
#else

#ifdef linux
			/*
			 *  On my linux box, attempting to open the
			 *   (nonexistant) device /dev/fd1 results in
			 *   a significant pause, followed by a series
			 *   of kernel error messages.
			 *  Hardwire an assumption of one floppy disk
			 */
	    if ( HRD_type_index == 2 && HRD_index > 0 )
		break;
#endif  /* linux floppy */
	    fd = open( string, O_RDONLY  );
	    if (fd != -1 ) {
#ifdef linux
	    	    if ( HRD_type_index == 0 )
			result = ioctl( fd, HDIO_GET_IDENTITY, &HRD_info );
		    else
#else
		        result = 0;
#endif
		    close(fd);
		    if ( result != -1 ) {
		        return ((HRDEV_DISK << HRDEV_TYPE_SHIFT) +
			    (HRD_type_index << HRDISK_TYPE_SHIFT ) +
			     HRD_index++ );
		   }
	    }
#endif  /* SYS_DISKIO */

	    HRD_index++;
	}
	HRD_type_index++;
	HRD_index = 0;
    }
    return -1;
}

void
Save_HR_Disk( idx )
   int idx;
{
#ifdef HAVE_SYS_DISKIO_H
    strcpy( HRD_savedModel,  HRD_info.model_num );   
#endif
#ifdef HAVE_LINUX_HDREG_H
    strcpy( HRD_savedModel,  HRD_info.model );   
#endif
}

char *
describe_disk( idx )
    int idx;
{
    if ( HRD_savedModel[0] == '\0' )
	return( "some sort of disk");
    else
	return( HRD_savedModel );
}
