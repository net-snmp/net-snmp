/*
 *  Host Resources MIB - disk device group implementation - hr_disk.c
 *
 */

#include <config.h>

#include "host_res.h"
#include "hr_disk.h"

#include <fcntl.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
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
#if HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#if HAVE_SYS_DKIO_H
#include <sys/dkio.h>
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

void  Init_HR_Disk __P((void));
int   Get_Next_HR_Disk __P((void));
void  Save_HR_Disk_General __P((void));
void  Save_HR_Disk_Specific __P((void));
int   Query_Disk __P((int));
char *describe_disk __P((int));
int header_hrdisk __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));
void Add_HR_Disk_entry __P(( char*, char, char, char, char, char));


       int HRD_type_index;
       int HRD_index;
static char HRD_savedModel[40];
static long HRD_savedCapacity = 1044;
static int  HRD_savedFlags;
     time_t HRD_history[HRDEV_TYPE_MASK];

#ifdef HAVE_SYS_DISKIO_H
static disk_describe_type HRD_info;
static capacity_type      HRD_cap;

static int  HRD_savedIntf_type;
static int  HRD_savedDev_type;
#endif

#ifdef HAVE_SYS_DKIO_H
static struct dk_cinfo    HRD_info;
static struct dk_geom     HRD_cap;

static int  HRD_savedCtrl_type;
#endif

#ifdef HAVE_LINUX_HDREG_H
static struct hd_driveid HRD_info;
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/


void	init_hr_disk( )
{
    int i;

    init_device[ HRDEV_DISK ] = &Init_HR_Disk;	
    next_device[ HRDEV_DISK ] = &Get_Next_HR_Disk;
    save_device[ HRDEV_DISK ] = &Save_HR_Disk_General;	
#ifdef HRD_MONOTONICALLY_INCREASING
    dev_idx_inc[ HRDEV_DISK ] = 1;
#endif

#ifdef linux
    Add_HR_Disk_entry ( "/dev/hd%c%c", 'a', 'd', '\0', '1', '6' );
    Add_HR_Disk_entry ( "/dev/sd%c%c", 'a', 'g', '\0', '1', '6' );
    Add_HR_Disk_entry ( "/dev/fd%c%c", '0', '0', '\0', '\0', '\0' );
#endif
#ifdef hpux
#ifdef hpux10
    Add_HR_Disk_entry ( "/dev/rdsk/c0t%cd%c", '0', '6', '0', '0', '4' );
#else
    Add_HR_Disk_entry ( "/dev/rdsk/c201d%cs%c", '0', '6', '0', '0', '4' );
#endif
#endif
#ifdef solaris
    Add_HR_Disk_entry ( "/dev/rdsk/c0t%cd0s%c", '0', '6', '0', '0', '7' );
#endif

    device_descr[ HRDEV_DISK ] = &describe_disk;	
    HRD_savedModel[0] = '\0';
    HRD_savedCapacity = 0;

    for ( i=0 ; i<HRDEV_TYPE_MASK ; ++i )
	HRD_history[i] = 0;
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
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRDISK_ENTRY_NAME_LENGTH	11
    oid newname[MAX_NAME_LEN];
    int disk_idx, LowIndex = -1;
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP("var_hrdisk: %s %d\n", c_oid, exact);
    }
    
    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
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
	    Save_HR_Disk_Specific();
            break;
	}
	if ((!exact && (result < 0)) &&
		( LowIndex == -1 ||  disk_idx < LowIndex )) {
	    LowIndex = disk_idx;
	    Save_HR_Disk_Specific();
#ifdef HRD_MONOTONICALLY_INCREASING
	    break;
#endif
        }
    }

    if ( LowIndex == -1 ) {
      DEBUGP("... index out of range\n");
      return(MATCH_FAILED);
    }

    newname[HRDISK_ENTRY_NAME_LENGTH] = LowIndex;
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP("... get disk stats %s\n", c_oid);
    }
    
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
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
    int  disk_idx;

    disk_idx = header_hrdisk(vp, name, length, exact, var_len, write_method);
    if ( disk_idx == MATCH_FAILED )
	return NULL;
        

    switch (vp->magic){
	case HRDISK_ACCESS:
	    long_return = Is_It_Writeable();
	    return (u_char *)&long_return;
	case HRDISK_MEDIA:
	    long_return = What_Type_Disk();
	    return (u_char *)&long_return;
	case HRDISK_REMOVEABLE:
	    long_return = Is_It_Removeable();
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

#define MAX_NUMBER_DISK_TYPES	10	/* probably should be a variable */
#define MAX_DISKS_PER_TYPE	7	/* SCSI disks - not a hard limit */
#define	HRDISK_TYPE_SHIFT	3	/* log2 MAX_DISKS_PER_TYPE+1 */

char *disk_device_strings[ MAX_NUMBER_DISK_TYPES ];
char disk_device_id[   MAX_NUMBER_DISK_TYPES ];
char disk_device_last[ MAX_NUMBER_DISK_TYPES ];
char disk_device_full[ MAX_NUMBER_DISK_TYPES ];
char disk_partition_first[   MAX_NUMBER_DISK_TYPES ];
char disk_partition_last[    MAX_NUMBER_DISK_TYPES ];
int HR_number_disk_types = 0;


void
Add_HR_Disk_entry ( dev_string, first_dev, last_dev, full_dev, first_partn, last_partn)
    char *dev_string;
    char first_dev, last_dev;
    char full_dev;
    char first_partn, last_partn;
{
    disk_device_strings[ HR_number_disk_types ] = dev_string;
    disk_device_id[      HR_number_disk_types ] = first_dev;
    disk_device_last[    HR_number_disk_types ] = last_dev;
    disk_device_full[    HR_number_disk_types ] = full_dev;
    disk_partition_first[HR_number_disk_types ] = first_partn;
    disk_partition_last[ HR_number_disk_types ] = last_partn;

		/*
		 * Split long runs of disks into separate "types"
		 */
    while ( last_dev - first_dev > MAX_DISKS_PER_TYPE ) {
	first_dev = first_dev+MAX_DISKS_PER_TYPE;
	disk_device_last[HR_number_disk_types] = first_dev-1;
	HR_number_disk_types++;

	disk_device_strings[ HR_number_disk_types ] = dev_string;
	disk_device_id[      HR_number_disk_types ] = first_dev;
	disk_device_last[    HR_number_disk_types ] = last_dev;
	disk_device_full[    HR_number_disk_types ] = full_dev;
	disk_partition_first[HR_number_disk_types ] = first_partn;
	disk_partition_last[ HR_number_disk_types ] = last_partn;
    }

    HR_number_disk_types++;
}
  

void
Init_HR_Disk __P((void))
{
    HRD_type_index = 0;
    HRD_index = -1;
}

int
Get_Next_HR_Disk __P((void))
{
    char string[100];
    int fd, result;
    int index;
    int max_disks;
    time_t now;

    HRD_index++;
    (void*) time( &now );
    while ( HRD_type_index < HR_number_disk_types ) {
	max_disks = disk_device_last[    HRD_type_index ] -
		    disk_device_id[      HRD_type_index ] +1;

	while ( HRD_index < max_disks ) {
	    index = (HRD_type_index << HRDISK_TYPE_SHIFT) + HRD_index;

			/*
			 * Check to see whether this device
			 *   has been probed for 'recently'
			 *   and skip if so.
			 * This has a *major* impact on run
			 *   times (by a factor of 10!)
			 */
	    if (( HRD_history[ index ] != 0 ) &&
		(( now - HRD_history[ index ]) < 60 ))
	    {
			HRD_index++;
			continue;
	    }

		/* Construct the device name in "string" */
	    sprintf(string, disk_device_strings[ HRD_type_index ], 
			    disk_device_id[      HRD_type_index ] + HRD_index,
			    disk_device_full[    HRD_type_index ] );

	    DEBUGP("Get_Next_HR_Disk: %s (%d/%d)\n",
		string, HRD_type_index, HRD_index );
	
	    fd = open( string, O_RDONLY  );
	    if (fd != -1 ) {
		result = Query_Disk( fd );
		close(fd);
		if ( result != -1 ) {
		    HRD_history[ index ] = 0;
		    return ((HRDEV_DISK << HRDEV_TYPE_SHIFT) + index );
		}
	    }
	    HRD_history[ index ] = now;
	    HRD_index++;
	}
	HRD_type_index++;
	HRD_index = 0;
    }
    HRD_index = -1;
    return -1;
}

void
Save_HR_Disk_Specific __P((void))
{
#ifdef HAVE_SYS_DISKIO_H
	    HRD_savedIntf_type = HRD_info.intf_type; 
	    HRD_savedDev_type  = HRD_info.dev_type;
	    HRD_savedFlags     = HRD_info.flags;
	    HRD_savedCapacity  = HRD_cap.lba;
#endif
#ifdef HAVE_SYS_DKIO_H
	    HRD_savedCtrl_type = HRD_info.dki_ctype;
	    HRD_savedFlags     = HRD_info.dki_flags;
	    HRD_savedCapacity  = HRD_cap.dkg_ncyl*
				 HRD_cap.dkg_nhead*
				 HRD_cap.dkg_nsect; /* ??? */
#endif
#ifdef HAVE_LINUX_HDREG_H
	    HRD_savedCapacity  = HRD_info.lba_capacity / 2 ;
	    HRD_savedFlags     = HRD_info.config;
#endif
}

void
Save_HR_Disk_General __P((void))
{
#ifdef HAVE_SYS_DISKIO_H
    strcpy( HRD_savedModel,  HRD_info.model_num );   
#endif
#ifdef HAVE_SYS_DKIO_H
    strcpy( HRD_savedModel,  HRD_info.dki_dname );   
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


int
Query_Disk( fd )
    int fd;
{
    int result = -1;

#ifdef HAVE_SYS_DISKIO_H
    result = ioctl( fd, DIOC_DESCRIBE, &HRD_info );
    if ( result != -1 )
	result = ioctl( fd, DIOC_CAPACITY, &HRD_cap );
#endif

#ifdef HAVE_SYS_DKIO_H
    result = ioctl( fd, DKIOCINFO, &HRD_info );
    if ( result != -1 )
	result = ioctl( fd, DKIOCGGEOM, &HRD_cap );
#endif

#ifdef HAVE_LINUX_HDREG_H
    if ( HRD_type_index == 0 )		/* Hard disk only */
	result = ioctl( fd, HDIO_GET_IDENTITY, &HRD_info );
#endif

    return( result );
}


int
Is_It_Writeable()
{
#ifdef HAVE_SYS_DISKIO_H
    if (( HRD_savedFlags & WRITE_PROTECT_FLAG ) ||
	( HRD_savedDev_type == CDROM_DEV_TYPE ))
	return(2);	/* read only */
#endif

#ifdef HAVE_SYS_DKIO_H
    if ( HRD_savedCtrl_type == DKC_CDROM )
	return(2);	/* read only */
#endif

    return(1);		/* read-write */
}

int
What_Type_Disk()
{
#ifdef HAVE_SYS_DISKIO_H
    switch ( HRD_savedDev_type ) {
	case DISK_DEV_TYPE:
		if ( HRD_savedIntf_type == PC_FDC_INTF )
    		    return(4);	/* Floppy Disk */
		else
    		    return(3);	/* Hard Disk */
		break;
	case CDROM_DEV_TYPE:
    		return(5);	/* Optical RO */
		break;
	case WORM_DEV_TYPE:
    		return(6);	/* Optical WORM */
		break;
	case MO_DEV_TYPE:
    		return(7);	/* Optical R/W */
		break;
	default:
    		return(2);	/* Unknown */
		break;
    }
#endif

#ifdef HAVE_SYS_DKIO_H
    switch ( HRD_savedCtrl_type ) {
	case DKC_WDC2880:
	case DKC_DSD5215:
	case DKC_XY450:
	case DKC_ACB4000:
	case DKC_MD21:
	case DKC_XD7053:
	case DKC_SCSI_CCS:
	case DKC_PANTHER:
	case DKC_CDC_9057:
	case DKC_FJ_M1060:
	case DKC_DIRECT:
	case DKC_PCMCIA_ATA:
    		return(3);	/* Hard Disk */
		break;
	case DKC_NCRFLOPPY:
	case DKC_SMSFLOPPY:
	case DKC_INTEL82077:
    		return(4);	/* Floppy Disk */
		break;
	case DKC_CDROM:
    		return(5);	/* Optical RO */
		break;
	case DKC_PCMCIA_MEM:
    		return(8);	/* RAM disk */
		break;
	case DKC_MD:			/* "meta-disk" driver */
    		return(1);	/* Other */
		break;
    }
#endif


    return(2);			/* Unknown */
}

int
Is_It_Removeable()
{
#ifdef HAVE_SYS_DISKIO_H
    if (( HRD_savedIntf_type == PC_FDC_INTF   ) ||
	( HRD_savedDev_type  == WORM_DEV_TYPE ) ||
	( HRD_savedDev_type  == MO_DEV_TYPE   ) ||
	( HRD_savedDev_type  == CDROM_DEV_TYPE ))
	    return(1);		/* true */
#endif

#ifdef HAVE_SYS_DKIO_H
    if (( HRD_savedCtrl_type == DKC_CDROM      ) ||
	( HRD_savedCtrl_type == DKC_NCRFLOPPY  ) ||
	( HRD_savedCtrl_type == DKC_SMSFLOPPY  ) ||
	( HRD_savedCtrl_type == DKC_INTEL82077 ) ||
	( HRD_savedCtrl_type == DKC_PCMCIA_MEM ) ||
	( HRD_savedCtrl_type == DKC_PCMCIA_ATA ))
	    return(1);		/* true */
#endif

#ifdef HAVE_LINUX_HDREG_H
    if ( HRD_savedFlags & 0x80 )
	    return(1);		/* true */
#endif

    return(2);			/* false */
}
