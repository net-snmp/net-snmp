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
#if HAVE_LINUX_HDREG_H
#include <linux/hdreg.h>
#endif
#if HAVE_SYS_DISKLABEL_H
#define DKTYPENAMES
#include <sys/disklabel.h>
#endif
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#define HRD_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

void  Init_HR_Disk (void);
int   Get_Next_HR_Disk (void);
void  Save_HR_Disk_General (void);
void  Save_HR_Disk_Specific (void);
int   Query_Disk (int);
int   Is_It_Writeable (void);
int   What_Type_Disk (void);
int   Is_It_Removeable (void);
const char *describe_disk (int);
int header_hrdisk (struct variable *,oid *, size_t *, int, size_t *, WriteMethod **);
void Add_HR_Disk_entry (const char *, char, char, char, char, char);

int HRD_type_index;
int HRD_index;
static char HRD_savedModel[40];
static long HRD_savedCapacity = 1044;
static int  HRD_savedFlags;
     time_t HRD_history[HRDEV_TYPE_MASK];

#ifdef DIOC_DESCRIBE
static disk_describe_type HRD_info;
static capacity_type      HRD_cap;

static int  HRD_savedIntf_type;
static int  HRD_savedDev_type;
#endif

#ifdef DKIOCINFO
static struct dk_cinfo    HRD_info;
static struct dk_geom     HRD_cap;

static int  HRD_savedCtrl_type;
#endif

#ifdef HAVE_LINUX_HDREG_H
static struct hd_driveid HRD_info;
#endif

#ifdef DIOCGDINFO
static struct disklabel HRD_info;
#endif

	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

#define	HRDISK_ACCESS		1
#define	HRDISK_MEDIA		2
#define	HRDISK_REMOVEABLE	3
#define	HRDISK_CAPACITY		4

struct variable4 hrdisk_variables[] = {
    { HRDISK_ACCESS,    ASN_INTEGER, RONLY, var_hrdisk, 2, {1,1}},
    { HRDISK_MEDIA,     ASN_INTEGER, RONLY, var_hrdisk, 2, {1,2}},
    { HRDISK_REMOVEABLE,ASN_INTEGER, RONLY, var_hrdisk, 2, {1,3}},
    { HRDISK_CAPACITY,  ASN_INTEGER, RONLY, var_hrdisk, 2, {1,4}}
};
oid hrdisk_variables_oid[] = { 1,3,6,1,2,1,25,3,6};


void init_hr_disk(void)
{
    int i;

    init_device[ HRDEV_DISK ] = Init_HR_Disk;	
    next_device[ HRDEV_DISK ] = Get_Next_HR_Disk;
    save_device[ HRDEV_DISK ] = Save_HR_Disk_General;	
#ifdef HRD_MONOTONICALLY_INCREASING
    dev_idx_inc[ HRDEV_DISK ] = 1;
#endif

#if defined(linux)
    Add_HR_Disk_entry ( "/dev/hd%c%c", 'a', 'd', '\0', '1', '6' );
    Add_HR_Disk_entry ( "/dev/sd%c%c", 'a', 'g', '\0', '1', '6' );
    Add_HR_Disk_entry ( "/dev/fd%c%c", '0', '0', '\0', '\0', '\0' );
#elif defined(hpux)
#ifdef hpux10
    Add_HR_Disk_entry ( "/dev/rdsk/c0t%cd%c", '0', '6', '0', '0', '4' );
#else
    Add_HR_Disk_entry ( "/dev/rdsk/c201d%cs%c", '0', '6', '0', '0', '4' );
#endif
#elif defined(solaris2)
    Add_HR_Disk_entry ( "/dev/rdsk/c0t%cd0s%c", '0', '6', '0', '0', '7' );
#elif defined(freebsd3)
    Add_HR_Disk_entry ("/dev/wd0s%c%c", '1', '4', '\0', 'a', 'h');
    Add_HR_Disk_entry ("/dev/wd1s%c%c", '1', '4', '\0', 'a', 'h');
    Add_HR_Disk_entry ("/dev/sd0s%c%c", '1', '4', '\0', 'a', 'h');
    Add_HR_Disk_entry ("/dev/sd1s%c%c", '1', '4', '\0', 'a', 'h');
#elif defined(freebsd2)
    Add_HR_Disk_entry ("/dev/wd%c%c", '0', '3', '\0', 'a', 'h');
    Add_HR_Disk_entry ("/dev/sd%c%c", '0', '3', '\0', 'a', 'h');
#elif defined(netbsd1)
    Add_HR_Disk_entry ("/dev/wd%c%c", '0', '3', 'c', 'a', 'h');
    Add_HR_Disk_entry ("/dev/sd%c%c", '0', '3', 'c', 'a', 'h');
#endif

    device_descr[ HRDEV_DISK ] = describe_disk;	
    HRD_savedModel[0] = '\0';
    HRD_savedCapacity = 0;

    for ( i=0 ; i<HRDEV_TYPE_MASK ; ++i )
	HRD_history[i] = 0;

    REGISTER_MIB("host/hr_disk", hrdisk_variables, variable4, hrdisk_variables_oid);
}

/*
  header_hrdisk(...
  Arguments:
  vp	  IN      - pointer to variable entry that points here
  name    IN/OUT  - IN/name requested, OUT/name found
  length  IN/OUT  - length of IN/OUT oid's 
  exact   IN      - TRUE if an exact match was requested
  var_len OUT     - length of variable or 0 if function returned
  write_method
*/

int
header_hrdisk(struct variable *vp,
	      oid *name,
	      size_t *length,
	      int exact,
	      size_t *var_len,
	      WriteMethod **write_method)
{
#define HRDISK_ENTRY_NAME_LENGTH	11
    oid newname[MAX_OID_LEN];
    int disk_idx, LowIndex = -1;
    int result;

    DEBUGMSGTL(("host/hr_disk", "var_hrdisk: "));
    DEBUGMSGOID(("host/hr_disk", name, *length));
    DEBUGMSG(("host/hr_disk"," %d\n", exact));
    
    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
	/* Find "next" disk entry */

    Init_HR_Disk();
    for ( ;; ) {
        disk_idx = Get_Next_HR_Disk();
        if ( disk_idx == -1 )
	    break;
	newname[HRDISK_ENTRY_NAME_LENGTH] = disk_idx;
        result = snmp_oid_compare(name, *length, newname, (int)vp->namelen + 1);
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
      DEBUGMSGTL(("host/hr_disk", "... index out of range\n"));
      return(MATCH_FAILED);
    }

    newname[HRDISK_ENTRY_NAME_LENGTH] = LowIndex;
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 1) * sizeof(oid));
    *length = vp->namelen + 1;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    DEBUGMSGTL(("host/hr_disk", "... get disk stats "));
    DEBUGMSGOID(("host/hr_disk", name, *length));
    DEBUGMSG(("host/hr_disk","\n"));
    
    return LowIndex;
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char *
var_hrdisk(struct variable *vp,
	   oid *name,
	   size_t *length,
	   int exact,
	   size_t *var_len,
	   WriteMethod **write_method)
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
	    DEBUGMSGTL(("snmpd", "unknown sub-id %d in var_hrdisk\n", vp->magic));
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

const char *disk_device_strings[ MAX_NUMBER_DISK_TYPES ];
char disk_device_id[   MAX_NUMBER_DISK_TYPES ];
char disk_device_last[ MAX_NUMBER_DISK_TYPES ];
char disk_device_full[ MAX_NUMBER_DISK_TYPES ];
char disk_partition_first[   MAX_NUMBER_DISK_TYPES ];
char disk_partition_last[    MAX_NUMBER_DISK_TYPES ];
int HR_number_disk_types = 0;


void
Add_HR_Disk_entry (const char *dev_string,
		   char first_dev, 
		   char last_dev,
		   char full_dev,
		   char first_partn, 
		   char last_partn)
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
Init_HR_Disk(void)
{
    HRD_type_index = 0;
    HRD_index = -1;
    DEBUGMSGTL(("host/hr_disk","Init_Disk\n"));
}

int
Get_Next_HR_Disk (void)
{
    char string[100];
    int fd, result;
    int iindex;
    int max_disks;
    time_t now;

    HRD_index++;
    (void*) time( &now );
    DEBUGMSGTL(("host/hr_disk","Next_Disk type %d of %d\n",
			 HRD_type_index, HR_number_disk_types));
    while ( HRD_type_index < HR_number_disk_types ) {
	max_disks = disk_device_last[    HRD_type_index ] -
		    disk_device_id[      HRD_type_index ] +1;
        DEBUGMSGTL(("host/hr_disk","Next_Disk max %d of type %d\n",
			 max_disks, HRD_type_index ));

	while ( HRD_index < max_disks ) {
	    iindex = (HRD_type_index << HRDISK_TYPE_SHIFT) + HRD_index;

			/*
			 * Check to see whether this device
			 *   has been probed for 'recently'
			 *   and skip if so.
			 * This has a *major* impact on run
			 *   times (by a factor of 10!)
			 */
	    if (( HRD_history[ iindex ] != 0 ) &&
		(( now - HRD_history[ iindex ]) < 60 ))
	    {
			HRD_index++;
			continue;
	    }

		/* Construct the device name in "string" */
	    sprintf(string, disk_device_strings[ HRD_type_index ], 
			    disk_device_id[      HRD_type_index ] + HRD_index,
			    disk_device_full[    HRD_type_index ] );

	    DEBUGMSGTL(("host/hr_disk", "Get_Next_HR_Disk: %s (%d/%d)\n",
                        string, HRD_type_index, HRD_index ));
	
	    fd = open( string, O_RDONLY  );
	    if (fd != -1 ) {
		result = Query_Disk( fd );
		close(fd);
		if ( result != -1 ) {
		    HRD_history[ iindex ] = 0;
		    return ((HRDEV_DISK << HRDEV_TYPE_SHIFT) + iindex );
		}
	    }
	    HRD_history[ iindex ] = now;
	    HRD_index++;
	}
	HRD_type_index++;
	HRD_index = 0;
    }
    HRD_index = -1;
    return -1;
}

void
Save_HR_Disk_Specific (void)
{
#ifdef DIOC_DESCRIBE
	    HRD_savedIntf_type = HRD_info.intf_type; 
	    HRD_savedDev_type  = HRD_info.dev_type;
	    HRD_savedFlags     = HRD_info.flags;
	    HRD_savedCapacity  = HRD_cap.lba / 2;
#endif
#ifdef DKIOCINFO
	    HRD_savedCtrl_type = HRD_info.dki_ctype;
	    HRD_savedFlags     = HRD_info.dki_flags;
	    HRD_savedCapacity  = HRD_cap.dkg_ncyl*
				 HRD_cap.dkg_nhead*
				 HRD_cap.dkg_nsect / 2; /* ??? */
#endif
#ifdef HAVE_LINUX_HDREG_H
	    HRD_savedCapacity  = HRD_info.lba_capacity / 2 ;
	    HRD_savedFlags     = HRD_info.config;
#endif
#ifdef DIOCGDINFO
	    HRD_savedCapacity  = HRD_info.d_secperunit / 2;
#endif
}

void
Save_HR_Disk_General (void)
{
#ifdef DIOC_DESCRIBE
    strcpy( HRD_savedModel,  HRD_info.model_num );   
#endif
#ifdef DKIOCINFO
    strcpy( HRD_savedModel,  HRD_info.dki_dname );   
#endif
#ifdef HAVE_LINUX_HDREG_H
    strcpy( HRD_savedModel,  (const char *)HRD_info.model );   
#endif
#ifdef DIOCGDINFO
    strcpy( HRD_savedModel,  dktypenames[HRD_info.d_type]);
#endif
}

const char *
describe_disk(int idx)
{
    if ( HRD_savedModel[0] == '\0' )
	return( "some sort of disk");
    else
	return( HRD_savedModel );
}


int
Query_Disk(int fd)
{
    int result = -1;

#ifdef DIOC_DESCRIBE
    result = ioctl( fd, DIOC_DESCRIBE, &HRD_info );
    if ( result != -1 )
	result = ioctl( fd, DIOC_CAPACITY, &HRD_cap );
#endif

#ifdef DKIOCINFO
    result = ioctl( fd, DKIOCINFO, &HRD_info );
    if ( result != -1 )
	result = ioctl( fd, DKIOCGGEOM, &HRD_cap );
#endif

#ifdef HAVE_LINUX_HDREG_H
    if ( HRD_type_index == 0 )		/* Hard disk only */
	result = ioctl( fd, HDIO_GET_IDENTITY, &HRD_info );
#endif

#ifdef DIOCGDINFO
    result = ioctl(fd, DIOCGDINFO, &HRD_info);
#endif

    return( result );
}


int
Is_It_Writeable(void)
{
#ifdef DIOC_DESCRIBE
    if (( HRD_savedFlags & WRITE_PROTECT_FLAG ) ||
	( HRD_savedDev_type == CDROM_DEV_TYPE ))
	return(2);	/* read only */
#endif

#ifdef DKIOCINFO
    if ( HRD_savedCtrl_type == DKC_CDROM )
	return(2);	/* read only */
#endif

    return(1);		/* read-write */
}

int
What_Type_Disk(void)
{
#ifdef DIOC_DESCRIBE
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

#ifdef DKIOCINFO
    switch ( HRD_savedCtrl_type ) {
	case DKC_WDC2880:
	case DKC_DSD5215:
#ifdef DKC_XY450
	case DKC_XY450:
#endif
	case DKC_ACB4000:
	case DKC_MD21:
#ifdef DKC_XD7053
	case DKC_XD7053:
#endif
	case DKC_SCSI_CCS:
#ifdef DKC_PANTHER
	case DKC_PANTHER:
#endif
#ifdef DKC_CDC_9057
	case DKC_CDC_9057:
#endif
#ifdef DKC_FJ_M1060
	case DKC_FJ_M1060:
#endif
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
Is_It_Removeable(void)
{
#ifdef DIOC_DESCRIBE
    if (( HRD_savedIntf_type == PC_FDC_INTF   ) ||
	( HRD_savedDev_type  == WORM_DEV_TYPE ) ||
	( HRD_savedDev_type  == MO_DEV_TYPE   ) ||
	( HRD_savedDev_type  == CDROM_DEV_TYPE ))
	    return(1);		/* true */
#endif

#ifdef DKIOCINFO
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
