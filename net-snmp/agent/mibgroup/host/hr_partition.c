/*
 *  Host Resources MIB - partition device group implementation - hr_partition.c
 *
 */

#include <config.h>

#include <fcntl.h>
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "host_res.h"
#include "hr_partition.h"
#include "hr_filesys.h"
#include "hr_disk.h"


#include <sys/stat.h>

#define HRP_MONOTONICALLY_INCREASING

	/*********************
	 *
	 *  Kernel & interface information,
	 *   and internal forward declarations
	 *
	 *********************/

static int  HRP_savedDiskIndex;
static int  HRP_savedPartIndex;
static char HRP_savedName[100];

extern int   HRD_index;
extern int   HRD_type_index;

void  Save_HR_Partition __P((int, int));


	/*********************
	 *
	 *  Initialisation & common implementation functions
	 *
	 *********************/

void  Init_HR_Partition __P((void));
int   Get_Next_HR_Partition __P((void));
int header_hrpartition __P((struct variable *,oid *, int *, int, int *, int (**write) __P((int, u_char *, u_char, int, u_char *,oid *,int)) ));

#define MATCH_FAILED	-1
#define MATCH_SUCCEEDED	0

int
header_hrpartition(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;    /* IN - pointer to variable entry that points here */
    oid     *name;	    /* IN/OUT - input name requested, output name found */
    int     *length;	    /* IN/OUT - length of input and output oid's */
    int     exact;	    /* IN - TRUE if an exact match was requested. */
    int     *var_len;	    /* OUT - length of variable or 0 if function returned. */
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
#define HRPART_DISK_NAME_LENGTH		11
#define HRPART_ENTRY_NAME_LENGTH	12
    oid newname[MAX_NAME_LEN];
    int part_idx, LowDiskIndex=-1, LowPartIndex = -1;
    int result;
    char c_oid[MAX_NAME_LEN];

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP("var_hrpartition: %s %d\n", c_oid, exact);
    }

    memcpy( (char *)newname,(char *)vp->name, (int)vp->namelen * sizeof(oid));
	/* Find "next" partition entry */

    Init_HR_Disk();
    Init_HR_Partition();

		/*
	 	 *  Find the "next" disk and partition entries.
		 *  If we're in the middle of the table, then there's
		 *     no point in examining earlier disks, so set the
		 *     starting disk to that of the variable being queried.
		 *
		 *  If we've moved from one column of the table to another,
		 *     then we need to start at the beginning again.
		 *     (i.e. the 'compare' fails to match)
		 *  Similarly if we're at the start of the table
		 *     (i.e. *length is too short to be a full instance)
		 */

    if (( compare( vp->name, (int)vp->namelen, name, (int)vp->namelen ) == 0 ) &&
	( *length > HRPART_DISK_NAME_LENGTH )) {
        LowDiskIndex = (name[HRPART_DISK_NAME_LENGTH] & ((1<<HRDEV_TYPE_SHIFT)-1));

	while ( HRD_index < LowDiskIndex ) {
            Init_HR_Partition();	/* moves to next disk */
	    if ( HRD_index == -1 );
		return(MATCH_FAILED);
	}
    }

    for ( ;; ) {
        part_idx = Get_Next_HR_Partition();
        if ( part_idx == -1 )
	    break;
	newname[HRPART_DISK_NAME_LENGTH] = (HRDEV_DISK << HRDEV_TYPE_SHIFT) + HRD_index;
	newname[HRPART_ENTRY_NAME_LENGTH] = part_idx;
        result = compare(name, *length, newname, (int)vp->namelen + 2);
        if (exact && (result == 0)) {
	    Save_HR_Partition( HRD_index, part_idx );
	    LowDiskIndex = HRD_index;
	    LowPartIndex = part_idx;
            break;
	}
	if (!exact && (result < 0)) {
	    if ( LowPartIndex == -1 ) {
		Save_HR_Partition( HRD_index, part_idx );
	        LowDiskIndex = HRD_index;
	        LowPartIndex = part_idx;
	    }
	    else if ( LowDiskIndex < HRD_index )
		break;
	    else if ( part_idx < LowPartIndex ) {
		Save_HR_Partition( HRD_index, part_idx );
	        LowDiskIndex = HRD_index;
	        LowPartIndex = part_idx;
	    }
#ifdef HRP_MONOTONICALLY_INCREASING
	    break;
#endif
	}
    }

    if ( LowPartIndex == -1 ) {
        DEBUGP("... index out of range\n");
        return(MATCH_FAILED);
    }

    newname[HRPART_DISK_NAME_LENGTH] = (HRDEV_DISK << HRDEV_TYPE_SHIFT) + LowDiskIndex;
    newname[HRPART_ENTRY_NAME_LENGTH] = LowPartIndex;
    memcpy( (char *)name,(char *)newname, ((int)vp->namelen + 2) * sizeof(oid));
    *length = vp->namelen + 2;
    *write_method = 0;
    *var_len = sizeof(long);	/* default to 'long' results */

    if (snmp_get_do_debugging()) {
      sprint_objid (c_oid, name, *length);
      DEBUGP("... get partition stats %s\n", c_oid);
    }
    return LowPartIndex;
}


	/*********************
	 *
	 *  System specific implementation functions
	 *
	 *********************/


u_char	*
var_hrpartition(vp, name, length, exact, var_len, write_method)
    register struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, u_char *,u_char, int, u_char *,oid*, int));
{
    int  part_idx;
    static char string[100];
    struct stat stat_buf;

    part_idx = header_hrpartition(vp, name, length, exact, var_len, write_method);
    if ( part_idx == MATCH_FAILED )
	return NULL;
        
    if (stat( HRP_savedName, &stat_buf ) == -1 )
	return NULL;

    switch (vp->magic){
	case HRPART_INDEX:
	    long_return = part_idx;
	    return (u_char *)&long_return;
	case HRPART_LABEL:
	    *var_len = strlen(HRP_savedName);
	    return (u_char *)HRP_savedName;
	case HRPART_ID:			/* Use the device number */
	    sprintf(string, "0x%x", (int)stat_buf.st_rdev) ;
	    *var_len = strlen(string);
	    return (u_char *) string;
	case HRPART_SIZE:
				/* XXX - based on single partition assumption */
	    long_return = Get_FSSize( HRP_savedName );
	    return (u_char *)&long_return;
	case HRPART_FSIDX:
	    long_return = Get_FSIndex( HRP_savedName );
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

static int HRP_index;
extern char *disk_device_strings[];
extern char disk_device_id[];
extern char disk_device_last[];
extern char disk_device_full[];
extern char disk_partition_first[];
extern char disk_partition_last[];

void
Init_HR_Partition __P((void))
{
   (void)Get_Next_HR_Disk();

   HRP_index = -1;
}

int
Get_Next_HR_Partition __P((void))
{
    char string[100];
    int max_partitions;
    int fd;

    if ( HRD_index == -1 )
	return -1;

    HRP_index++;
    max_partitions = disk_partition_last[ HRD_type_index ]
		   - disk_partition_first[ HRD_type_index ] +1;
    while ( HRP_index < max_partitions ) {
	sprintf(string, disk_device_strings[  HRD_type_index ],
			disk_device_id[       HRD_type_index ] + HRD_index,
			disk_partition_first[ HRD_type_index ] + HRP_index );
	DEBUGP("Get_Next_HR_Partition: %s (%d/%d:%d)\n",
		string, HRD_type_index, HRD_index, HRP_index );

	fd=open( string, O_RDONLY  );
	if (fd != -1 ) {
            close(fd);
            return( HRP_index );
	}
	HRP_index++;
    }

	/*
	 * Finished with this disk, try the next
	 */
    Init_HR_Partition();
    return( Get_Next_HR_Partition() );
}

void
Save_HR_Partition( disk_idx, part_idx )
   int disk_idx;
   int part_idx;
{
   HRP_savedDiskIndex = disk_idx;
   HRP_savedPartIndex = part_idx;
   sprintf( HRP_savedName, disk_device_strings[  HRD_type_index ],
			   disk_device_id[       HRD_type_index ] + HRD_index,
			   disk_partition_first[ HRD_type_index ] + HRP_index );
}
