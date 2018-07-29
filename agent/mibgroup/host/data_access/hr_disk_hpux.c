#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/snmp_vars.h>
#include <fcntl.h>
#include <sys/diskio.h>
#include <sys/scsi.h>
#include "../hr_disk.h"

static disk_describe_type HRD_info;
static capacity_type HRD_cap;

static int      HRD_savedIntf_type;
static int      HRD_savedDev_type;
static int      HRD_savedFlags;

void init_hr_disk_entries(void)
{
#if defined(hpux10) || defined(hpux11)
    Add_HR_Disk_entry("/dev/rdsk/c%dt%xd%d", 0, 1, 0, 15,
                      "/dev/rdsk/c%dt%xd0", 0, 4);
#else                           /* hpux9 */
    Add_HR_Disk_entry("/dev/rdsk/c%dd%xs%d", 201, 201, 0, 15,
                      "/dev/rdsk/c%dd%xs0", 0, 4);
#endif
}

void shutdown_hr_disk(void)
{
}

void Save_HR_Disk_Specific(void)
{
    HRD_savedIntf_type = HRD_info.intf_type;
    HRD_savedDev_type = HRD_info.dev_type;
    HRD_savedFlags = HRD_info.flags;
    HRD_savedCapacity = HRD_cap.lba / 2;
}

void Save_HR_Disk_General(void)
{
    strlcpy(HRD_savedModel, HRD_info.model_num, HRD_SAVED_MODEL_SIZE);
}

int Query_Disk(int fd, const char *devfull)
{
    if (ioctl(fd, DIOC_DESCRIBE, &HRD_info) < 0)
        return -1;
    return ioctl(fd, DIOC_CAPACITY, &HRD_cap);
}

int Is_It_Writeable(void)
{
    if (HRD_savedFlags & WRITE_PROTECT_FLAG ||
        HRD_savedDev_type == CDROM_DEV_TYPE)
        return 2;             /* read only */

    return 1;                 /* read-write */
}

int What_Type_Disk(void)
{
    switch (HRD_savedDev_type) {
    case DISK_DEV_TYPE:
        if (HRD_savedIntf_type == PC_FDC_INTF)
            return 4;         /* Floppy Disk */
        else
            return 3;         /* Hard Disk */
        break;
    case CDROM_DEV_TYPE:
        return 5;             /* Optical RO */
        break;
    case WORM_DEV_TYPE:
        return 6;             /* Optical WORM */
        break;
    case MO_DEV_TYPE:
        return 7;             /* Optical R/W */
        break;
    default:
        return 2;             /* Unknown */
        break;
    }

    return 2;                 /* Unknown */
}

int Is_It_Removeable(void)
{
    if (HRD_savedIntf_type == PC_FDC_INTF ||
        HRD_savedDev_type == WORM_DEV_TYPE ||
        HRD_savedDev_type == MO_DEV_TYPE ||
        HRD_savedDev_type == CDROM_DEV_TYPE)
        return 1;             /* true */

    return 2;                 /* false */
}
