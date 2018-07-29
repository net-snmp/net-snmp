#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/snmp_vars.h>
#include "../hr_disk.h"
#if HAVE_DIRENT_H
#include <dirent.h>
#endif
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
#include <regex.h>
#endif
#include <linux/fs.h>
#include <linux/hdreg.h>
#include <sys/ioctl.h>

#define MAX_NUMBER_DISK_TYPES 16

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
static char    *lvm_device_names[MAX_NUMBER_DISK_TYPES];
static int      lvm_device_count;
#endif

static struct hd_driveid HRD_info;
static int      HRD_savedFlags;

static void Add_LVM_Disks(void)
{
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    /*
     * LVM devices are harder because their name can be almost anything (see
     * regexp below). Each logical volume is interpreted as its own device with
     * one partition, even if two logical volumes share common volume group.
     */
    regex_t         lvol;
    int             res;
    DIR            *dir;
    struct dirent  *d;

    res =
        regcomp(&lvol, "[0-9a-zA-Z+_\\.-]+-[0-9a-zA-Z+_\\.-]+",
                REG_EXTENDED | REG_NOSUB);
    if (res != 0) {
        char            error[200];
        regerror(res, &lvol, error, sizeof(error)-1);
        DEBUGMSGTL(("host/hr_disk",
                    "Add_LVM_Disks: cannot compile regexp: %s", error));
        return;
    }

    dir = opendir("/dev/mapper/");
    if (dir == NULL) {
        DEBUGMSGTL(("host/hr_disk",
                    "Add_LVM_Disks: cannot open /dev/mapper"));
        regfree(&lvol);
        return;
    }

    while ((d = readdir(dir)) != NULL) {
        res = regexec(&lvol, d->d_name, 0, NULL, 0);
        if (res == 0) {
            char *path = (char*)malloc(PATH_MAX + 1);
            if (path == NULL) {
                DEBUGMSGTL(("host/hr_disk",
                            "Add_LVM_Disks: cannot allocate memory for device %s",
                            d->d_name));
                break;
            }
            snprintf(path, PATH_MAX-1, "/dev/mapper/%s", d->d_name);
            Add_HR_Disk_entry(path, -1, -1, 0, 0, path, 0, 0);

            /*
             * store the device name so we can free it in Remove_LVM_Disks
             */
            lvm_device_names[lvm_device_count] = path;
            ++lvm_device_count;
            if (lvm_device_count >= MAX_NUMBER_DISK_TYPES) {
                DEBUGMSGTL(("host/hr_disk",
                            "Add_LVM_Disks: maximum count of LVM devices reached"));
                break;
            }
        }
    }
    closedir(dir);
    regfree(&lvol);
#endif
}

static void Remove_LVM_Disks(void)
{
#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
    /*
     * just free the device names allocated in add_lvm_disks
     */
    int             i;
    for (i = 0; i < lvm_device_count; i++) {
        free(lvm_device_names[i]);
        lvm_device_names[i] = NULL;
    }
    lvm_device_count = 0;
#endif
}

void init_hr_disk_entries(void)
{
    Add_HR_Disk_entry("/dev/hd%c%d", -1, -1, 'a', 'l', "/dev/hd%c", 1, 15);
    Add_HR_Disk_entry("/dev/sd%c%d", -1, -1, 'a', 'p', "/dev/sd%c", 1, 15);
    Add_HR_Disk_entry("/dev/md%d", -1, -1, 0, 3, "/dev/md%d", 0, 0);
    Add_HR_Disk_entry("/dev/fd%d", -1, -1, 0, 1, "/dev/fd%d", 0, 0);

    Add_LVM_Disks();
}

void shutdown_hr_disk(void)
{
    Remove_LVM_Disks();
}

void Save_HR_Disk_Specific(void)
{
    HRD_savedCapacity = HRD_info.lba_capacity / 2;
    HRD_savedFlags = HRD_info.config;
}

void Save_HR_Disk_General(void)
{
    strlcpy(HRD_savedModel, (const char *) HRD_info.model,
            HRD_SAVED_MODEL_SIZE);
}

int Query_Disk(int fd, const char *devfull)
{
    if (HRD_type_index == 0)    /* IDE hard disk */
        return ioctl(fd, HDIO_GET_IDENTITY, &HRD_info);
    else if (HRD_type_index != 3) {     /* SCSI hard disk, md and LVM devices */
        long            h;

        if (ioctl(fd, BLKGETSIZE, &h) < 0)
            return -1;
        if (HRD_type_index == 2 && h == 0L)
            return -1;        /* ignore empty md devices */

        HRD_info.lba_capacity = h;
        if (HRD_type_index == 1)
            snprintf((char *)HRD_info.model, sizeof(HRD_info.model),
                     "SCSI disk (%s)", devfull);
        else if (HRD_type_index >= 4)
            snprintf((char *)HRD_info.model, sizeof(HRD_info.model),
                     "LVM volume (%s)", devfull + strlen("/dev/mapper/"));
        else
            snprintf((char *)HRD_info.model, sizeof(HRD_info.model),
                     "RAID disk (%s)", devfull);
        HRD_info.config = 0;
    }

    return 0;
}

int Is_It_Writeable(void)
{
    return 1;                 /* read-write */
}

int What_Type_Disk(void)
{
    return 2;                 /* Unknown */
}

int Is_It_Removeable(void)
{
    return HRD_savedFlags & 0x80 ? 1 /* true */ : 2 /* false */;
}

