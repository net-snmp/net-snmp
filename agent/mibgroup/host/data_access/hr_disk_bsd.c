#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/snmp_vars.h>
#define DKTYPENAMES
#include <sys/disklabel.h>
#include "../hr_disk.h"

static struct disklabel HRD_info;

void init_hr_disk_entries(void)
{
#if defined(freebsd4) || defined(freebsd5)
    Add_HR_Disk_entry("/dev/ad%ds%d%c", 0, 1, 1, 4, "/dev/ad%ds%d", 'a', 'h');
    Add_HR_Disk_entry("/dev/da%ds%d%c", 0, 1, 1, 4, "/dev/da%ds%d", 'a', 'h');
#elif defined(freebsd3)
    Add_HR_Disk_entry("/dev/wd%ds%d%c", 0, 1, 1, 4, "/dev/wd%ds%d", 'a',
                      'h');
    Add_HR_Disk_entry("/dev/sd%ds%d%c", 0, 1, 1, 4, "/dev/sd%ds%d", 'a',
                      'h');
#elif defined(freebsd2)
    Add_HR_Disk_entry("/dev/wd%d%c", -1, -1, 0, 3, "/dev/wd%d", 'a', 'h');
    Add_HR_Disk_entry("/dev/sd%d%c", -1, -1, 0, 3, "/dev/sd%d", 'a', 'h');
#elif defined(netbsd1)
    Add_HR_Disk_entry("/dev/wd%d%c", -1, -1, 0, 3, "/dev/wd%dc", 'a', 'h');
    Add_HR_Disk_entry("/dev/sd%d%c", -1, -1, 0, 3, "/dev/sd%dc", 'a', 'h');
#endif
}

void shutdown_hr_disk(void)
{
}

void Save_HR_Disk_Specific(void)
{
    HRD_savedCapacity = HRD_info.d_secperunit / 2;
}

void Save_HR_Disk_General(void)
{
    strlcpy(HRD_savedModel, dktypenames[HRD_info.d_type], HRD_SAVED_MODEL_SIZE);
}


int Query_Disk(int fd, const char *devfull)
{
#if defined(DIOCGMEDIASIZE)
    unsigned long long size64;

    if (ioctl(fd, DIOCGMEDIASIZE, &size64) < 0)
        return -1;
    HRD_info.d_secperunit = size64 / 512;
    return 0;
#elif defined(DIOCGDINFO)
    return ioctl(fd, DIOCGDINFO, &HRD_info);
#else
    return -1;
#endif
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
    return 2;                 /* false */
}
