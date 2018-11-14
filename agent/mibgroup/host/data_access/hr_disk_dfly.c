#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/snmp_vars.h>
#define DKTYPENAMES
#include <sys/disklabel32.h>
#include <sys/disklabel64.h>
#include <sys/dtype.h>
#include "../hr_disk.h"

static struct disklabel32 HRD_info32;
static struct disklabel64 HRD_info64;
static int disktype;

void init_hr_disk_entries(void)
{
    Add_HR_Disk_entry("/dev/ad%ds%d%c", 0, 1, 1, 4, "/dev/ad%ds%d", 'a', 'h');
    Add_HR_Disk_entry("/dev/da%ds%d%c", 0, 1, 1, 4, "/dev/da%ds%d", 'a', 'h');
}

void shutdown_hr_disk(void)
{
}

void Save_HR_Disk_Specific(void)
{
    switch (disktype) {
    case 32: HRD_savedCapacity = HRD_info32.d_secperunit / 2; break;
    case 64: HRD_savedCapacity = HRD_info64.d_total_size / 1024; break;
    default: HRD_savedCapacity = 0;
    }
}

void Save_HR_Disk_General(void)
{
    switch (disktype) {
    case 32: strlcpy(HRD_savedModel, dktypenames[HRD_info32.d_type], HRD_SAVED_MODEL_SIZE); break;
    case 64: strlcpy(HRD_savedModel, "unknown", HRD_SAVED_MODEL_SIZE); break;
    }
}


int Query_Disk(int fd, const char *devfull)
{
    if (ioctl(fd, DIOCGDINFO64, &HRD_info64) == 0) {
	disktype = 64;
	return 0;
    }
    if (ioctl(fd, DIOCGDINFO32, &HRD_info32) == 0) {
	disktype = 32;
	return 0;
    }
    
    return -1;
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
