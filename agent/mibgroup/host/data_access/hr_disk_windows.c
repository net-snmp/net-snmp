#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/snmp_vars.h>
#include "../hr_disk.h"

void
init_hr_disk_entries(void)
{
}

void
shutdown_hr_disk(void)
{
}

void
Save_HR_Disk_Specific(void)
{
}

void
Save_HR_Disk_General(void)
{
}

int
Query_Disk(int fd, const char *devfull)
{
    return -1;
}

int
Is_It_Writeable(void)
{
    return 1;                   /* read-write */
}

int
What_Type_Disk(void)
{
    return 2;                   /* Unknown */
}

int
Is_It_Removeable(void)
{
    return 2;                   /* false */
}
