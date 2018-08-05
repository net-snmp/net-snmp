/*
 *  Host Resources MIB - partition device group interface - hr_partition.h
 *
 */
#ifndef _MIBGROUP_HRPART_H
#define _MIBGROUP_HRPART_H

config_require(host/hr_disk)

#if defined(__APPLE__) && defined(__MACH__)
config_require(host/data_access/hr_partition_darwin)
#else
config_require(host/data_access/hr_partition_other)
#endif

extern void     init_hr_partition(void);
extern FindVarMethod var_hrpartition;

int Get_HR_Disk_Label(char *string, size_t str_len, const char *devfull);

#endif                          /* _MIBGROUP_HRPART_H */
