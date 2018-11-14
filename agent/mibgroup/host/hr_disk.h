/*
 *  Host Resources MIB - disk device group interface - hr_disk.h
 *
 */
#ifndef _MIBGROUP_HRDISK_H
#define _MIBGROUP_HRDISK_H

config_require(host/hr_device)

#if defined(__linux__)
config_require(host/data_access/hr_disk_linux)
#elif defined(__APPLE__) && defined(__MACH__)
config_require(host/data_access/hr_disk_darwin)
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || \
    defined(__bsdi__)
config_require(host/data_access/hr_disk_bsd)
#elif defined(__DragonFly__)
config_require(host/data_access/hr_disk_dfly)
#elif defined(__sun)
config_require(host/data_access/hr_disk_solaris)
#elif defined(_AIX)
config_require(host/data_access/hr_disk_aix)
#elif defined(__hpux)
config_require(host/data_access/hr_disk_hpux)
#endif

/*************************************************************
 * constants for enums for the MIB node
 * hrDiskStorageAccess (INTEGER / ASN_INTEGER)
 */
#define HRDISKSTORAGEACCESS_READWRITE  1
#define HRDISKSTORAGEACCESS_READONLY  2


/*************************************************************
 * constants for enums for the MIB node
 * hrDiskStorageMedia (INTEGER / ASN_INTEGER)
 */
#define HRDISKSTORAGEMEDIA_OTHER  1
#define HRDISKSTORAGEMEDIA_UNKNOWN  2
#define HRDISKSTORAGEMEDIA_HARDDISK  3
#define HRDISKSTORAGEMEDIA_FLOPPYDISK  4
#define HRDISKSTORAGEMEDIA_OPTICALDISKROM  5
#define HRDISKSTORAGEMEDIA_OPTICALDISKWORM  6
#define HRDISKSTORAGEMEDIA_OPTICALDISKRW  7
#define HRDISKSTORAGEMEDIA_RAMDISK  8

extern void     init_hr_disk(void);
extern void     init_hr_disk_entries(void);
extern void     shutdown_hr_disk(void);

extern void     Init_HR_Disk(void);
extern void     Add_HR_Disk_entry(const char *, int, int, int, int,
                                  const char *, int, int);
extern int      Get_Next_HR_Disk(void);
extern int      Get_Next_HR_Disk_Partition(char *, size_t, int);
extern int      Query_Disk(int, const char *);
extern void     Save_HR_Disk_General(void);
extern void     Save_HR_Disk_Specific(void);
extern int      Is_It_Writeable(void);
extern int      What_Type_Disk(void);
extern int      Is_It_Removeable(void);
extern FindVarMethod var_hrdisk;
extern long     HRD_savedCapacity;
#define HRD_SAVED_MODEL_SIZE 40
extern char     HRD_savedModel[];
extern int      HRD_type_index;


#endif                          /* _MIBGROUP_HRDISK_H */
