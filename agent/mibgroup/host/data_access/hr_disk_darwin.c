#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/snmp_vars.h>
#include "../hr_disk.h"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/IOBSD.h>
#include <DiskArbitration/DADisk.h>

static int64_t  HRD_cap;
static int      HRD_access;
static int      HRD_type;
static int      HRD_removable;
static char     HRD_model[40];
static int      HRD_saved_access;
static int      HRD_saved_type;
static int      HRD_saved_removeble;

typedef struct type_value_map_s {
     const char *type;
     uint32_t    value;
} type_value_map;

static type_value_map media_type_map[] = {
    { "CD-ROM", HRDISKSTORAGEMEDIA_OPTICALDISKROM},
    { "DVD-R", HRDISKSTORAGEMEDIA_OPTICALDISKWORM},
    { "DVD+R", HRDISKSTORAGEMEDIA_OPTICALDISKWORM},
};
static const int media_types = sizeof(media_type_map)/sizeof(media_type_map[0]);

static int
_get_type_value(const char *str_type)
{
    int           i;

    if (NULL == str_type)
        return HRDISKSTORAGEMEDIA_UNKNOWN;

    for (i = 0; i < media_types; ++i) {
        if (0 == strcmp(media_type_map[i].type, str_type))
            return media_type_map[i].value;
    }

    return HRDISKSTORAGEMEDIA_UNKNOWN;
}

static type_value_map proto_map[] = {
    { "ATA", HRDISKSTORAGEMEDIA_HARDDISK},
    { "ATAPI", HRDISKSTORAGEMEDIA_OPTICALDISKROM}
};
static int proto_maps = sizeof(proto_map)/sizeof(proto_map[0]);

static int _get_type_from_protocol(const char *prot)
{
    int           i;

    if (NULL == prot)
        return TV_FALSE;

    for (i = 0; i < proto_maps; ++i) {
        if (0 == strcmp(proto_map[i].type, prot))
            return proto_map[i].value;
    }

    return HRDISKSTORAGEMEDIA_UNKNOWN;
}

void init_hr_disk_entries(void)
{
    Add_HR_Disk_entry("/dev/disk%ds%d", -1, -1, 0, 32, "/dev/disk%d", 1, 32);
}

void shutdown_hr_disk(void)
{
}

void Save_HR_Disk_Specific(void)
{
    HRD_savedCapacity = HRD_cap / 1024;
    HRD_saved_access = HRD_access;
    HRD_saved_type = HRD_type;
    HRD_saved_removeble = HRD_removable;
}

void Save_HR_Disk_General(void)
{
    strlcpy(HRD_savedModel, HRD_model, HRD_SAVED_MODEL_SIZE);
}

int Query_Disk(int fd, const char *devfull)
{
    DASessionRef        sess_ref;
    DADiskRef           disk;
    CFDictionaryRef     desc;
    CFStringRef         str_ref;
    CFNumberRef         number_ref;
    CFBooleanRef        bool_ref;
    CFStringEncoding    sys_encoding = CFStringGetSystemEncoding();

    sess_ref = DASessionCreate(NULL);
    if (NULL == sess_ref)
        return -1;

    disk = DADiskCreateFromBSDName(NULL, sess_ref, devfull);
    if (NULL == disk) {
        CFRelease(sess_ref);
        return -1;
    }

    desc = DADiskCopyDescription(disk);
    if (NULL == desc) {
        CFRelease(disk);
        CFRelease(sess_ref);
        return -1;
    }

    number_ref = (CFNumberRef)
        CFDictionaryGetValue(desc, kDADiskDescriptionMediaSizeKey);
    if (number_ref)
        CFNumberGetValue(number_ref, kCFNumberSInt64Type, &HRD_cap);
    else
        HRD_cap = 0;
    DEBUGMSGTL(("verbose:diskmgr:darwin", " size %lld\n", HRD_cap));

    /** writable?  */
    bool_ref = (CFBooleanRef)
        CFDictionaryGetValue(desc, kDADiskDescriptionMediaWritableKey);
    if (bool_ref)
        HRD_access = CFBooleanGetValue(bool_ref);
    else
        HRD_access = 0;
    DEBUGMSGTL(("verbose:diskmgr:darwin", " writable %d\n",
                HRD_access));

    /** removable?  */
    bool_ref = (CFBooleanRef)
        CFDictionaryGetValue(desc, kDADiskDescriptionMediaRemovableKey);
    if (bool_ref)
        HRD_removable = CFBooleanGetValue(bool_ref);
    else
        HRD_removable = 0;
    DEBUGMSGTL(("verbose:diskmgr:darwin", " removable %d\n",
                HRD_removable));

    /** get type */
    str_ref = (CFStringRef)
        CFDictionaryGetValue(desc, kDADiskDescriptionMediaTypeKey);
    if (str_ref) {
        HRD_type = _get_type_value(CFStringGetCStringPtr(str_ref,
                                                         sys_encoding));
        DEBUGMSGTL(("verbose:diskmgr:darwin", " type %s / %d\n",
                    CFStringGetCStringPtr(str_ref, sys_encoding),
                    HRD_type));
    } else {
        str_ref = (CFStringRef)
            CFDictionaryGetValue(desc, kDADiskDescriptionDeviceProtocolKey);
        if (str_ref) {
            HRD_type =
                _get_type_from_protocol(CFStringGetCStringPtr(str_ref,
                                                              sys_encoding));
            DEBUGMSGTL(("verbose:diskmgr:darwin", " type %s / %d\n",
                        CFStringGetCStringPtr(str_ref, sys_encoding),
                        HRD_type));
        }
        else
            HRD_type = HRDISKSTORAGEMEDIA_UNKNOWN;
    }

    /** model */
    str_ref = (CFStringRef)
        CFDictionaryGetValue(desc, kDADiskDescriptionDeviceModelKey);
    if (str_ref) {
        strlcpy(HRD_model, CFStringGetCStringPtr(str_ref, sys_encoding),
                sizeof(HRD_model));
        DEBUGMSGTL(("verbose:diskmgr:darwin", " model %s\n", HRD_model));
    } else {
        HRD_model[0] = 0;
    }
    CFRelease(disk);
    CFRelease(desc);
    CFRelease(sess_ref);

    return 0;
}

int Is_It_Writeable(void)
{
    return HRD_access ? 1 /* read-write */ : 2 /* read-only */;
}

int Is_It_Removeable(void)
{
    return HRD_removable ? 1 /* true */ : 2 /* false */;
}

int What_Type_Disk(void)
{
    return HRD_type;
}
