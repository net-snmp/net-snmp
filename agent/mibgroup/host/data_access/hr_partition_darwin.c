#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/snmp_agent.h>
#include <net-snmp/agent/agent_handler.h>
#include <net-snmp/agent/snmp_vars.h>
#include <net-snmp/agent/var_struct.h>
#include "host/hr_partition.h"
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/IOBSD.h>
#include <DiskArbitration/DADisk.h>

int Get_HR_Disk_Label(char *string, size_t str_len, const char *devfull)
{
    DASessionRef        sess_ref;
    DADiskRef           disk;
    CFDictionaryRef     desc;
    CFStringRef         str_ref;
    CFStringEncoding    sys_encoding = CFStringGetSystemEncoding();

    DEBUGMSGTL(("host/hr_disk", "Disk Label type %s\n", devfull));

    sess_ref = DASessionCreate( NULL );
    if (NULL == sess_ref) {
        strlcpy(string, devfull, str_len);
        return -1;
    }

    disk = DADiskCreateFromBSDName( NULL, sess_ref, devfull );
    if (NULL == disk) {
        CFRelease(sess_ref);
        strlcpy(string, devfull, str_len);
        return -1;
    }

    desc = DADiskCopyDescription( disk );
    if (NULL == desc) {
        snmp_log(LOG_ERR,
                 "diskmgr: couldn't get disk description for %s, skipping\n",
                 devfull);
        CFRelease(disk);
        CFRelease(sess_ref);
        strlcpy(string, devfull, str_len);
        return -1;
    }

    /** model */
    str_ref = (CFStringRef)
        CFDictionaryGetValue(desc, kDADiskDescriptionMediaNameKey);
    if (str_ref) {
        strlcpy(string, CFStringGetCStringPtr(str_ref, sys_encoding),
                str_len);
        DEBUGMSGTL(("verbose:diskmgr:darwin", " name %s\n", string));
    }
    else {
        strlcpy(string, devfull, str_len);
    }
    
    CFRelease(disk);
    CFRelease(desc);
    CFRelease(sess_ref);
    
    return 0;
}
