#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/agent_callbacks.h>
#include <CoreFoundation/CoreFoundation.h>
#include <IOKit/IOKitLib.h>
#include <IOKit/storage/IOBlockStorageDriver.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/IOBSD.h>
#include "struct.h"
#include "diskio.h"
#include "diskio_darwin.h"
#include "util_funcs/header_simple_table.h"

#define MAXDRIVES	16	/* most drives we will record */
#define MAXDRIVENAME	31	/* largest drive name we allow */

#define kIDXBytesRead		0	/* used as index into the stats array in a drivestats struct */
#define kIDXBytesWritten	1
#define kIDXNumReads		2
#define kIDXNumWrites		3
#define kIDXBytesReadXhi	4
#define kIDXBytesReadXlo	5
#define kIDXBytesWrittenXhi	6
#define kIDXBytesWrittenXlo	7
#define kIDXLast		7

struct drivestats {
    char name[MAXDRIVENAME + 1];
    long bsd_unit_number;
    long stats[kIDXLast+1];
};

static mach_port_t masterPort;		/* to communicate with I/O Kit	*/

static struct drivestats drivestat[MAXDRIVES];

static mach_port_t masterPort;		/* to communicate with I/O Kit	*/

static int num_drives;			/* number of drives detected	*/

void init_diskio_darwin(void)
{
    /* Get the I/O Kit communication handle. */
    IOMasterPort(bootstrap_port, &masterPort);
}    

static int
collect_drive_stats(io_registry_entry_t driver, long *stats)
{
    CFNumberRef     number;
    CFDictionaryRef properties;
    CFDictionaryRef statistics;
    long            value;
    SInt64          value64;
    kern_return_t   status;
    int             i;


    /*
     * If the drive goes away, we may not get any properties
     * for it.  So take some defaults. Nb: use memset ??
     */
    for (i = 0; i < kIDXLast; i++) {
	stats[i] = 0;
    }

    /* retrieve the properties */
    status = IORegistryEntryCreateCFProperties(driver,
                                               NETSNMP_REMOVE_CONST(struct __CFDictionary **, &properties),
					       kCFAllocatorDefault, kNilOptions);
    if (status != KERN_SUCCESS) {
	snmp_log(LOG_ERR, "diskio: device has no properties\n");
/*	fprintf(stderr, "device has no properties\n"); */
	return (1);
    }

    /* retrieve statistics from properties */
    statistics = (CFDictionaryRef)CFDictionaryGetValue(properties,
						       CFSTR(kIOBlockStorageDriverStatisticsKey));
    if (statistics) {

	/* Now hand me the crystals. */
	if ((number = (CFNumberRef)CFDictionaryGetValue(statistics,
						 CFSTR(kIOBlockStorageDriverStatisticsBytesReadKey)))) {
	    CFNumberGetValue(number, kCFNumberSInt32Type, &value);
	    stats[kIDXBytesRead] = value;
	}

	if ((number = (CFNumberRef)CFDictionaryGetValue(statistics,
						 CFSTR(kIOBlockStorageDriverStatisticsBytesWrittenKey)))) {
	    CFNumberGetValue(number, kCFNumberSInt32Type, &value);
	    stats[kIDXBytesWritten] = value;
	}

	if ((number = (CFNumberRef)CFDictionaryGetValue(statistics,
						 CFSTR(kIOBlockStorageDriverStatisticsReadsKey)))) {
	    CFNumberGetValue(number, kCFNumberSInt32Type, &value);
	    stats[kIDXNumReads] = value;
	}
	if ((number = (CFNumberRef)CFDictionaryGetValue(statistics,
						 CFSTR(kIOBlockStorageDriverStatisticsWritesKey)))) {
	    CFNumberGetValue(number, kCFNumberSInt32Type, &value);
	    stats[kIDXNumWrites] = value;
	}
	/* grab the 64 bit versions of the bytes read */
	if ((number = (CFNumberRef)CFDictionaryGetValue(statistics,
						 CFSTR(kIOBlockStorageDriverStatisticsBytesReadKey)))) {
	    CFNumberGetValue(number, kCFNumberSInt64Type, &value64);
	    stats[kIDXBytesReadXhi] = (long)(value64 >> 32);
	    stats[kIDXBytesReadXlo] = (long)(value64 & 0xffffffff);	
	}
		
	/* grab the 64 bit versions of the bytes written */
	if ((number = (CFNumberRef)CFDictionaryGetValue(statistics,
						 CFSTR(kIOBlockStorageDriverStatisticsBytesWrittenKey)))) {
	    CFNumberGetValue(number, kCFNumberSInt64Type, &value64);
	    stats[kIDXBytesWrittenXhi] = (long)(value64 >> 32);
	    stats[kIDXBytesWrittenXlo] = (long)(value64 & 0xffffffff);	
	}
    }
    /* we're done with the properties, release them */
    CFRelease(properties);
    return (0);
}

/*
 * Check whether an IORegistryEntry refers to a valid
 * I/O device, and if so, collect the information.
 */
static int
handle_drive(io_registry_entry_t drive, struct drivestats * dstat)
{
    io_registry_entry_t parent;
    CFMutableDictionaryRef     properties;
    CFStringRef         name;
    CFNumberRef         number;
    kern_return_t       status;

    /* get drive's parent */
    status = IORegistryEntryGetParentEntry(drive, kIOServicePlane, &parent);
    if (status != KERN_SUCCESS) {
	snmp_log(LOG_ERR, "diskio: device has no parent\n");
/*	fprintf(stderr, "device has no parent\n"); */
	return(1);
    }

    if (IOObjectConformsTo(parent, "IOBlockStorageDriver")) {

	/* get drive properties */
	status = IORegistryEntryCreateCFProperties(drive, &properties,
					    kCFAllocatorDefault, kNilOptions);
	if (status != KERN_SUCCESS) {
	    snmp_log(LOG_ERR, "diskio: device has no properties\n");
/*	    fprintf(stderr, "device has no properties\n"); */
	    return(1);
	}

	/* get BSD name and unitnumber from properties */
	name = (CFStringRef)CFDictionaryGetValue(properties,
					  CFSTR(kIOBSDNameKey));
	number = (CFNumberRef)CFDictionaryGetValue(properties,
					    CFSTR(kIOBSDUnitKey));

	/* Collect stats and if successful store them with the name and unitnumber */
	if (name && number && !collect_drive_stats(parent, dstat->stats)) {

	    CFStringGetCString(name, dstat->name, MAXDRIVENAME, CFStringGetSystemEncoding());
	    CFNumberGetValue(number, kCFNumberSInt32Type, &dstat->bsd_unit_number);
	    num_drives++;
	}

	/* clean up, return success */
	CFRelease(properties);
	return(0);
    }

    /* failed, don't keep parent */
    IOObjectRelease(parent);
    return(1);
}

static int
diskio_getstats(void)
{
    time_t                 now;
    io_iterator_t          drivelist;
    io_registry_entry_t    drive;
    CFMutableDictionaryRef match;
    kern_return_t          status;

    now = time(NULL);	/* register current time and check whether cache can be used */
    if (diskio_cache_valid(now)) {
        return 0;
    }

    /*  Retrieve a list of drives. */
    match = IOServiceMatching("IOMedia");
    CFDictionaryAddValue(match, CFSTR(kIOMediaWholeKey), kCFBooleanTrue);
    status = IOServiceGetMatchingServices(masterPort, match, &drivelist);
    if (status != KERN_SUCCESS) {
	snmp_log(LOG_ERR, "diskio: couldn't match whole IOMedia devices\n");
/*	fprintf(stderr,"Couldn't match whole IOMedia devices\n"); */
	return -1;
    }

    num_drives = 0;  /* NB: Incremented by handle_drive */
    while ((drive = IOIteratorNext(drivelist)) && (num_drives < MAXDRIVES)) {
	handle_drive(drive, &drivestat[num_drives]);
	IOObjectRelease(drive);
    }
    IOObjectRelease(drivelist);

    diskio_set_cache_time(now);
    return 0;
}

u_char         *
var_diskio(struct variable * vp,
           oid * name,
           size_t * length,
           int exact, size_t * var_len, WriteMethod ** write_method)
{
    static long     long_ret;
    static struct   counter64 c64_ret;
    unsigned int    indx;

    if (diskio_getstats() == 1) {
        return NULL;
    }


    if (header_simple_table
        (vp, name, length, exact, var_len, write_method, num_drives)) {
        return NULL;
    }

    indx = (unsigned int) (name[*length - 1] - 1);

    if (indx >= num_drives)
        return NULL;

    switch (vp->magic) {
	case DISKIO_INDEX:
	    long_ret = (long) drivestat[indx].bsd_unit_number;
	    return (u_char *) & long_ret;
	case DISKIO_DEVICE:
	    *var_len = strlen(drivestat[indx].name);
	    return (u_char *) drivestat[indx].name;
	case DISKIO_NREAD:
	    long_ret = (signed long) drivestat[indx].stats[kIDXBytesRead];
	    return (u_char *) & long_ret;
	case DISKIO_NWRITTEN:
	    long_ret = (signed long) drivestat[indx].stats[kIDXBytesWritten];
	    return (u_char *) & long_ret;
	case DISKIO_READS:
	    long_ret = (signed long) drivestat[indx].stats[kIDXNumReads];
	    return (u_char *) & long_ret;
	case DISKIO_WRITES:
	    long_ret = (signed long) drivestat[indx].stats[kIDXNumWrites];
	    return (u_char *) & long_ret;
	case DISKIO_LA1:
	case DISKIO_LA5:
	case DISKIO_LA15:
	    /* Hardening: Darwin doesn't provide disk load averages here yet. */
	    long_ret = 0;
	    return (u_char *) & long_ret;
	case DISKIO_NREADX:
	    *var_len = sizeof(struct counter64);
	    c64_ret.low = (signed long) drivestat[indx].stats[kIDXBytesReadXlo];
	    c64_ret.high = (signed long) drivestat[indx].stats[kIDXBytesReadXhi];
	    return (u_char *) & c64_ret;
	case DISKIO_NWRITTENX:
	    *var_len = sizeof(struct counter64);
	    c64_ret.low = (signed long) drivestat[indx].stats[kIDXBytesWrittenXlo];
	    c64_ret.high = (signed long) drivestat[indx].stats[kIDXBytesWrittenXhi];
	    return (u_char *) & c64_ret;
	case DISKIO_BUSYTIME:
	    /* Hardening: return zero until native Darwin busy-time is wired up. */
	    *var_len = sizeof(struct counter64);
	    c64_ret.low = 0;
	    c64_ret.high = 0;
	    return (u_char *) & c64_ret;
	default:
	    ERROR_MSG("diskio.c: don't know how to handle this request.");
    }
    return NULL;
}
