#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/agent_callbacks.h>
#include <sys/sysctl.h>
#include "diskio.h"
#include "diskio_netbsd.h"
#include "util_funcs/header_simple_table.h"

static int      ndisk;
#ifdef HW_IOSTATNAMES
static int nmib[2] = {CTL_HW, HW_IOSTATNAMES};
#else
static int nmib[2] = {CTL_HW, HW_DISKNAMES};
#endif
#ifdef HW_DISKSTATS
#include <sys/disk.h>
static int dmib[3] = {CTL_HW, HW_DISKSTATS, sizeof(struct disk_sysctl)};
static struct disk_sysctl *dk;
#endif
#ifdef HW_IOSTATS
#include <sys/iostat.h>
static int dmib[3] = {CTL_HW, HW_IOSTATS, sizeof(struct io_sysctl)};
static struct io_sysctl *dk;
#endif
static char   **dkname;

static int
diskio_getstats(void)
{
    time_t          now;
    char           *t, *tp;
    size_t          size, dkn_size;
    int             i;

    now = time(NULL);
    if (diskio_cache_valid(now)) {
        return 1;
    }
    size = 0;
    if (sysctl(dmib, 3, NULL, &size, NULL, 0) < 0) {
        perror("Can't get size of HW_DISKSTATS/HW_IOSTATS mib");
        return 0;
    }
    if (ndisk != size / dmib[2]) {
        if (dk)
            free(dk);
        if (dkname) {
            for (i = 0; i < ndisk; i++)
                if (dkname[i])
                    free(dkname[i]);
            free(dkname);
        }
        ndisk = size / dmib[2];
        if (ndisk == 0)
            return 0;
        dkname = malloc(ndisk * sizeof(char *));
        if (dkname == NULL) {
            perror("Can't alloc memory for dkname");
            return 0;
        }

        dkn_size = 0;
        if (sysctl(nmib, 2, NULL, &dkn_size, NULL, 0) < 0) {
            perror("Can't get size of HW_DISKNAMES mib");
            return 0;
        }
        t = malloc(dkn_size);
        if (t == NULL) {
            perror("Can't alloc memory for t");
            return 0;
        }
        if (sysctl(nmib, 2, t, &dkn_size, NULL, 0) < 0) {
            perror("Can't get size of HW_DISKNAMES mib");
            free(t);
            return 0;
        }
        for (i = 0, tp = strtok(t, " "); tp && i < ndisk; i++,
	    tp = strtok(NULL, " ")) {
            dkname[i] = strdup(tp);
        }
        free(t);
        dk = malloc(ndisk * sizeof(*dk));
        if (dk == NULL) {
            perror("Can't alloc memory for dk");
            return 0;
        }
    }
    if (sysctl(dmib, 3, dk, &size, NULL, 0) < 0) {
        perror("Can't get HW_DISKSTATS/HW_IOSTATS mib");
        return 0;
    }
    diskio_set_cache_time(now);
    return 1;
}

u_char *
var_diskio(struct variable * vp,
           oid * name,
           size_t * length,
           int exact, size_t * var_len, WriteMethod ** write_method)
{
    static long     long_ret;
    static long long        longlong_ret;
    static struct counter64 c64_ret;
    unsigned int    indx;

    if (diskio_getstats() == 0)
        return 0;

    if (header_simple_table
        (vp, name, length, exact, var_len, write_method, ndisk))
        return NULL;

    indx = (unsigned int) (name[*length - 1] - 1);
    if (indx >= ndisk)
        return NULL;

    switch (vp->magic) {
    case DISKIO_INDEX:
        long_ret = (long) indx + 1;
        return (u_char *) & long_ret;

    case DISKIO_DEVICE:
        *var_len = strlen(dkname[indx]);
        return (u_char *) dkname[indx];

    case DISKIO_NREAD:
#ifdef HW_DISKSTATS
     	long_ret = dk[indx].dk_rbytes;
#endif
#ifdef HW_IOSTATS
	if (dk[indx].type == IOSTAT_DISK)
	    long_ret = dk[indx].rbytes;
#endif
        return (u_char *) & long_ret;

    case DISKIO_NWRITTEN:
#ifdef HW_DISKSTATS
     	long_ret = dk[indx].dk_wbytes;
#endif
#ifdef HW_IOSTATS
	if (dk[indx].type == IOSTAT_DISK)
	    long_ret = dk[indx].wbytes;
#endif
        return (u_char *) & long_ret;

    case DISKIO_NREADX:
        *var_len = sizeof(struct counter64);
        longlong_ret = dk[indx].rbytes;
        c64_ret.low = longlong_ret & 0xffffffff;
        c64_ret.high = longlong_ret >> 32;
        return (u_char *) & c64_ret;

    case DISKIO_NWRITTENX:
        *var_len = sizeof(struct counter64);
        longlong_ret = dk[indx].wbytes;
        c64_ret.low = longlong_ret & 0xffffffff;
        c64_ret.high = longlong_ret >> 32;
        return (u_char *) & c64_ret;

    case DISKIO_READS:
#ifdef HW_DISKSTATS
     	long_ret = dk[indx].dk_rxfer;
#endif
#ifdef HW_IOSTATS
	if (dk[indx].type == IOSTAT_DISK)
	    long_ret = dk[indx].rxfer;
#endif
        return (u_char *) & long_ret;

    case DISKIO_WRITES:
#ifdef HW_DISKSTATS
     	long_ret = dk[indx].dk_wxfer;
#endif
#ifdef HW_IOSTATS
	if (dk[indx].type == IOSTAT_DISK)
	    long_ret = dk[indx].wxfer;
#endif
        return (u_char *) & long_ret;

    case DISKIO_BUSYTIME:
#ifdef HW_IOSTATS
        *var_len = sizeof(struct counter64);
	if (dk[indx].type == IOSTAT_DISK) {
	    longlong_ret = dk[indx].time_sec*1000 + dk[indx].time_usec/1000;
	    c64_ret.low = longlong_ret & 0xffffffff;
	    c64_ret.high = longlong_ret >> 32;
	    return (u_char *) & c64_ret;
	}
	else
	    return NULL;
#else
	return NULL;
#endif

    default:
        ERROR_MSG("diskio.c: don't know how to handle this request.");
    }
    return NULL;
}
