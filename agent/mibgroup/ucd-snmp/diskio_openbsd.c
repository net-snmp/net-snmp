#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/agent_callbacks.h>
#include <string.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/disk.h>
#include "diskio.h"
#include "diskio_openbsd.h"
#include "util_funcs/header_simple_table.h"

static int      ndisk;
static struct diskstats *dk;
static char   **dkname;

static int
diskio_getstats(void)
{
    time_t          now;
    int             mib[2];
    char           *t, *tp,*te;
    size_t          size, dkn_size;
    int             i;

    now = time(NULL);
    if (diskio_cache_valid(now)) {
        return 1;
    }
    mib[0] = CTL_HW;
    mib[1] = HW_DISKSTATS;
    size = 0;
    if (sysctl(mib, 2, NULL, &size, NULL, 0) < 0) {
        perror("Can't get size of HW_DISKSTATS mib");
        return 0;
    }
    if (ndisk != size / sizeof(*dk)) {
        if (dk)
            free(dk);
        if (dkname) {
            for (i = 0; i < ndisk; i++)
                if (dkname[i])
                    free(dkname[i]);
            free(dkname);
        }
        ndisk = size / sizeof(*dk);
        if (ndisk == 0)
            return 0;
        dkname = malloc(ndisk * sizeof(char *));
        if (dkname == NULL) {
            perror("Can't alloc memory for dkname");
            return 0;
        }

        mib[0] = CTL_HW;
        mib[1] = HW_DISKNAMES;
        if (sysctl(mib, 2, NULL, &dkn_size, NULL, 0) < 0) {
            perror("Can't get size of HW_DISKNAMES mib");
            return 0;
        }
        te = tp = t = malloc(dkn_size);
        if (t == NULL) {
            perror("Can't alloc memory for te/tp/t");
            return 0;
        }
        if (sysctl(mib, 2, t, &dkn_size, NULL, 0) < 0) {
            perror("Can't get size of HW_DISKNAMES mib");
            free(t);
            return 0;
        }
        for (i = 0; i < ndisk; i++) {
	    while (te-t < dkn_size && *te != ',') te++;
	    *te++ = '\0';
            dkname[i] = strdup(tp);
            tp = te;
        }
        free(t);
        dk = malloc(ndisk * sizeof(*dk));
        if (dk == NULL) {
            perror("Can't alloc memory for dk");
            return 0;
        }
    }
    mib[0] = CTL_HW;
    mib[1] = HW_DISKSTATS;
    if (sysctl(mib, 2, dk, &size, NULL, 0) < 0) {
        perror("Can't get HW_DISKSTATS mib");
        return 0;
    }
    diskio_set_cache_time(now);
    return 1;
}

u_char         *
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
        long_ret = (unsigned long) (dk[indx].ds_rbytes) & 0xffffffff;
        return (u_char *) & long_ret;
    case DISKIO_NWRITTEN:
        long_ret = (unsigned long) (dk[indx].ds_wbytes) & 0xffffffff;
        return (u_char *) & long_ret;
    case DISKIO_READS:
        long_ret = (unsigned long) dk[indx].ds_rxfer & 0xffffffff;
        return (u_char *) & long_ret;
    case DISKIO_WRITES:
        long_ret = (unsigned long) dk[indx].ds_wxfer & 0xffffffff;
        return (u_char *) & long_ret;
    case DISKIO_NREADX:
        *var_len = sizeof(struct counter64);
        c64_ret.low = dk[indx].ds_rbytes & 0xffffffff;
        c64_ret.high = dk[indx].ds_rbytes >> 32;
        return (u_char *) & c64_ret;
    case DISKIO_NWRITTENX:
        *var_len = sizeof(struct counter64);
        c64_ret.low = dk[indx].ds_rbytes & 0xffffffff;
        c64_ret.high = dk[indx].ds_rbytes >> 32;
        return (u_char *) & c64_ret;
    case DISKIO_BUSYTIME:
        *var_len = sizeof(struct counter64);
	longlong_ret = dk[indx].ds_time.tv_sec*1000000 + dk[indx].ds_time.tv_usec;
        c64_ret.low = longlong_ret & 0xffffffff;
        c64_ret.high = longlong_ret >> 32;
	return (u_char *) &c64_ret;
    default:
        ERROR_MSG("diskio.c: don't know how to handle this request.");
    }
    return NULL;
}
