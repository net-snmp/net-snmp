#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/agent_callbacks.h>
#include <string.h>
#include <sys/param.h>
#include <sys/sysctl.h>
#include <sys/disk.h>
#include "diskio.h"
#include "diskio_bsdi.h"
#include "util_funcs/header_simple_table.h"

static int      ndisk;
static struct diskstats *dk;
static char   **dkname;

static int
diskio_getstats(void)
{
    time_t          now;
    int             mib[2];
    char           *t, *tp;
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
        mib[0] = CTL_HW;
        mib[1] = HW_DISKNAMES;
        if (sysctl(mib, 2, NULL, &dkn_size, NULL, 0) < 0) {
            perror("Can't get size of HW_DISKNAMES mib");
            return 0;
        }
        tp = t = malloc(dkn_size);
        if (sysctl(mib, 2, t, &dkn_size, NULL, 0) < 0) {
            perror("Can't get size of HW_DISKNAMES mib");
            return 0;
        }
        for (i = 0; i < ndisk; i++) {
            dkname[i] = strdup(tp);
            tp += strlen(tp) + 1;
        }
        free(t);
        dk = malloc(ndisk * sizeof(*dk));
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
        long_ret =
            (signed long) (dk[indx].dk_sectors * dk[indx].dk_secsize);
        return (u_char *) & long_ret;
    case DISKIO_NWRITTEN:
        return NULL;            /* Sigh... BSD doesn't keep separate track */
    case DISKIO_READS:
        long_ret = (signed long) dk[indx].dk_xfers;
        return (u_char *) & long_ret;
    case DISKIO_WRITES:
        return NULL;            /* Sigh... BSD doesn't keep separate track */

    default:
        ERROR_MSG("diskio.c: don't know how to handle this request.");
    }
    return NULL;
}
