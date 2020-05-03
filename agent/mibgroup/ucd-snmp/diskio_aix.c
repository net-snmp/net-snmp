#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/agent_callbacks.h>
/*
 * handle disk statistics via libperfstat
 */
#ifdef HAVE_SYS_PROTOSW_H
#include <sys/protosw.h>
#endif
#include <libperfstat.h>
#include "diskio_aix.h"
#include "diskio.h"
#include "util_funcs/header_simple_table.h"

static perfstat_disk_t *ps_disk;	/* storage for all disk values */
static int ps_numdisks;			/* number of disks in system, may change while running */

void init_diskio_aix(void)
{
    /* gather information on first request */
}

/*
 * collect statistics for all disks
 */
int
collect_disks(void)
{
    time_t          now;
    int             i;
    perfstat_id_t   first;

    /* cache valid? if yes, just return */
    now = time(NULL);
    if (ps_disk != NULL && diskio_cache_valid(now)) {
        return 0;
    }

    /* get number of disks we have */
    i = perfstat_disk(NULL, NULL, sizeof(perfstat_disk_t), 0);
    if(i <= 0) return 1;

    /* if number of disks differs or structures are uninitialized, init them */
    if(i != ps_numdisks || ps_disk == NULL) {
        if(ps_disk != NULL) free(ps_disk);
        ps_numdisks = i;
        ps_disk = malloc(sizeof(perfstat_disk_t) * ps_numdisks);
        if(ps_disk == NULL) return 1;
    }

    /* gather statistics about all disks we have */
    strcpy(first.name, "");
    i = perfstat_disk(&first, ps_disk, sizeof(perfstat_disk_t), ps_numdisks);
    if(i != ps_numdisks) return 1;

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
    static struct counter64 c64_ret;
    unsigned int    indx;

    /* get disk statistics */
    if (collect_disks())
        return NULL;

    if (header_simple_table
        (vp, name, length, exact, var_len, write_method, ps_numdisks))
        return NULL;

    indx = (unsigned int) (name[*length - 1] - 1);
    if (indx >= ps_numdisks)
        return NULL;

    /* deliver requested data on requested disk */
    switch (vp->magic) {
    case DISKIO_INDEX:
        long_ret = (long) indx;
        return (u_char *) & long_ret;
    case DISKIO_DEVICE:
        *var_len = strlen(ps_disk[indx].name);
        return (u_char *) ps_disk[indx].name;
    case DISKIO_NREAD:
        long_ret = (signed long) ps_disk[indx].rblks * ps_disk[indx].bsize;
        return (u_char *) & long_ret;
    case DISKIO_NWRITTEN:
        long_ret = (signed long) ps_disk[indx].wblks * ps_disk[indx].bsize;
        return (u_char *) & long_ret;
    case DISKIO_READS:
        long_ret = (signed long) ps_disk[indx].xfers;
        return (u_char *) & long_ret;
    case DISKIO_WRITES:
        long_ret = (signed long) 0;	/* AIX has just one value for read/write transfers */
        return (u_char *) & long_ret;
    case DISKIO_NREADX:
        *var_len = sizeof(struct counter64);
        c64_ret.low = (ps_disk[indx].rblks * ps_disk[indx].bsize) & 0xffffffff;
        c64_ret.high = (ps_disk[indx].rblks * ps_disk[indx].bsize) >> 32;
        return (u_char *) & c64_ret;
    case DISKIO_NWRITTENX:
        *var_len = sizeof(struct counter64);
        c64_ret.low = (ps_disk[indx].wblks * ps_disk[indx].bsize) & 0xffffffff;
        c64_ret.high = (ps_disk[indx].wblks * ps_disk[indx].bsize) >> 32;
        return (u_char *) & c64_ret;

    default:
        ERROR_MSG("diskio.c: don't know how to handle this request.");
    }

    /* return NULL in case of error */
    return NULL;
}
