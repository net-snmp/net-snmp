#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/agent_callbacks.h>
#include <kstat.h>
#include "diskio.h"
#include "diskio_solaris.h"
#include "util_funcs/header_simple_table.h"

#define MAX_DISKS 128

static kstat_ctl_t *kc;
static kstat_t *ksp;
static kstat_io_t kio;
static int      cache_disknr = -1;

void init_diskio_solaris(void)
{
    kc = kstat_open();

    if (kc == NULL)
        snmp_log(LOG_ERR, "diskio: Couldn't open kstat\n");
}

int
get_disk(int disknr)
{
    time_t          now;
    int             i = 0;
    kstat_t *tksp;

    now = time(NULL);
    if (disknr == cache_disknr && diskio_cache_valid(now)) {
        return 1;
    }

    /*
     * could be optimized by checking if cache_disknr<=disknr
     * if so, just reread the data - not going through the whole chain
     * from kc->kc_chain 
     */

    for (tksp = kc->kc_chain; tksp != NULL; tksp = tksp->ks_next) {
        if (tksp->ks_type == KSTAT_TYPE_IO
            && !strcmp(tksp->ks_class, "disk")) {
            if (i == disknr) {
                if (kstat_read(kc, tksp, &kio) == -1)
                    snmp_log(LOG_ERR, "diskio: kstat_read failed\n");
		ksp = tksp;
                diskio_set_cache_time(now);
                cache_disknr = disknr;
                return 1;
            } else {
                i++;
            }
        }
    }
    return 0;
}


u_char         *
var_diskio(struct variable * vp,
           oid * name,
           size_t * length,
           int exact, size_t * var_len, WriteMethod ** write_method)
{
    /*
     * define any variables we might return as static! 
     */
    static long     long_ret;
    static struct counter64 c64_ret;

    if (header_simple_table
        (vp, name, length, exact, var_len, write_method, MAX_DISKS))
        return NULL;


    if (get_disk(name[*length - 1] - 1) == 0)
        return NULL;


    /*
     * We can now simply test on vp's magic number, defined in diskio.h 
     */
    switch (vp->magic) {
    case DISKIO_INDEX:
        long_ret = (long) name[*length - 1];
        return (u_char *) & long_ret;
    case DISKIO_DEVICE:
        *var_len = strlen(ksp->ks_name);
        return (u_char *) ksp->ks_name;
    case DISKIO_NREAD:
        long_ret = (uint32_t) kio.nread;
        return (u_char *) & long_ret;
    case DISKIO_NWRITTEN:
        long_ret = (uint32_t) kio.nwritten;
        return (u_char *) & long_ret;
    case DISKIO_NREADX:
        *var_len = sizeof(struct counter64);
        c64_ret.low = kio.nread & 0xffffffff;
        c64_ret.high = kio.nread >> 32;
        return (u_char *) & c64_ret;
    case DISKIO_NWRITTENX:
        *var_len = sizeof(struct counter64);
        c64_ret.low = kio.nwritten & 0xffffffff;
        c64_ret.high = kio.nwritten >> 32;
        return (u_char *) & c64_ret;
    case DISKIO_READS:
        long_ret = (uint32_t) kio.reads;
        return (u_char *) & long_ret;
    case DISKIO_WRITES:
        long_ret = (uint32_t) kio.writes;
        return (u_char *) & long_ret;

    default:
        ERROR_MSG("diskio.c: don't know how to handle this request.");
    }
    /*
     * if we fall to here, fail by returning NULL 
     */
    return NULL;
}
