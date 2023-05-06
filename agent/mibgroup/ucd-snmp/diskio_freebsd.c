#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <math.h>
#include <sys/param.h>
#ifdef HAVE_DEVSTAT_GETDEVS
#include <sys/resource.h>       /* for CPUSTATES in devstat.h */
#elif HAVE_SYS_DKSTAT_H
#include <sys/dkstat.h>
#endif
#include <devstat.h>
#include <net-snmp/utilities.h>
#include "diskio.h"
#include "diskio_freebsd.h"
#include "util_funcs/header_simple_table.h"

#ifdef HAVE_DEVSTAT_GETDEVS
  #define GETDEVS(x) devstat_getdevs(NULL, (x))
#else
  #define GETDEVS(x) getdevs((x))
#endif

struct dev_la {
#ifdef HAVE_DEVSTAT_GETDEVS
        struct bintime prev;
#else
        struct timeval prev;
#endif
        double la1,la5,la15;
        char name[DEVSTAT_NAME_LEN+5];
};

static struct dev_la *devloads;
static int ndevs;

#ifndef HAVE_DEVSTAT_GETDEVS
double devla_timeval_diff(struct timeval *t1, struct timeval *t2)
{
    double dt1 = (double) t1->tv_sec + (double) t1->tv_usec * 0.000001;
    double dt2 = (double) t2->tv_sec + (double) t2->tv_usec * 0.000001;

    return dt2 - dt1;
}
#endif

void devla_getstats(unsigned int regno, void *dummy)
{
    static struct statinfo *lastat = NULL;
    int i;
    double busy_time, busy_percent;
    static double expon1, expon5, expon15;
    char current_name[DEVSTAT_NAME_LEN+5];

    if (lastat == NULL) {
        lastat = malloc(sizeof(struct statinfo));
        if (lastat != NULL)
            lastat->dinfo = calloc(sizeof(struct devinfo), 1);
        if (lastat == NULL || lastat->dinfo == NULL) {
            SNMP_FREE(lastat);
            ERROR_MSG("Memory alloc failure - devla_getstats()\n");
            return;
        }
    }

    if ((GETDEVS(lastat)) == -1) {
        ERROR_MSG("can't do getdevs()\n");
        return;
    }

    if (ndevs != 0) {
        for (i=0; i < ndevs; i++) {
            snprintf(current_name, sizeof(current_name), "%s%d",
                     lastat->dinfo->devices[i].device_name,
                     lastat->dinfo->devices[i].unit_number);
            if (strcmp(current_name, devloads[i].name)) {
                ndevs = 0;
                free(devloads);
            }
        }
    }

    if (ndevs == 0) {
        ndevs = lastat->dinfo->numdevs;
        devloads = malloc(ndevs * sizeof(struct dev_la));
        memset(devloads, '\0', ndevs * sizeof(struct dev_la));
        for (i=0; i < ndevs; i++) {
            devloads[i].la1 = devloads[i].la5 = devloads[i].la15 = 0;
            memcpy(&devloads[i].prev, &lastat->dinfo->devices[i].busy_time,
                   sizeof(devloads[i].prev));
            snprintf(devloads[i].name, sizeof(devloads[i].name), "%s%d",
                     lastat->dinfo->devices[i].device_name,
                     lastat->dinfo->devices[i].unit_number);
        }
        expon1  = exp(-(((double)DISKIO_SAMPLE_INTERVAL) / ((double)60)));
        expon5  = exp(-(((double)DISKIO_SAMPLE_INTERVAL) / ((double)300)));
        expon15 = exp(-(((double)DISKIO_SAMPLE_INTERVAL) / ((double)900)));
    }

    for (i=0; i<ndevs; i++) {
#ifdef HAVE_DEVSTAT_GETDEVS
        busy_time = devstat_compute_etime(&lastat->dinfo->devices[i].busy_time,
                                          &devloads[i].prev);
#else
        busy_time = devla_timeval_diff(&devloads[i].prev,
                                       &lastat->dinfo->devices[i].busy_time);
#endif
        if (busy_time < 0)
            busy_time = 0;   /* Account for possible FP loss of precision near zero */
        busy_percent = busy_time * 100 / DISKIO_SAMPLE_INTERVAL;
        devloads[i].la1 = devloads[i].la1 * expon1 +
            busy_percent * (1 - expon1);
        /* fprintf(stderr, "(%d) %s: update la1=%.2lf%%\n", i, devloads[i].name, expon1); */
        devloads[i].la5 = devloads[i].la5 * expon5 +
            busy_percent * (1 - expon5);
        devloads[i].la15 = devloads[i].la15 * expon15 +
            busy_percent * (1 - expon15);
        memcpy(&devloads[i].prev, &lastat->dinfo->devices[i].busy_time,
               sizeof(devloads[i].prev));
    }
}

static int      ndisk;
static struct statinfo *stat;
FILE           *file;

static int
diskio_getstats(void)
{
    time_t          now;
    int             i;

    now = time(NULL);
    if (diskio_cache_valid(now)) {
        return 0;
    }
    if (stat == NULL) {
        stat = (struct statinfo *) malloc(sizeof(struct statinfo));
        if (stat != NULL)
            stat->dinfo = calloc(sizeof(struct devinfo), 1);
        if (stat == NULL || stat->dinfo == NULL) {
		SNMP_FREE(stat);
        	ERROR_MSG("Memory alloc failure - diskio_getstats()\n");
		return 1;
	}
    }

    if (GETDEVS(stat) == -1) {
        fprintf(stderr, "Can't get devices:%s\n", devstat_errbuf);
        return 1;
    }
    ndisk = stat->dinfo->numdevs;
    /* Gross hack to include device numbers in the device name array */
    for (i = 0; i < ndisk; i++) {
      char *cp = stat->dinfo->devices[i].device_name;
      int len = strlen(cp);
      if (len > DEVSTAT_NAME_LEN - 3)
        len -= 3;
      cp += len;
      sprintf(cp, "%d", stat->dinfo->devices[i].unit_number);
    }
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
    long long       longlong_ret;
    unsigned int    indx;

    if (diskio_getstats() == 1) {
        return NULL;
    }


    if (header_simple_table
        (vp, name, length, exact, var_len, write_method, ndisk)) {
        return NULL;
    }

    indx = (unsigned int) (name[*length - 1] - 1);

    if (indx >= ndisk)
        return NULL;

    switch (vp->magic) {
    case DISKIO_INDEX:
        long_ret = (long) indx + 1;
        return (u_char *) & long_ret;
    case DISKIO_DEVICE:
        *var_len = strlen(stat->dinfo->devices[indx].device_name);
        return (u_char *) stat->dinfo->devices[indx].device_name;
    case DISKIO_NREAD:
#ifdef HAVE_DEVSTAT_GETDEVS
        long_ret = (signed long) stat->dinfo->devices[indx].bytes[DEVSTAT_READ] & 0xFFFFFFFF;
#else
        long_ret = (signed long) stat->dinfo->devices[indx].bytes_read;
#endif
        return (u_char *) & long_ret;
    case DISKIO_NWRITTEN:
#ifdef HAVE_DEVSTAT_GETDEVS
        long_ret = (signed long) stat->dinfo->devices[indx].bytes[DEVSTAT_WRITE] & 0xFFFFFFFF;
#else
        long_ret = (signed long) stat->dinfo->devices[indx].bytes_written;
#endif
        return (u_char *) & long_ret;
    case DISKIO_NREADX:
        *var_len = sizeof(struct counter64);
#ifdef HAVE_DEVSTAT_GETDEVS
        longlong_ret = stat->dinfo->devices[indx].bytes[DEVSTAT_READ];
#else
        longlong_ret = stat->dinfo->devices[indx].bytes_read;
#endif
        c64_ret.low = longlong_ret & 0xffffffff;
        c64_ret.high = longlong_ret >> 32;
        return (u_char *) & c64_ret;
    case DISKIO_NWRITTENX:
        *var_len = sizeof(struct counter64);
#ifdef HAVE_DEVSTAT_GETDEVS
        longlong_ret = stat->dinfo->devices[indx].bytes[DEVSTAT_WRITE];
#else
        longlong_ret = stat->dinfo->devices[indx].bytes_written;
#endif
        c64_ret.low = longlong_ret & 0xffffffff;
        c64_ret.high = longlong_ret >> 32;
        return (u_char *) & c64_ret;
    case DISKIO_READS:
#ifdef HAVE_DEVSTAT_GETDEVS
        long_ret = (signed long) stat->dinfo->devices[indx].operations[DEVSTAT_READ] & 0xFFFFFFFF;
#else
        long_ret = (signed long) stat->dinfo->devices[indx].num_reads;
#endif
        return (u_char *) & long_ret;
    case DISKIO_WRITES:
#ifdef HAVE_DEVSTAT_GETDEVS
        long_ret = (signed long) stat->dinfo->devices[indx].operations[DEVSTAT_WRITE] & 0xFFFFFFFF;
#else
        long_ret = (signed long) stat->dinfo->devices[indx].num_writes;
#endif
        return (u_char *) & long_ret;
    case DISKIO_LA1:
	long_ret = devloads[indx].la1;
	return (u_char *) & long_ret;
    case DISKIO_LA5:
        long_ret = devloads[indx].la5;
        return (u_char *) & long_ret;
    case DISKIO_LA15:
        long_ret = devloads[indx].la15;
        return (u_char *) & long_ret;

    default:
        ERROR_MSG("diskio.c: don't know how to handle this request.");
    }
    return NULL;
}
