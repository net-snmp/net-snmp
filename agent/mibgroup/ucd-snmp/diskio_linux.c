#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/agent/agent_callbacks.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef HAVE_SYS_SYSMACROS_H
#include <sys/sysmacros.h> /* major() */
#endif
#include <math.h>
#include <unistd.h>
#include "diskio_linux.h"
#include "diskio.h"
#include "util_funcs/header_simple_table.h"

#define STRMAX 1024

static void     diskio_parse_config_disks(const char *token, char *cptr);
static int      diskio_pre_update_config(int, int, void *, void *);
static void     diskio_free_config(void);

#define DISK_INCR 2

typedef struct linux_diskio {
    int             major;
    int             minor;
    unsigned long   blocks;
    char            name[256];
    unsigned long   rio;
    unsigned long   rmerge;
    unsigned long   rsect;
    unsigned long   ruse;
    unsigned long   wio;
    unsigned long   wmerge;
    unsigned long   wsect;
    unsigned long   wuse;
    unsigned long   running;
    unsigned long   use;
    unsigned long   aveq;
} linux_diskio;

/* disk load averages */
typedef struct linux_diskio_la {
    unsigned long   use_prev;
    double          la1, la5, la15;
} linux_diskio_la;

typedef struct linux_diskio_header {
    linux_diskio   *indices;
    int             length;
    int             alloc;
} linux_diskio_header;

typedef struct linux_diskio_la_header {
    linux_diskio_la *indices;
    int             length;
} linux_diskio_la_header;

static linux_diskio_header head;
static linux_diskio_la_header la_head;

struct diskiopart {
    char            syspath[STRMAX];    /* full stat path */
    char            name[STRMAX];       /* name as provided */
    char            shortname[STRMAX];  /* short name for output */
    int             major;
    int             minor;
};

static int      numdisks;
static int      maxdisks;
static struct diskiopart *disks;

/* to do: make sure diskio_free_config() gets invoked upon SIGHUP. */
static int
diskio_pre_update_config(int major, int minor, void *serverarg,
                         void *clientarg)
{
    diskio_free_config();
    return 0;
}

static void
diskio_free_config(void)
{
    int             i;

    DEBUGMSGTL(("diskio", "free config %d\n",
                netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                                       NETSNMP_DS_AGENT_DISKIO_NO_RAM)));
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                           NETSNMP_DS_AGENT_DISKIO_NO_FD, 0);
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                           NETSNMP_DS_AGENT_DISKIO_NO_LOOP, 0);
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                           NETSNMP_DS_AGENT_DISKIO_NO_RAM, 0);
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                           NETSNMP_DS_AGENT_DISKIO_NO_MD, 0);
    netsnmp_ds_set_boolean(NETSNMP_DS_APPLICATION_ID,
                           NETSNMP_DS_AGENT_DISKIO_NO_NBD, 0);

    if (la_head.length) {
        /*
         * reset any usage stats, we may get different list of devices from
         * config
         */
        free(la_head.indices);
        la_head.length = 0;
        la_head.indices = NULL;
    }
    if (numdisks > 0) {
        head.length = 0;
        numdisks = 0;
        for (i = 0; i < maxdisks; i++) {        /* init/erase disk db */
            disks[i].syspath[0] = 0;
            disks[i].name[0] = 0;
            disks[i].shortname[0] = 0;
            disks[i].major = -1;
            disks[i].minor = -1;
        }
    }
}

static int
disk_exists(char *path)
{
    int             index;
    for (index = 0; index < numdisks; index++) {
        DEBUGMSGTL(("ucd-snmp/disk", "Checking for %s. Found %s at %d\n",
                    path, disks[index].syspath, index));
        if (strcmp(path, disks[index].syspath) == 0) {
            return index;
        }
    }
    return -1;
}

static void
add_device(char *path, int addNewDisks)
{
    int             index;
    char            device[STRMAX];
    char            syspath[STRMAX];
    char           *basename;
    struct stat     stbuf;

    if (!path || !strcmp(path, "none")) {
        DEBUGMSGTL(("ucd-snmp/diskio", "Skipping null path device (%s)\n",
                    path));
        return;
    }
    if (numdisks == maxdisks) {
        if (maxdisks == 0) {
            maxdisks = 50;
            disks = malloc(maxdisks * sizeof(struct diskiopart));
            if (!disks) {
                config_perror("malloc failed for new diskio allocation.");
                netsnmp_config_error("\tignoring:  %s", path);
                return;
            }
            memset(disks, 0, maxdisks * sizeof(struct diskiopart));
        } else {
            struct diskiopart *newdisks;
            maxdisks *= 2;
            newdisks = realloc(disks, maxdisks * sizeof(struct diskiopart));
            if (!newdisks) {
                free(disks);
                disks = NULL;
                config_perror("malloc failed for new diskio allocation.");
                netsnmp_config_error("\tignoring:  %s", path);
                return;
            }
            disks = newdisks;
            memset(disks + maxdisks / 2, 0,
                   maxdisks / 2 * sizeof(struct diskiopart));
        }
    }

    /* first find the path for this device */
    device[0] = '\0';
    if (*path != '/') {
        strlcpy(device, "/dev/", STRMAX - 1);
    }
    strncat(device, path, STRMAX - 1);

    /* check for /dev existence */
    if (stat(device, &stbuf) != 0) {    /* ENOENT */
        config_perror("diskio path does not exist.");
        netsnmp_config_error("\tignoring:  %s", path);
        return;
    } else if (!S_ISBLK(stbuf.st_mode)) {       /* ENODEV */
        config_perror("diskio path is not a device.");
        netsnmp_config_error("\tignoring:  %s", path);
        return;
    }

    /*
     * either came with a slash or we just put one there, so the following
     * always works
     */
    basename = strrchr(device, '/') + 1;
    /*
     * construct a sys path using the device numbers to avoid having to
     * disambiguate the various text forms 
     */
    snprintf(syspath, STRMAX - 1, "/sys/dev/block/%d:%d/stat",
             major(stbuf.st_rdev), minor(stbuf.st_rdev));
    DEBUGMSGTL(("ucd-snmp/diskio", " monitoring sys path (%s)\n",
                syspath));

    index = disk_exists(syspath);

    if (index == -1 && addNewDisks) {
        /* The following buffers are cleared above, no need to add '\0' */
        strlcpy(disks[numdisks].syspath, syspath,
                sizeof(disks[numdisks].syspath) - 1);
        strlcpy(disks[numdisks].name, path,
                sizeof(disks[numdisks].name) - 1);
        strlcpy(disks[numdisks].shortname, basename,
                sizeof(disks[numdisks].shortname) - 1);
        disks[numdisks].major = major(stbuf.st_rdev);
        disks[numdisks].minor = minor(stbuf.st_rdev);
        numdisks++;
    }
}

static void
diskio_parse_config_disks(const char *token, char *cptr)
{
#if defined(HAVE_FSTAB_H) || defined(HAVE_GETMNTENT) || defined(HAVE_STATFS)
    char            path[STRMAX];

    /*
     * read disk path (eg, /1 or /usr) 
     */
    copy_nword(cptr, path, sizeof(path));

    /* TODO: we may include regular expressions in future */
    /*
     * check if the disk already exists, if so then modify its
     * parameters. if it does not exist then add it
     */
    add_device(path, 1);
#endif                      /* HAVE_FSTAB_H || HAVE_GETMNTENT || HAVE_STATFS */
}

void init_diskio_linux(void)
{
    char *app = netsnmp_ds_get_string(NETSNMP_DS_LIBRARY_ID,
                                      NETSNMP_DS_LIB_APPTYPE);
    netsnmp_ds_register_config(ASN_BOOLEAN, app, "diskio_exclude_fd",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_FD);
    netsnmp_ds_register_config(ASN_BOOLEAN, app, "diskio_exclude_loop",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_LOOP);
    netsnmp_ds_register_config(ASN_BOOLEAN, app, "diskio_exclude_ram",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_RAM);
    netsnmp_ds_register_config(ASN_BOOLEAN, app, "diskio_exclude_md",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_MD);
    netsnmp_ds_register_config(ASN_BOOLEAN, app, "diskio_exclude_nbd",
                               NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_NBD);

    snmpd_register_config_handler("diskio", diskio_parse_config_disks,
        diskio_free_config, "path | device");
    

    snmp_register_callback(SNMP_CALLBACK_APPLICATION,
	                   SNMPD_CALLBACK_PRE_UPDATE_CONFIG,
	                   diskio_pre_update_config, NULL);

}

static int
get_sysfs_stats(void)
{
    int             i;
    char            buffer[1024];

    head.length = 0;

    for (i = 0; i < numdisks; i++) {
        linux_diskio   *pTemp;
        FILE *f = fopen(disks[i].syspath, "r");

        if (f == NULL) {
            DEBUGMSGTL(("ucd-snmp/diskio", "Can't open %s, skipping",
                        disks[i].syspath));
            continue;
        }

        if (fgets(buffer, sizeof(buffer), f) == NULL) {
            DEBUGMSGTL(("ucd-snmp/diskio", "Can't read %s, skipping",
                        disks[i].syspath));
            fclose(f);
            continue;
        }

        if (head.length == head.alloc) {
            head.alloc += DISK_INCR;
            head.indices = realloc(head.indices,
                                   head.alloc * sizeof(linux_diskio));
        }
        pTemp = &head.indices[head.length];
        pTemp->major = disks[i].major;
        pTemp->minor = disks[i].minor;
        strlcpy(pTemp->name, disks[i].shortname, sizeof(pTemp->name) - 1);
        if (sscanf (buffer,
                    "%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu\n",
                    &pTemp->rio, &pTemp->rmerge, &pTemp->rsect, &pTemp->ruse,
                    &pTemp->wio, &pTemp->wmerge, &pTemp->wsect, &pTemp->wuse,
                    &pTemp->running, &pTemp->use, &pTemp->aveq) != 11)
            sscanf(buffer,
                   "%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu%*[ \n\t]%lu\n",
                   &pTemp->rio, &pTemp->rsect, &pTemp->wio, &pTemp->wsect);
        head.length++;
        fclose(f);
    }
    return 0;
}

static int
is_excluded(const char *name)
{
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_FD)
        && !(strncmp(name, "fd", 2)))
        return 1;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_LOOP)
        && !(strncmp(name, "loop", 4)))
        return 1;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_RAM)
        && !(strncmp(name, "ram", 3)))
        return 1;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_MD)
        && !(strncmp(name, "md", 2)))
        return 1;
    if (netsnmp_ds_get_boolean(NETSNMP_DS_APPLICATION_ID,
                               NETSNMP_DS_AGENT_DISKIO_NO_NBD)
        && !(strncmp(name, "nbd", 2)))
        return 1;
    return 0;
}

static int read_proc_partitions(void)
{
    FILE           *parts;
    char            buffer[1024];
    int             rc;

    /*
     * /proc/partitions was introduced before 2002. See also
     * get_partition_list() in b/fs/partitions/check.c. Today the code that
     * implements /proc/partitions exists in show_partition() in block/genhd.c.
     */
    parts = fopen("/proc/partitions", "r");
    if (!parts) {
        snmp_log_perror("/proc/partitions");
        return FALSE;
    }

    /* Skip the first two lines since these contain header information. */
    NETSNMP_IGNORE_RESULT(fgets(buffer, sizeof(buffer), parts));
    NETSNMP_IGNORE_RESULT(fgets(buffer, sizeof(buffer), parts));

    while (!feof(parts)) {
        linux_diskio   *pTemp;

        if (head.length == head.alloc) {
            head.alloc += DISK_INCR;
            head.indices = realloc(head.indices,
                                   head.alloc * sizeof(linux_diskio));
        }
        pTemp = &head.indices[head.length];

        rc = fscanf(parts,
                    "%d %d %lu %255s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
                    &pTemp->major, &pTemp->minor, &pTemp->blocks,
                    pTemp->name, &pTemp->rio, &pTemp->rmerge,
                    &pTemp->rsect, &pTemp->ruse, &pTemp->wio,
                    &pTemp->wmerge, &pTemp->wsect, &pTemp->wuse,
                    &pTemp->running, &pTemp->use, &pTemp->aveq);
        if (rc != 15) {
            snmp_log(LOG_ERR,
                     "diskio.c: cannot find statistics in /proc/partitions\n");
            fclose(parts);
            return FALSE;
        }
        if (!is_excluded(pTemp->name))
            head.length++;
    }

    fclose(parts);

    return TRUE;
}

static int read_proc_diskstats(void)
{
    FILE           *parts;
    char            buffer[1024];

    /*
     * /proc/diskstats was introduced by Linux kernel commit 3422161186a4
     * ("[PATCH] Aggregated disk statistics") # v2.6.12.
     */
    parts = fopen("/proc/diskstats", "r");
    if (!parts)
        return FALSE;

    while (fgets(buffer, sizeof(buffer), parts)) {
        linux_diskio *pTemp;

        if (head.length == head.alloc) {
            head.alloc += DISK_INCR;
            head.indices = realloc(head.indices,
                                   head.alloc * sizeof(linux_diskio));
        }
        pTemp = &head.indices[head.length];
        sscanf(buffer, "%d %d", &pTemp->major, &pTemp->minor);
        if (sscanf(buffer,
                   "%d %d %s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu\n",
                   &pTemp->major, &pTemp->minor, pTemp->name, &pTemp->rio,
                   &pTemp->rmerge, &pTemp->rsect, &pTemp->ruse, &pTemp->wio,
                   &pTemp->wmerge, &pTemp->wsect, &pTemp->wuse,
                   &pTemp->running, &pTemp->use, &pTemp->aveq) != 14 &&
            sscanf(buffer, "%d %d %s %lu %lu %lu %lu\n", &pTemp->major,
                   &pTemp->minor, pTemp->name, &pTemp->rio,
                   &pTemp->rsect, &pTemp->wio, &pTemp->wsect) != 7) {
            fclose(parts);
            snmp_log(LOG_ERR,
                     "diskio.c: failed to parse /proc/diskstats\n");
            return FALSE;
        }
        if (!is_excluded(pTemp->name))
            head.length++;
    }

    fclose(parts);

    return TRUE;
}

static int
diskio_getstats(void)
{
    struct stat     stbuf;
    time_t          now;

    now = time(NULL);
    if (diskio_cache_valid(now)) {
        return 0;
    }

    if (!head.indices) {
        head.alloc = DISK_INCR;
        head.indices = malloc(head.alloc * sizeof(linux_diskio));
    }
    head.length = 0;

    memset(head.indices, 0, head.alloc * sizeof(linux_diskio));

    if (numdisks > 0) {
        /*
         * 'diskio' configuration is used - go through the whitelist only and
         * read /sys/dev/block/xxx
         */
        diskio_set_cache_time(now);
        return get_sysfs_stats();
    }
    /* 'diskio' configuration is not used - report all devices */
    if (read_proc_diskstats()) {
    } else if (stat("/proc/vz", &stbuf) == 0) {
        // OpenVZ / Virtuozzo containers do not have /proc/diskstats
    } else if (!read_proc_partitions()) {
        return 1;
    }

    diskio_set_cache_time(now);
    return 0;
}

void
devla_getstats(unsigned int regno, void *dummy)
{

    static double   expon1, expon5, expon15;
    double          busy_time, busy_percent;
    int             idx;

    if (diskio_getstats() == 1) {
        ERROR_MSG("can't do diskio_getstats()\n");
        return;
    }

    if (!la_head.length) {
        la_head.indices = malloc(head.length * sizeof(linux_diskio_la));
        for (idx = 0; idx < head.length; idx++) {
            la_head.indices[idx].la1 = la_head.indices[idx].la5 =
                la_head.indices[idx].la15 = 0.;
            la_head.indices[idx].use_prev = head.indices[idx].use;
        }
        la_head.length = head.length;
        expon1 = exp(-(((double) DISKIO_SAMPLE_INTERVAL) / ((double) 60)));
        expon5 =
            exp(-(((double) DISKIO_SAMPLE_INTERVAL) / ((double) 300)));
        expon15 =
            exp(-(((double) DISKIO_SAMPLE_INTERVAL) / ((double) 900)));
    } else if (head.length - la_head.length) {
        la_head.indices = realloc(la_head.indices,
                                  head.length * sizeof(linux_diskio_la));
        for (idx = la_head.length; idx < head.length; idx++) {
            la_head.indices[idx].la1 = la_head.indices[idx].la5 =
                la_head.indices[idx].la15 = 0.;
            la_head.indices[idx].use_prev = head.indices[idx].use;
        }
        la_head.length = head.length;
    }

    for (idx = 0; idx < head.length; idx++) {
        busy_time = head.indices[idx].use - la_head.indices[idx].use_prev;
        busy_percent =
            busy_time * 100. / ((double) DISKIO_SAMPLE_INTERVAL) / 1000.;
        la_head.indices[idx].la1 =
            la_head.indices[idx].la1 * expon1 + busy_percent * (1. -
                                                                expon1);
        la_head.indices[idx].la5 =
            la_head.indices[idx].la5 * expon5 + busy_percent * (1. -
                                                                expon5);
        la_head.indices[idx].la15 =
            la_head.indices[idx].la15 * expon15 + busy_percent * (1. -
                                                                  expon15);
        /*
         * fprintf(stderr, "(%d) update la1=%f la5=%f la15=%f\n",
         * idx, la_head.indices[idx].la1, la_head.indices[idx].la5,
         * la_head.indices[idx].la15);
         */
        la_head.indices[idx].use_prev = head.indices[idx].use;
    }
}

u_char         *
var_diskio(struct variable *vp,
           oid * name,
           size_t *length,
           int exact, size_t *var_len, WriteMethod ** write_method)
{
    unsigned int    indx;
    static unsigned long long_ret;
    static struct counter64 c64_ret;

    if (diskio_getstats() == 1) {
        return NULL;
    }

    if (header_simple_table
        (vp, name, length, exact, var_len, write_method, head.length)) {
        return NULL;
    }

    indx = (unsigned int) (name[*length - 1] - 1);

    if (indx >= head.length)
        return NULL;

    switch (vp->magic) {
    case DISKIO_INDEX:
        long_ret = indx + 1;
        return (u_char *) & long_ret;
    case DISKIO_DEVICE:
        *var_len = strlen(head.indices[indx].name);
        return (u_char *) head.indices[indx].name;
    case DISKIO_NREAD:
        long_ret = (head.indices[indx].rsect * 512) & 0xffffffff;
        return (u_char *) & long_ret;
    case DISKIO_NWRITTEN:
        long_ret = (head.indices[indx].wsect * 512) & 0xffffffff;
        return (u_char *) & long_ret;
    case DISKIO_READS:
        long_ret = head.indices[indx].rio & 0xffffffff;
        return (u_char *) & long_ret;
    case DISKIO_WRITES:
        long_ret = head.indices[indx].wio & 0xffffffff;
        return (u_char *) & long_ret;
    case DISKIO_LA1:
        if (la_head.length > indx)
            long_ret = la_head.indices[indx].la1;
        else
            long_ret = 0;       /* we don't have the load yet */
        return (u_char *) & long_ret;
    case DISKIO_LA5:
        if (la_head.length > indx)
            long_ret = la_head.indices[indx].la5;
        else
            long_ret = 0;       /* we don't have the load yet */
        return (u_char *) & long_ret;
    case DISKIO_LA15:
        if (la_head.length > indx)
            long_ret = la_head.indices[indx].la15;
        else
            long_ret = 0;
        return (u_char *) & long_ret;
    case DISKIO_BUSYTIME:
        *var_len = sizeof(struct counter64);
        c64_ret.low = head.indices[indx].use * 1000 & 0xffffffff;
        c64_ret.high = head.indices[indx].use * 1000 >> 32;
        return (u_char *) & c64_ret;
    case DISKIO_NREADX:
        *var_len = sizeof(struct counter64);
        c64_ret.low = head.indices[indx].rsect * 512 & 0xffffffff;
        c64_ret.high = head.indices[indx].rsect >> (32 - 9);
        return (u_char *) & c64_ret;
    case DISKIO_NWRITTENX:
        *var_len = sizeof(struct counter64);
        c64_ret.low = head.indices[indx].wsect * 512 & 0xffffffff;
        c64_ret.high = head.indices[indx].wsect >> (32 - 9);
        return (u_char *) & c64_ret;
    default:
        snmp_log(LOG_ERR, "don't know how to handle %d request\n",
                 vp->magic);
    }
    return NULL;
}
