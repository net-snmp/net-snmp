#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "../entity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <linux/ethtool.h>
#include <linux/sockios.h>
#ifdef HAVE_PCI_PCI_H
#include <pci/pci.h>
#endif
#if defined(HAVE_SENSORS_SENSORS_H) && defined(NETSNMP_USE_SENSORS_V3)
#include <sensors/sensors.h>
#endif

#define DMI_PATH    "/sys/class/dmi/id"
#define DT_PATH     "/proc/device-tree"
#define PCI_PATH    "/sys/bus/pci/devices"
#define USB_PATH    "/sys/bus/usb/devices"
#define NET_PATH    "/sys/class/net"
#define NVME_PATH   "/sys/class/nvme"
#define BLOCK_PATH  "/sys/block"
#define HWMON_PATH  "/sys/class/hwmon"
#define PSY_PATH    "/sys/class/power_supply"
#define RTC_PATH    "/sys/class/rtc"
#define PTP_PATH    "/sys/class/ptp"
#define TPM_PATH    "/sys/class/tpm"
#define INPUT_PATH  "/sys/class/input"
#define I2C_DEV_PATH "/sys/class/i2c-dev"
#define GRAPHICS_PATH "/sys/class/graphics"
#define GPIO_PATH   "/sys/class/gpio"
#define NODE_PATH   "/sys/devices/system/node"
#define ACPI_PATH   "/sys/bus/acpi/devices"
#define THERMAL_PATH "/sys/class/thermal"

#define IDX_CHASSIS      1
#define IDX_BASEBOARD   10
#define IDX_BIOS        20
#define IDX_MEMORY     100
#define IDX_DIMM_BASE  110
#define IDX_CPU_BASE    200
#define IDX_CACHE_BASE  300   /* 10 slots per CPU package: 300-309, 310-319, … */
#define IDX_NODE_BASE   500
#define IDX_NODE_MEMORY_BASE 600
#define IDX_PCI_BASE   1000
#define IDX_ATA_BASE   1500
#define IDX_RTC_BASE   2400
#define IDX_ACPI_SYSTEM 2500
#define IDX_ACPI_BUS_BASE 2510
#define IDX_THERMAL_ZONE_BASE 2600
#define IDX_SENSOR_BASE 4000
#define IDX_SFP_BASE   10000
#define IDX_CPU_LOGICAL_CONTAINER_BASE 19000
#define IDX_CPU_CACHE_CONTAINER_BASE 19500
#define IDX_LOGICAL_CPU_BASE 20000
#define IDX_DYNAMIC_BASE 200000

#define HWMON_BUCKETS   256   /* slots in the hwmon hash table */
#define HWMON_SLOT_SZ    20   /* index slots per chip (chip + up to 19 sensors) */

#define ENTITY_INDEXES_FILE     "entity_indexes"
#define ENTITY_INDEXES_TMP_FILE "entity_indexes.tmp"

typedef struct entity_index_alloc_s {
    char key[128];
    int idx;
    struct entity_index_alloc_s *next;
} entity_index_alloc;

static entity_index_alloc *_idx_alloc_head  = NULL;
static int                 _idx_alloc_dirty = 0;
static int                 _idx_alloc_next  = IDX_DYNAMIC_BASE;

/* FNV-1a 32-bit hash — used for stable index assignment */
static uint32_t
_fnv1a_hash(const char *s)
{
    uint32_t h = 2166136261u;
    while (*s) {
        h ^= (unsigned char)*s++;
        h *= 16777619u;
    }
    return h;
}

static uint32_t
_entity_list_hash(void)
{
    netsnmp_entity_info *e;
    uint32_t h = 2166136261u;

    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e)) {
        h ^= (uint32_t)e->idx;          h *= 16777619u;
        h ^= (uint32_t)e->parent_idx;   h *= 16777619u;
        h ^= (uint32_t)e->iana_class;   h *= 16777619u;
        h ^= (uint32_t)e->is_fru;       h *= 16777619u;
        h ^= (uint32_t)e->ifindex;      h *= 16777619u;
        h ^= _fnv1a_hash(e->name);      h *= 16777619u;
        h ^= _fnv1a_hash(e->serial);    h *= 16777619u;
        h ^= _fnv1a_hash(e->fw_rev);    h *= 16777619u;
        h ^= _fnv1a_hash(e->hw_rev);    h *= 16777619u;
        h ^= _fnv1a_hash(e->mfg_name);  h *= 16777619u;
        h ^= _fnv1a_hash(e->model_name);h *= 16777619u;
        h ^= _fnv1a_hash(e->alias);     h *= 16777619u;
        h ^= _fnv1a_hash(e->uris);      h *= 16777619u;
    }
    return h;
}

static void
_entity_list_clone_free(netsnmp_entity_info *head)
{
    netsnmp_entity_info *e, *next;

    for (e = head; e; e = next) {
        next = e->next;
        SNMP_FREE(e);
    }
}

static netsnmp_entity_info *
_entity_list_clone(void)
{
    netsnmp_entity_info *src, *copy, *head = NULL, *tail = NULL;

    for (src = netsnmp_entity_get_first(); src;
         src = netsnmp_entity_get_next(src)) {
        copy = SNMP_MALLOC_TYPEDEF(netsnmp_entity_info);
        if (!copy) {
            _entity_list_clone_free(head);
            return NULL;
        }
        memcpy(copy, src, sizeof(*copy));
        copy->next = NULL;

        if (tail)
            tail->next = copy;
        else
            head = copy;
        tail = copy;
    }

    return head;
}

static netsnmp_entity_info *
_entity_list_find_idx(netsnmp_entity_info *head, int idx)
{
    netsnmp_entity_info *e;

    for (e = head; e; e = e->next) {
        if (e->idx == idx)
            return e;
        if (e->idx > idx)
            return NULL;
    }
    return NULL;
}

static void
_log_entity_device_change(const char *action, const netsnmp_entity_info *e)
{
    snmp_log(LOG_INFO,
             "entity: %s device index=%d class=%d name=\"%s\" descr=\"%s\"\n",
             action, e->idx, e->iana_class, e->name, e->descr);
}

static void
_log_entity_topology_diff(netsnmp_entity_info *old_entities,
                          uint32_t hash_before, uint32_t hash_after)
{
    netsnmp_entity_info *e;
    int added = 0, removed = 0;

    if (!old_entities) {
        snmp_log(LOG_NOTICE,
                 "entity: hardware topology changed (%08x -> %08x)\n",
                 (unsigned)hash_before, (unsigned)hash_after);
        return;
    }

    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e))
        if (!_entity_list_find_idx(old_entities, e->idx))
            added++;
    for (e = old_entities; e; e = e->next)
        if (!netsnmp_entity_get_byIdx(e->idx))
            removed++;

    snmp_log(LOG_NOTICE,
             "entity: hardware topology changed (%08x -> %08x): %d added, %d removed\n",
             (unsigned)hash_before, (unsigned)hash_after, added, removed);

    for (e = old_entities; e; e = e->next)
        if (!netsnmp_entity_get_byIdx(e->idx))
            _log_entity_device_change("removed", e);
    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e))
        if (!_entity_list_find_idx(old_entities, e->idx))
            _log_entity_device_change("added", e);
}

/* Map a string key to a free slot in a linear-probe hash table of `buckets`
 * entries.  `used` is a caller-allocated zero-initialised char array of size
 * `buckets`.  Returns the slot index, or -1 when the table is full. */
static int
_hash_alloc_slot(const char *key, char *used, int buckets)
{
    int slot = (int)(_fnv1a_hash(key) % (uint32_t)buckets);
    int tries = 0;

    while (used[slot] && tries < buckets) {
        slot = (slot + 1) % buckets;
        tries++;
    }
    if (tries == buckets)
        return -1;
    used[slot] = 1;
    return slot;
}

static void
_entity_index_alloc_free(void)
{
    entity_index_alloc *a, *next;

    for (a = _idx_alloc_head; a; a = next) {
        next = a->next;
        free(a);
    }
    _idx_alloc_head  = NULL;
    _idx_alloc_dirty = 0;
    _idx_alloc_next  = IDX_DYNAMIC_BASE;
}

static entity_index_alloc *
_entity_index_alloc_find(const char *key)
{
    entity_index_alloc *a;

    for (a = _idx_alloc_head; a; a = a->next)
        if (strcmp(a->key, key) == 0)
            return a;
    return NULL;
}

static void
_entity_index_alloc_add(const char *key, int idx)
{
    entity_index_alloc *a;

    if (!key || !key[0] || idx <= 0)
        return;
    if (_entity_index_alloc_find(key))
        return;

    a = SNMP_MALLOC_TYPEDEF(entity_index_alloc);
    if (!a)
        return;
    strlcpy(a->key, key, sizeof(a->key));
    a->idx = idx;
    a->next = _idx_alloc_head;
    _idx_alloc_head = a;
    if (idx >= _idx_alloc_next)
        _idx_alloc_next = idx + 1;
}

static void
_entity_index_alloc_load(void)
{
    char path[512], line[1024], key[128];
    int idx;
    FILE *f;

    _entity_index_alloc_free();

    snprintf(path, sizeof(path), "%s/%s",
             get_persistent_directory(), ENTITY_INDEXES_FILE);
    f = fopen(path, "r");
    if (!f)
        return;

    while (fgets(line, sizeof(line), f)) {
        if (sscanf(line, "%d %127[^\t]", &idx, key) == 2 && key[0] &&
            idx >= IDX_DYNAMIC_BASE && !_entity_index_alloc_find(key))
            _entity_index_alloc_add(key, idx);
    }

    fclose(f);
    _idx_alloc_dirty = 0;
}

static int
_entity_index_alloc(const char *key)
{
    entity_index_alloc *a;
    int idx;

    if (!key || !key[0])
        return 0;

    a = _entity_index_alloc_find(key);
    if (a)
        return a->idx;

    idx = _idx_alloc_next;
    _entity_index_alloc_add(key, idx);
    _idx_alloc_dirty = 1;
    return idx;
}

static int
_entity_idx_in_alloc(int idx)
{
    entity_index_alloc *a;

    for (a = _idx_alloc_head; a; a = a->next)
        if (a->idx == idx)
            return 1;
    return 0;
}

static void
_entity_indexes_write(void)
{
    entity_index_alloc *a;
    netsnmp_entity_info *e;
    char path[512], tmp_path[512];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s",
             get_persistent_directory(), ENTITY_INDEXES_FILE);
    snprintf(tmp_path, sizeof(tmp_path), "%s/%s",
             get_persistent_directory(), ENTITY_INDEXES_TMP_FILE);

    f = fopen(tmp_path, "w");
    if (!f) {
        snmp_log(LOG_ERR, "entity: cannot write %s: %s\n",
                 tmp_path, strerror(errno));
        return;
    }

    /* Dynamic devices (alloc list) — includes ghosts for absent devices */
    for (a = _idx_alloc_head; a; a = a->next) {
        e = netsnmp_entity_get_byIdx(a->idx);
        if (e)
            fprintf(f, "%d\t%s\t%s\t%s\t%s\t%s\t%s\n",
                    a->idx, a->key, e->uris, e->name,
                    e->mfg_name, e->model_name, e->descr);
        else
            fprintf(f, "%d\t%s\t\t\t\t\t\n", a->idx, a->key);
    }

    /* Static and PCI devices — skip those already written above */
    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e)) {
        if (!e->uris[0] || _entity_idx_in_alloc(e->idx))
            continue;
        fprintf(f, "%d\t\t%s\t%s\t%s\t%s\t%s\n",
                e->idx, e->uris, e->name,
                e->mfg_name, e->model_name, e->descr);
    }

    if (fclose(f) != 0) {
        snmp_log(LOG_ERR, "entity: cannot close %s: %s\n",
                 tmp_path, strerror(errno));
        remove(tmp_path);
        return;
    }

    if (rename(tmp_path, path) != 0) {
        snmp_log(LOG_ERR, "entity: cannot rename %s to %s: %s\n",
                 tmp_path, path, strerror(errno));
        remove(tmp_path);
        return;
    }

    _idx_alloc_dirty = 0;
}

/* ---- helpers ------------------------------------------------------------- */

static void
_sysfs_read(const char *path, char *buf, size_t bufsz)
{
    FILE *f;
    char *nl;

    buf[0] = '\0';
    if (!(f = fopen(path, "r")))
        return;
    if (!fgets(buf, bufsz, f)) {
        fclose(f);
        return;
    }
    fclose(f);
    if ((nl = strchr(buf, '\n')))
        *nl = '\0';
}

static void
_sysfs_read_key(const char *path, const char *key, char *buf, size_t bufsz)
{
    FILE *f;
    char line[512];
    size_t key_len;

    if (bufsz > 0)
        buf[0] = '\0';
    if (!path || !key || bufsz == 0)
        return;

    f = fopen(path, "r");
    if (!f)
        return;

    key_len = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        char *nl;

        if (strncmp(line, key, key_len) != 0 || line[key_len] != '=')
            continue;
        strlcpy(buf, line + key_len + 1, bufsz);
        if ((nl = strchr(buf, '\n')))
            *nl = '\0';
        break;
    }

    fclose(f);
}

static const char *
_strip_dev_prefix(const char *path)
{
    if (!path)
        return "";
    if (strncmp(path, "/dev/", 5) == 0)
        return path + 5;
    if (strncmp(path, "dev/", 4) == 0)
        return path + 4;
    return path;
}

static int
_is_placeholder(const char *s)
{
    if (!s || !s[0])
        return 1;
    if (strcmp(s, "To Be Filled By O.E.M.") == 0)
        return 1;
    if (strcmp(s, "Not Specified") == 0)
        return 1;
    if (strcmp(s, "None") == 0)
        return 1;
    if (strcmp(s, "Default string") == 0)
        return 1;
    return 0;
}

static void
_set_if_valid(char *dst, size_t dstsz, const char *src)
{
    if (!_is_placeholder(src))
        strlcpy(dst, src, dstsz);
}

static void
_dmi_field(const char *file, char *dst, size_t dstsz)
{
    char path[256], val[256];

    if (dstsz > 0)
        dst[0] = '\0';
    snprintf(path, sizeof(path), "%s/%s", DMI_PATH, file);
    _sysfs_read(path, val, sizeof(val));
    _set_if_valid(dst, dstsz, val);
}

static void
_dt_field(const char *file, char *dst, size_t dstsz)
{
    char path[256], val[256];

    if (dstsz > 0)
        dst[0] = '\0';
    snprintf(path, sizeof(path), "%s/%s", DT_PATH, file);
    _sysfs_read(path, val, sizeof(val));
    _set_if_valid(dst, dstsz, val);
}

static int
_sysfs_read_int(const char *path)
{
    char val[64];

    _sysfs_read(path, val, sizeof(val));
    if (!val[0])
        return 0;
    return atoi(val);
}

static void
_trim_trailing(char *s)
{
    size_t len;

    if (!s)
        return;
    len = strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t'))
        s[--len] = '\0';
}

static void
_append_uri(char *uris, size_t urisz, const char *uri)
{
    size_t len, uri_len;
    const char *p;

    if (!uri || !uri[0] || urisz == 0)
        return;

    uri_len = strlen(uri);
    len = strlen(uris);
    for (p = uris; p && *p; ) {
        const char *end = strchr(p, ' ');
        size_t tok_len = end ? (size_t)(end - p) : strlen(p);

        if (tok_len == uri_len && strncmp(p, uri, uri_len) == 0)
            return;
        p = end ? end + 1 : NULL;
    }

    if (len == 0) {
        if (uri_len < urisz)
            strlcpy(uris, uri, urisz);
        return;
    }

    if (len + 1 + uri_len >= urisz)
        return;
    uris[len++] = ' ';
    uris[len] = '\0';
    strlcpy(uris + len, uri, urisz - len);
}

static void
_append_file_uri(char *uris, size_t urisz, const char *path)
{
    char uri[PATH_MAX + 8];

    if (!path || !path[0])
        return;
    snprintf(uri, sizeof(uri), "file://%s", path);
    _append_uri(uris, urisz, uri);
}

static void
_block_append_by_id_uris(char *uris, size_t urisz, const char *block_name)
{
    DIR *dir;
    struct dirent *de;
    char path[PATH_MAX], target[PATH_MAX], dev_path[PATH_MAX];

    if (!block_name || !block_name[0])
        return;

    snprintf(dev_path, sizeof(dev_path), "/dev/%s", block_name);

    dir = opendir("/dev/disk/by-id");
    if (!dir)
        return;

    while ((de = readdir(dir))) {
        if (de->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "/dev/disk/by-id/%s", de->d_name);
        if (!realpath(path, target))
            continue;
        if (strcmp(target, dev_path) == 0)
            _append_file_uri(uris, urisz, path);
    }

    closedir(dir);
}

/* Find the first block namespace (e.g. "nvme0n1") for an NVMe controller. */
static void
_nvme_first_ns(const char *ctrl_name, char *ns_name, size_t ns_len)
{
    char path[512];
    DIR *dir;
    struct dirent *de;
    size_t ctrl_len;

    ns_name[0] = '\0';
    if (!ctrl_name || !ctrl_name[0])
        return;

    ctrl_len = strlen(ctrl_name);
    snprintf(path, sizeof(path), "%s/%s", NVME_PATH, ctrl_name);
    dir = opendir(path);
    if (!dir)
        return;

    while ((de = readdir(dir))) {
        if (strncmp(de->d_name, ctrl_name, ctrl_len) == 0 &&
            de->d_name[ctrl_len] == 'n' &&
            isdigit((unsigned char)de->d_name[ctrl_len + 1])) {
            strlcpy(ns_name, de->d_name, ns_len);
            break;
        }
    }
    closedir(dir);
}

static void
_block_append_uris(netsnmp_entity_info *e, const char *block_name)
{
    char path[PATH_MAX];

    if (!e || !block_name || !block_name[0])
        return;

    e->uris[0] = '\0';
    snprintf(path, sizeof(path), "/sys/block/%s", block_name);
    _append_file_uri(e->uris, sizeof(e->uris), path);
    snprintf(path, sizeof(path), "/dev/%s", block_name);
    _append_file_uri(e->uris, sizeof(e->uris), path);
    _block_append_by_id_uris(e->uris, sizeof(e->uris), block_name);
}

static void
_block_append_scsi_hctl_uri(netsnmp_entity_info *e, const char *hctl)
{
    char uri[64];

    if (!e || !hctl || !hctl[0])
        return;

    snprintf(uri, sizeof(uri), "scsi:%s", hctl);
    _append_uri(e->uris, sizeof(e->uris), uri);
}

static int
_sysfs_path_ata_port(const char *path)
{
    const char *p;

    if (!path)
        return 0;

    for (p = path; (p = strstr(p, "/ata")) != NULL; p += 4) {
        const char *np = p + 4;

        if (isdigit((unsigned char)*np))
            return atoi(np);
    }

    return 0;
}

static void
_block_stable_key(const char *sysfs_path, const char *hctl,
                  const char *block_name, char *key, size_t key_len)
{
    int ata_port;

    if (key_len > 0)
        key[0] = '\0';

    ata_port = _sysfs_path_ata_port(sysfs_path);
    if (ata_port > 0) {
        snprintf(key, key_len, "ata:%d", ata_port);
        return;
    }

    if (hctl && hctl[0]) {
        snprintf(key, key_len, "scsi:%s", hctl);
        return;
    }

    snprintf(key, key_len, "block:%s", block_name);
}

static void
_block_append_stable_key_uris(netsnmp_entity_info *e, const char *sysfs_path,
                              const char *hctl, const char *key)
{
    int ata_port;
    char uri[64];

    if (!e)
        return;

    ata_port = _sysfs_path_ata_port(sysfs_path);
    if (ata_port > 0) {
        snprintf(uri, sizeof(uri), "ata:%d", ata_port);
        _append_uri(e->uris, sizeof(e->uris), uri);
    }

    _block_append_scsi_hctl_uri(e, hctl);

    if (key && key[0] && strncmp(key, "ata:", 4) != 0 &&
        strncmp(key, "scsi:", 5) != 0)
        _append_uri(e->uris, sizeof(e->uris), key);
}

static void
_nvme_append_uris(netsnmp_entity_info *e, const char *ctrl_name)
{
    DIR *dir;
    struct dirent *de;
    char path[PATH_MAX];
    size_t len;

    if (!e || !ctrl_name || !ctrl_name[0])
        return;

    e->uris[0] = '\0';
    snprintf(path, sizeof(path), "nvme:%s", ctrl_name);
    _append_uri(e->uris, sizeof(e->uris), path);
    snprintf(path, sizeof(path), "%s/%s", NVME_PATH, ctrl_name);
    _append_file_uri(e->uris, sizeof(e->uris), path);
    snprintf(path, sizeof(path), "/dev/%s", ctrl_name);
    _append_file_uri(e->uris, sizeof(e->uris), path);

    dir = opendir(BLOCK_PATH);
    if (!dir)
        return;

    len = strlen(ctrl_name);
    while ((de = readdir(dir))) {
        if (strncmp(de->d_name, ctrl_name, len) != 0)
            continue;
        if (de->d_name[len] != 'n')
            continue;
        if (!isdigit((unsigned char)de->d_name[len + 1]))
            continue;

        snprintf(path, sizeof(path), "/sys/block/%s", de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        snprintf(path, sizeof(path), "/dev/%s", de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        _block_append_by_id_uris(e->uris, sizeof(e->uris), de->d_name);
    }

    closedir(dir);
}

static void
_usb_append_uris(netsnmp_entity_info *e, const char *name)
{
    char path[PATH_MAX], val[64], vendor[32], product[32], serial[128];
    char busnum_str[32], devnum_str[32], devname[128];
    int busnum, devnum;
    const char *sp;

    if (!e || !name || !name[0])
        return;

    e->uris[0] = '\0';
    snprintf(path, sizeof(path), "usb:%s", name);
    _append_uri(e->uris, sizeof(e->uris), path);
    snprintf(path, sizeof(path), "%s/%s", USB_PATH, name);
    _append_file_uri(e->uris, sizeof(e->uris), path);

    snprintf(path, sizeof(path), "%s/%s/uevent", USB_PATH, name);
    _sysfs_read_key(path, "DEVNAME", devname, sizeof(devname));
    if (devname[0]) {
        snprintf(path, sizeof(path), "/dev/%s", _strip_dev_prefix(devname));
        _append_file_uri(e->uris, sizeof(e->uris), path);
    }

    snprintf(path, sizeof(path), "%s/%s/busnum", USB_PATH, name);
    _sysfs_read(path, busnum_str, sizeof(busnum_str));
    snprintf(path, sizeof(path), "%s/%s/devnum", USB_PATH, name);
    _sysfs_read(path, devnum_str, sizeof(devnum_str));
    busnum = busnum_str[0] ? atoi(busnum_str) : 0;
    devnum = devnum_str[0] ? atoi(devnum_str) : 0;
    if (!devname[0] && busnum > 0 && devnum > 0) {
        snprintf(path, sizeof(path), "/dev/bus/usb/%03d/%03d", busnum, devnum);
        _append_file_uri(e->uris, sizeof(e->uris), path);
    }
    if (busnum > 0 && devnum > 0) {
        snprintf(path, sizeof(path), "usb://%03d/%03d", busnum, devnum);
        _append_uri(e->uris, sizeof(e->uris), path);
    }

    snprintf(path, sizeof(path), "%s/%s/idVendor", USB_PATH, name);
    _sysfs_read(path, vendor, sizeof(vendor));
    snprintf(path, sizeof(path), "%s/%s/idProduct", USB_PATH, name);
    _sysfs_read(path, product, sizeof(product));
    snprintf(path, sizeof(path), "%s/%s/serial", USB_PATH, name);
    _sysfs_read(path, serial, sizeof(serial));
    if (vendor[0] && product[0]) {
        for (sp = serial; *sp && !isspace((unsigned char)*sp); sp++)
            ;
        if (serial[0] && !*sp)
            snprintf(val, sizeof(val), "usb:v%sp%s:%s", vendor, product, serial);
        else
            snprintf(val, sizeof(val), "usb:v%sp%s", vendor, product);
        _append_uri(e->uris, sizeof(e->uris), val);
    }
}

static int
_hex_nibble(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int
_parse_uuid(const char *s, u_char *uuid)
{
    int n, high, low;

    n = 0;
    while (s && *s && n < 16) {
        if (*s == '-') {
            s++;
            continue;
        }
        high = _hex_nibble(*s++);
        if (!*s)
            return 0;
        low = _hex_nibble(*s++);
        if (high < 0 || low < 0)
            return 0;
        uuid[n++] = (u_char)((high << 4) | low);
    }

    return n == 16 && (!s || !*s);
}

static netsnmp_entity_info *
_find_first_by_class(int iana_class)
{
    netsnmp_entity_info *e;

    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e))
        if (e->iana_class == iana_class)
            return e;
    return NULL;
}

static netsnmp_entity_info *
_find_first_name_prefix(const char *prefix)
{
    netsnmp_entity_info *e;
    size_t len;

    len = strlen(prefix);
    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e))
        if (strncmp(e->name, prefix, len) == 0)
            return e;
    return NULL;
}

static int
_numa_node_count(void)
{
    DIR *dir;
    struct dirent *de;
    int count, node;

    dir = opendir(NODE_PATH);
    if (!dir)
        return 0;

    count = 0;
    while ((de = readdir(dir)) != NULL) {
        if (sscanf(de->d_name, "node%d", &node) != 1)
            continue;
        if (node >= 0)
            count++;
    }
    closedir(dir);
    return count;
}

static int
_numa_enabled(void)
{
    return _numa_node_count() > 1;
}

static int
_numa_node_idx(int node)
{
    return IDX_NODE_BASE + node;
}

static int
_numa_memory_idx(int node)
{
    return IDX_NODE_MEMORY_BASE + node;
}

static int
_numa_valid_node(int node)
{
    char path[PATH_MAX];

    if (node < 0)
        return 0;
    snprintf(path, sizeof(path), "%s/node%d", NODE_PATH, node);
    return access(path, F_OK) == 0;
}

static int
_numa_cpu_node(int phys_id)
{
    DIR *node_dir, *cpu_dir;
    struct dirent *node_de, *cpu_de;
    char path[PATH_MAX], val[64];
    int node, cpu, pkg;

    if (!_numa_enabled())
        return -1;

    node_dir = opendir(NODE_PATH);
    if (!node_dir)
        return -1;

    while ((node_de = readdir(node_dir)) != NULL) {
        if (sscanf(node_de->d_name, "node%d", &node) != 1)
            continue;

        snprintf(path, sizeof(path), "%s/%s", NODE_PATH, node_de->d_name);
        cpu_dir = opendir(path);
        if (!cpu_dir)
            continue;

        while ((cpu_de = readdir(cpu_dir)) != NULL) {
            if (sscanf(cpu_de->d_name, "cpu%d", &cpu) != 1)
                continue;
            snprintf(path, sizeof(path),
                     "/sys/devices/system/cpu/%s/topology/physical_package_id",
                     cpu_de->d_name);
            _sysfs_read(path, val, sizeof(val));
            if (!val[0])
                continue;
            pkg = atoi(val);
            if (pkg == phys_id) {
                closedir(cpu_dir);
                closedir(node_dir);
                return node;
            }
        }
        closedir(cpu_dir);
    }

    closedir(node_dir);
    return -1;
}

static int
_numa_pci_node(const char *bdf)
{
    char path[PATH_MAX], val[64];
    int node;

    if (!_numa_enabled() || !bdf || !bdf[0])
        return -1;

    snprintf(path, sizeof(path), "%s/%s/numa_node", PCI_PATH, bdf);
    _sysfs_read(path, val, sizeof(val));
    if (!val[0])
        return -1;

    node = atoi(val);
    return _numa_valid_node(node) ? node : -1;
}

static int
_numa_parent_idx(int node)
{
    if (!_numa_enabled() || !_numa_valid_node(node))
        return IDX_BASEBOARD;
    return _numa_node_idx(node);
}

static int
_numa_memory_parent_idx(int node)
{
    if (!_numa_enabled() || !_numa_valid_node(node))
        return IDX_MEMORY;
    return _numa_memory_idx(node);
}

static void
_memory_kb_descr(unsigned long long kb, const char *prefix,
                 char *buf, size_t bufsz)
{
    unsigned long long mib, unit_mib, scaled10;
    const char *suffix;

    if (bufsz > 0)
        buf[0] = '\0';
    if (bufsz == 0)
        return;

    if (kb == 0) {
        strlcpy(buf, prefix, bufsz);
        return;
    }

    mib = (kb + 512) / 1024;
    if (mib < 1024) {
        snprintf(buf, bufsz, "%s (%llu MiB)", prefix, mib);
        return;
    }

    if (mib >= 1024ULL * 1024ULL * 1024ULL) {
        unit_mib = 1024ULL * 1024ULL * 1024ULL;
        suffix = "PiB";
    } else if (mib >= 1024ULL * 1024ULL) {
        unit_mib = 1024ULL * 1024ULL;
        suffix = "TiB";
    } else {
        unit_mib = 1024ULL;
        suffix = "GiB";
    }

    scaled10 = (mib * 10 + unit_mib / 2) / unit_mib;
    snprintf(buf, bufsz, "%s (%llu.%llu %s)", prefix,
             scaled10 / 10, scaled10 % 10, suffix);
}

static int
_numa_node_from_pci_uri(const char *uris)
{
    const char *p;
    char bdf[16];

    if (!uris || !uris[0])
        return -1;

    p = strstr(uris, "pci:");
    if (!p)
        return -1;
    if (sscanf(p, "pci:%15[0-9a-fA-F:.]", bdf) != 1)
        return -1;
    if (strlen(bdf) != 12)
        return -1;
    return _numa_pci_node(bdf);
}

static void
_numa_fix_top_level_parents(void)
{
    netsnmp_entity_info *e;

    if (!_numa_enabled())
        return;

    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e)) {
        int node;

        if (e->parent_idx != IDX_BASEBOARD)
            continue;

        if (e->iana_class == IANA_PHYS_CPU) {
            int phys_id;

            if (sscanf(e->name, "cpu%d", &phys_id) == 1) {
                node = _numa_cpu_node(phys_id);
                if (node >= 0)
                    e->parent_idx = _numa_node_idx(node);
            }
            continue;
        }

        node = _numa_node_from_pci_uri(e->uris);
        if (node >= 0)
            e->parent_idx = _numa_node_idx(node);
    }
}

/* ---- Phase 1: DMI chassis / BIOS / baseboard ----------------------------- */

static void
_load_dmi(void)
{
    netsnmp_entity_info *e;
    char val[256];

    e = netsnmp_entity_create(IDX_CHASSIS);
    if (!e) return;
    e->iana_class = IANA_PHYS_CHASSIS;
    e->parent_idx = 0;
    e->is_fru     = TV_TRUE;
    strlcpy(e->name,  "chassis",        sizeof(e->name));
    strlcpy(e->descr, "System Chassis", sizeof(e->descr));
    snprintf(e->uris, sizeof(e->uris), "file://%s", DMI_PATH);
    _dmi_field("sys_vendor",     e->mfg_name,   sizeof(e->mfg_name));
    _dmi_field("product_name",   e->model_name, sizeof(e->model_name));
    _dmi_field("product_serial", e->serial,     sizeof(e->serial));
    _dmi_field("product_version",e->hw_rev,     sizeof(e->hw_rev));
    if (!e->model_name[0])
        _dt_field("model", e->model_name, sizeof(e->model_name));
    if (!e->serial[0])
        _dt_field("serial-number", e->serial, sizeof(e->serial));
    _dmi_field("product_uuid", val, sizeof(val));
    if (_parse_uuid(val, e->uuid))
        e->uuid_len = 16;

    e = netsnmp_entity_create(IDX_BASEBOARD);
    if (!e) return;
    e->iana_class = IANA_PHYS_BACKPLANE;
    e->parent_idx = IDX_CHASSIS;
    e->is_fru     = TV_TRUE;
    strlcpy(e->name,  "baseboard", sizeof(e->name));
    strlcpy(e->descr, "Baseboard", sizeof(e->descr));
    snprintf(e->uris, sizeof(e->uris), "file://%s", DMI_PATH);
    _dmi_field("board_vendor",  e->mfg_name,   sizeof(e->mfg_name));
    _dmi_field("board_name",    e->model_name, sizeof(e->model_name));
    _dmi_field("board_serial",  e->serial,     sizeof(e->serial));
    _dmi_field("board_version", e->hw_rev,     sizeof(e->hw_rev));
    if (!e->model_name[0])
        _dt_field("model", e->model_name, sizeof(e->model_name));
    if (!e->serial[0])
        _dt_field("serial-number", e->serial, sizeof(e->serial));

    e = netsnmp_entity_create(IDX_BIOS);
    if (!e) return;
    e->iana_class = IANA_PHYS_OTHER;
    e->parent_idx = IDX_BASEBOARD;
    e->parent_rel_pos = -1;
    strlcpy(e->name,  "bios", sizeof(e->name));
    strlcpy(e->descr, "BIOS", sizeof(e->descr));
    snprintf(e->uris, sizeof(e->uris), "file://%s", DMI_PATH);
    _dmi_field("bios_vendor",  e->mfg_name, sizeof(e->mfg_name));
    _dmi_field("bios_version", e->fw_rev,   sizeof(e->fw_rev));
    if (e->fw_rev[0]) {
        snprintf(val, sizeof(val), "BIOS %s", e->fw_rev);
        strlcpy(e->descr, val, sizeof(e->descr));
    }
}

/* ---- Phase 2: CPU packages ----------------------------------------------- */

static int
_cpu_thread_index_from_list(const char *list, int cpu_num)
{
    const char *p;
    int pos;

    pos = 0;
    if (!list)
        return 0;

    p = list;
    while (*p) {
        int first, last, cpu;

        if (sscanf(p, "%d-%d", &first, &last) == 2) {
            for (cpu = first; cpu <= last; cpu++) {
                if (cpu == cpu_num)
                    return pos;
                pos++;
            }
        } else if (sscanf(p, "%d", &first) == 1) {
            if (first == cpu_num)
                return pos;
            pos++;
        }

        while (*p && *p != ',')
            p++;
        if (*p == ',')
            p++;
        while (*p == ' ' || *p == '\t')
            p++;
    }
    return 0;
}

static void
_cpuinfo_for_cpu(int cpu_num, char *model, size_t modelsz,
                 char *family, size_t familysz, char *model_id,
                 size_t model_idsz, char *stepping, size_t steppingsz,
                 char *microcode, size_t microcodesz)
{
    FILE *fp;
    char buf[512], field[128], value[256];
    int in_cpu, cur_cpu;

    if (modelsz > 0)
        model[0] = '\0';
    if (familysz > 0)
        family[0] = '\0';
    if (model_idsz > 0)
        model_id[0] = '\0';
    if (steppingsz > 0)
        stepping[0] = '\0';
    if (microcodesz > 0)
        microcode[0] = '\0';

    fp = fopen("/proc/cpuinfo", "r");
    if (!fp)
        return;

    in_cpu = 0;
    cur_cpu = -1;
    while (fgets(buf, sizeof(buf), fp)) {
        char *nl;
        const char *p;

        nl = strchr(buf, '\n');
        if (nl)
            *nl = '\0';

        if (buf[0] == '\0') {
            if (in_cpu)
                break;
            continue;
        }

        if (sscanf(buf, "processor : %d", &cur_cpu) == 1 ||
            sscanf(buf, "processor\t: %d", &cur_cpu) == 1) {
            in_cpu = cur_cpu == cpu_num;
            continue;
        }
        if (!in_cpu)
            continue;

        p = buf;
        while (*p == ' ' || *p == '\t')
            p++;
        if (sscanf(p, "%127[^:]: %255[^\n]", field, value) != 2)
            continue;
        _trim_trailing(field);
        while (value[0] == ' ' || value[0] == '\t')
            memmove(value, value + 1, strlen(value));
        _trim_trailing(value);

        if (strcmp(field, "model name ") == 0 || strcmp(field, "model name") == 0)
            strlcpy(model, value, modelsz);
        else if (strcmp(field, "cpu family ") == 0 || strcmp(field, "cpu family") == 0)
            strlcpy(family, value, familysz);
        else if (strcmp(field, "model ") == 0 || strcmp(field, "model") == 0)
            strlcpy(model_id, value, model_idsz);
        else if (strcmp(field, "stepping ") == 0 || strcmp(field, "stepping") == 0)
            strlcpy(stepping, value, steppingsz);
        else if (strcmp(field, "microcode ") == 0 || strcmp(field, "microcode") == 0)
            strlcpy(microcode, value, microcodesz);
    }
    fclose(fp);
}

static void
_load_numa_nodes(void)
{
    DIR *dir;
    struct dirent *de;
    char path[PATH_MAX], val[128], descr[128];
    int node;
    unsigned long long kb;

    if (!_numa_enabled())
        return;

    dir = opendir(NODE_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;

        if (sscanf(de->d_name, "node%d", &node) != 1 || node < 0)
            continue;

        e = netsnmp_entity_create(_numa_node_idx(node));
        if (!e)
            continue;
        e->iana_class = IANA_PHYS_CONTAINER;
        e->parent_idx = IDX_BASEBOARD;
        e->is_fru     = TV_FALSE;
        snprintf(e->name, sizeof(e->name), "node%d", node);
        snprintf(e->descr, sizeof(e->descr), "NUMA node %d", node);
        snprintf(path, sizeof(path), "%s/%s", NODE_PATH, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);

        e = netsnmp_entity_create(_numa_memory_idx(node));
        if (!e)
            continue;
        e->iana_class = IANA_PHYS_OTHER;
        e->parent_idx = _numa_node_idx(node);
        e->is_fru     = TV_FALSE;
        snprintf(e->name, sizeof(e->name), "memory%d", node);
        snprintf(path, sizeof(path), "%s/%s/meminfo", NODE_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        kb = 0;
        if (sscanf(val, "Node %*d MemTotal: %llu kB", &kb) != 1)
            kb = 0;
        snprintf(val, sizeof(val), "Node %d memory", node);
        _memory_kb_descr(kb, val, descr, sizeof(descr));
        strlcpy(e->descr, descr, sizeof(e->descr));
        _append_file_uri(e->uris, sizeof(e->uris), path);
    }
    closedir(dir);
}

static void
_load_cpus(void)
{
    DIR *dir;
    struct dirent *de;
    int seen_pkg[256], cores_seen[256][256];
    int pkg_threads[256], pkg_cores[256], pkg_first_cpu[256];
    int cpu_nums[4096], cpu_count, i;

    memset(seen_pkg, 0, sizeof(seen_pkg));
    memset(cores_seen, 0, sizeof(cores_seen));
    memset(pkg_threads, 0, sizeof(pkg_threads));
    memset(pkg_cores, 0, sizeof(pkg_cores));
    for (i = 0; i < 256; i++)
        pkg_first_cpu[i] = -1;

    cpu_count = 0;
    dir = opendir("/sys/devices/system/cpu");
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        char path[PATH_MAX], val[64];
        int cpu_num, pkg, core;

        if (sscanf(de->d_name, "cpu%d", &cpu_num) != 1)
            continue;
        if (cpu_num < 0 || cpu_count >= (int)(sizeof(cpu_nums) / sizeof(cpu_nums[0])))
            continue;

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/%s/topology/physical_package_id",
                 de->d_name);
        _sysfs_read(path, val, sizeof(val));
        pkg = val[0] ? atoi(val) : 0;
        if (pkg < 0 || pkg >= 256)
            pkg = 0;

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/%s/topology/core_id",
                 de->d_name);
        _sysfs_read(path, val, sizeof(val));
        core = val[0] ? atoi(val) : cpu_num;
        if (core < 0 || core >= 256)
            core = cpu_num % 256;

        cpu_nums[cpu_count++] = cpu_num;
        seen_pkg[pkg] = 1;
        pkg_threads[pkg]++;
        if (pkg_first_cpu[pkg] < 0)
            pkg_first_cpu[pkg] = cpu_num;
        if (!cores_seen[pkg][core]) {
            cores_seen[pkg][core] = 1;
            pkg_cores[pkg]++;
        }
    }
    closedir(dir);

    for (i = 0; i < 256; i++) {
        netsnmp_entity_info *e;
        char model[256], family[32], model_id[32], stepping[32], microcode[64];
        char path[PATH_MAX];
        int node;

        if (!seen_pkg[i])
            continue;

        _cpuinfo_for_cpu(pkg_first_cpu[i], model, sizeof(model),
                         family, sizeof(family), model_id, sizeof(model_id),
                         stepping, sizeof(stepping), microcode,
                         sizeof(microcode));

        e = netsnmp_entity_create(IDX_CPU_BASE + i);
        if (!e)
            continue;

        node = _numa_cpu_node(i);
        e->iana_class = IANA_PHYS_CPU;
        e->parent_idx = _numa_parent_idx(node);
        e->parent_rel_pos = -1;
        e->is_fru     = TV_TRUE;
        snprintf(e->name, sizeof(e->name), "cpu-package%d", i);
        snprintf(e->descr, sizeof(e->descr),
                 "CPU package %d, %d cores, %d threads", i,
                 pkg_cores[i], pkg_threads[i]);
        _set_if_valid(e->model_name, sizeof(e->model_name), model);
        if (family[0] || model_id[0] || stepping[0])
            snprintf(e->hw_rev, sizeof(e->hw_rev),
                     "family %s model %s stepping %s",
                     family[0] ? family : "?",
                     model_id[0] ? model_id : "?",
                     stepping[0] ? stepping : "?");
        if (microcode[0])
            snprintf(e->fw_rev, sizeof(e->fw_rev), "microcode %s", microcode);
        snprintf(path, sizeof(path), "/sys/devices/system/cpu");
        _append_file_uri(e->uris, sizeof(e->uris), path);

        e = netsnmp_entity_create(IDX_CPU_LOGICAL_CONTAINER_BASE + i);
        if (e) {
            e->iana_class = IANA_PHYS_CONTAINER;
            e->parent_idx = IDX_CPU_BASE + i;
            e->parent_rel_pos = -1;
            e->is_fru     = TV_FALSE;
            snprintf(e->name, sizeof(e->name), "cpu-package%d-logical", i);
            strlcpy(e->descr, "Logical CPUs", sizeof(e->descr));
            snprintf(e->uris, sizeof(e->uris), "file://%s", path);
        }

        e = netsnmp_entity_create(IDX_CPU_CACHE_CONTAINER_BASE + i);
        if (e) {
            e->iana_class = IANA_PHYS_CONTAINER;
            e->parent_idx = IDX_CPU_BASE + i;
            e->parent_rel_pos = -1;
            e->is_fru     = TV_FALSE;
            snprintf(e->name, sizeof(e->name), "cpu-package%d-cache", i);
            strlcpy(e->descr, "CPU caches", sizeof(e->descr));
            snprintf(e->uris, sizeof(e->uris), "file://%s", path);
        }
    }

    for (i = 0; i < cpu_count; i++) {
        netsnmp_entity_info *e;
        char path[PATH_MAX], val[64], siblings[128];
        int cpu_num, pkg, core, thread_idx;

        cpu_num = cpu_nums[i];
        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/topology/physical_package_id",
                 cpu_num);
        _sysfs_read(path, val, sizeof(val));
        pkg = val[0] ? atoi(val) : 0;
        if (pkg < 0 || pkg >= 256)
            pkg = 0;

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/topology/core_id", cpu_num);
        _sysfs_read(path, val, sizeof(val));
        core = val[0] ? atoi(val) : cpu_num;

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list",
                 cpu_num);
        _sysfs_read(path, siblings, sizeof(siblings));
        thread_idx = _cpu_thread_index_from_list(siblings, cpu_num);

        e = netsnmp_entity_create(IDX_LOGICAL_CPU_BASE + cpu_num);
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_OTHER;
        e->parent_idx = IDX_CPU_LOGICAL_CONTAINER_BASE + pkg;
        e->parent_rel_pos = cpu_num;
        e->is_fru     = TV_FALSE;
        snprintf(e->name, sizeof(e->name), "cpu%d", cpu_num);
        snprintf(e->descr, sizeof(e->descr), "Logical CPU %d, core %d.%d",
                 cpu_num, core, thread_idx);
        snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d", cpu_num);
        _append_file_uri(e->uris, sizeof(e->uris), path);
    }
}

/* ---- Phase 3: DIMM slots via dmidecode ----------------------------------- */

static unsigned long long
_proc_memtotal_kb(void)
{
    FILE *fp;
    char line[256];
    unsigned long long kb;

    fp = fopen("/proc/meminfo", "r");
    if (!fp)
        return 0;

    kb = 0;
    while (fgets(line, sizeof(line), fp)) {
        if (sscanf(line, "MemTotal: %llu kB", &kb) == 1)
            break;
    }
    fclose(fp);
    return kb;
}

static void
_load_dimms(void)
{
    FILE *fp;
    char buf[512], field[128], value[256];
    int  in_mem_device, slot, installed;
    netsnmp_entity_info *e;

    in_mem_device = 0;
    slot = 0;
    installed = 0;
    e = NULL;

    if (!_numa_enabled()) {
        e = netsnmp_entity_create(IDX_MEMORY);
        if (e) {
            char descr[128];

            e->iana_class = IANA_PHYS_OTHER;
            e->parent_idx = IDX_BASEBOARD;
            e->parent_rel_pos = -1;
            strlcpy(e->name, "memory", sizeof(e->name));
            _memory_kb_descr(_proc_memtotal_kb(), "System Memory",
                             descr, sizeof(descr));
            strlcpy(e->descr, descr, sizeof(e->descr));
            snprintf(e->uris, sizeof(e->uris),
                      "file:///sys/devices/system/memory");
            _append_file_uri(e->uris, sizeof(e->uris), "/proc/meminfo");
        }
    }
    e = NULL;

    fp = popen("dmidecode -t memory 2>/dev/null", "r");
    if (!fp)
        return;

    while (fgets(buf, sizeof(buf), fp)) {
        char *nl;
        const char *p;

        nl = strchr(buf, '\n');
        if (nl) *nl = '\0';

        if (strncmp(buf, "Memory Device", 13) == 0 && buf[13] != ':') {
            in_mem_device = 1;
            e = netsnmp_entity_create(IDX_DIMM_BASE + slot);
            slot++;
            if (e) {
                e->iana_class = IANA_PHYS_OTHER;
                e->parent_idx = _numa_memory_parent_idx(0);
                strlcpy(e->descr, "Memory Device", sizeof(e->descr));
                snprintf(e->name, sizeof(e->name), "dimm%d", slot - 1);
            }
            continue;
        }

        if (!in_mem_device || !e)
            continue;

        if (buf[0] == '\0') {
            in_mem_device = 0;
            continue;
        }

        p = buf;
        while (*p == '\t' || *p == ' ') p++;

        if (sscanf(p, "%127[^:]: %255[^\n]", field, value) != 2)
            continue;

        if (strcmp(field, "Locator") == 0) {
            snprintf(e->alias, sizeof(e->alias), "dmi-memory:%d:%s",
                     slot - 1, value);
        } else if (strcmp(field, "Size") == 0) {
            if (strcmp(value, "No Module Installed") != 0 &&
                strcmp(value, "Unknown") != 0) {
                installed++;
                strlcat(e->descr, " ", sizeof(e->descr));
                strlcat(e->descr, value, sizeof(e->descr));
            }
        } else if (strcmp(field, "Manufacturer") == 0) {
            _set_if_valid(e->mfg_name, sizeof(e->mfg_name), value);
        } else if (strcmp(field, "Serial Number") == 0) {
            _set_if_valid(e->serial, sizeof(e->serial), value);
        } else if (strcmp(field, "Part Number") == 0) {
            _set_if_valid(e->model_name, sizeof(e->model_name), value);
        } else if (strcmp(field, "Speed") == 0) {
            if (!_is_placeholder(value) &&
                strcmp(value, "Unknown") != 0) {
                strlcat(e->descr, " @ ", sizeof(e->descr));
                strlcat(e->descr, value, sizeof(e->descr));
            }
        }
    }
    pclose(fp);
}

/* ---- Phase 4: CPU caches ------------------------------------------------- */

static void
_load_caches(void)
{
    DIR *cpu_dir, *cache_dir;
    const struct dirent *cpu_de, *cache_de;
    char path[512], pkg_id[64], level_s[64];
    int seen_pkg[64];

    memset(seen_pkg, 0, sizeof(seen_pkg));

    cpu_dir = opendir("/sys/devices/system/cpu");
    if (!cpu_dir)
        return;

    while ((cpu_de = readdir(cpu_dir))) {
        int cpu_num, phys_id, cache_idx;
        char cache_path[512];

        if (sscanf(cpu_de->d_name, "cpu%d", &cpu_num) != 1)
            continue;

        snprintf(path, sizeof(path),
                 "/sys/devices/system/cpu/%s/topology/physical_package_id",
                 cpu_de->d_name);
        _sysfs_read(path, pkg_id, sizeof(pkg_id));
        if (!pkg_id[0])
            continue;
        phys_id = atoi(pkg_id);
        if (phys_id < 0 || phys_id >= 64 || seen_pkg[phys_id])
            continue;
        seen_pkg[phys_id] = 1;

        snprintf(cache_path, sizeof(cache_path),
                 "/sys/devices/system/cpu/%s/cache", cpu_de->d_name);
        cache_dir = opendir(cache_path);
        if (!cache_dir)
            continue;

        while ((cache_de = readdir(cache_dir))) {
            char type[32], size[32];
            int level;
            netsnmp_entity_info *e;

            if (sscanf(cache_de->d_name, "index%d", &cache_idx) != 1)
                continue;

            snprintf(path, sizeof(path), "%s/%s/level", cache_path, cache_de->d_name);
            _sysfs_read(path, level_s, sizeof(level_s));
            if (!level_s[0])
                continue;
            level = atoi(level_s);

            snprintf(path, sizeof(path), "%s/%s/type", cache_path, cache_de->d_name);
            _sysfs_read(path, type, sizeof(type));

            snprintf(path, sizeof(path), "%s/%s/size", cache_path, cache_de->d_name);
            _sysfs_read(path, size, sizeof(size));

            e = netsnmp_entity_create(IDX_CACHE_BASE + phys_id * 10 + cache_idx);
            if (!e)
                continue;

            e->iana_class = IANA_PHYS_OTHER;
            e->parent_idx = IDX_CPU_CACHE_CONTAINER_BASE + phys_id;
            e->parent_rel_pos = cache_idx;
            e->is_fru     = TV_FALSE;
            snprintf(e->uris, sizeof(e->uris), "file://%s/%s",
                     cache_path, cache_de->d_name);

            if (strcmp(type, "Unified") == 0)
                snprintf(e->name,  sizeof(e->name),  "L%d-cache", level);
            else if (strcmp(type, "Data") == 0)
                snprintf(e->name,  sizeof(e->name),  "L%d-cache-data", level);
            else if (strcmp(type, "Instruction") == 0)
                snprintf(e->name,  sizeof(e->name),  "L%d-cache-instr", level);
            else
                snprintf(e->name,  sizeof(e->name),  "L%d-cache", level);

            if (strcmp(type, "Unified") == 0)
                snprintf(e->descr, sizeof(e->descr), "L%d cache %s", level, size);
            else
                snprintf(e->descr, sizeof(e->descr), "L%d %s cache %s",
                         level, type, size);

            strlcpy(e->model_name, size, sizeof(e->model_name));
        }
        closedir(cache_dir);
    }
    closedir(cpu_dir);
}

/* ---- Phase 5: PCI devices ------------------------------------------------ */

static int
_cmp_bdf(const void *a, const void *b)
{
    char * const *sa = (char * const *)a;
    char * const *sb = (char * const *)b;
    return strcmp(*sa, *sb);
}

static int
_pci_bdf_parts(const char *bdf, unsigned int *domain, unsigned int *bus,
               unsigned int *device, unsigned int *function)
{
    if (sscanf(bdf, "%x:%x:%x.%x", domain, bus, device, function) != 4)
        return 0;
    return *domain <= 0xffff && *bus <= 0xff && *device <= 0x1f &&
           *function <= 0x7;
}

static int
_pci_bdf_parent_rel_pos(const char *bdf)
{
    unsigned int domain, bus, device, function;

    if (!_pci_bdf_parts(bdf, &domain, &bus, &device, &function))
        return -1;
    return (int)device;
}

static int
_pci_path_parent_function_rel_pos(const char *real_path)
{
    char path[PATH_MAX], *last, *parent;
    unsigned int domain, bus, device, function;

    if (!real_path || !real_path[0])
        return -1;

    strlcpy(path, real_path, sizeof(path));
    last = strrchr(path, '/');
    if (!last)
        return -1;
    *last = '\0';

    parent = strrchr(path, '/');
    parent = parent ? parent + 1 : path;
    if (!_pci_bdf_parts(parent, &domain, &bus, &device, &function))
        return -1;

    return (int)function;
}

static const char *
_pci_class_descr(long class_val)
{
    int base = (int)((class_val >> 16) & 0xFF);
    int sub  = (int)((class_val >>  8) & 0xFF);

    switch (base) {
    case 0x00:
        return sub == 0x01 ? "VGA-compatible device" : "Unclassified device";
    case 0x01:
        switch (sub) {
        case 0x00: return "SCSI controller";
        case 0x01: return "IDE controller";
        case 0x02: return "Floppy disk controller";
        case 0x04: return "RAID controller";
        case 0x06: return "SATA controller";
        case 0x08: return "NVM Express controller";
        default:   return "Storage controller";
        }
    case 0x02:
        switch (sub) {
        case 0x00: return "Ethernet controller";
        case 0x80: return "Network controller";
        default:   return "Network controller";
        }
    case 0x03:
        return sub == 0x00 ? "VGA-compatible controller" : "Display controller";
    case 0x04:
        switch (sub) {
        case 0x00: return "Multimedia video controller";
        case 0x01: return "Multimedia audio controller";
        case 0x03: return "Audio device";
        default:   return "Multimedia controller";
        }
    case 0x05:
        switch (sub) {
        case 0x00: return "RAM memory";
        case 0x01: return "Flash memory";
        default:   return "Memory controller";
        }
    case 0x06:
        switch (sub) {
        case 0x00: return "Host bridge";
        case 0x01: return "ISA bridge";
        case 0x02: return "EISA bridge";
        case 0x04: return "PCI bridge";
        case 0x05: return "PCMCIA bridge";
        case 0x07: return "CardBus bridge";
        case 0x09: return "PCI-E to PCI bridge";
        default:   return "Bridge";
        }
    case 0x07:
        switch (sub) {
        case 0x00: return "Serial controller";
        case 0x01: return "Parallel controller";
        case 0x03: return "Modem";
        default:   return "Communication controller";
        }
    case 0x08:
        switch (sub) {
        case 0x00: return "PIC";
        case 0x01: return "DMA controller";
        case 0x02: return "Timer";
        case 0x03: return "RTC";
        case 0x05: return "SD host controller";
        case 0x06: return "IOMMU";
        case 0x80: return "System peripheral";
        default:   return "System peripheral";
        }
    case 0x09:
        switch (sub) {
        case 0x00: return "Keyboard controller";
        case 0x02: return "Mouse controller";
        default:   return "Input device";
        }
    case 0x0a: return "Docking station";
    case 0x0b: return "Processor";
    case 0x0c:
        switch (sub) {
        case 0x00: return "FireWire controller";
        case 0x03: return "USB controller";
        case 0x05: return "SMBus controller";
        case 0x07: return "IPMI interface";
        default:   return "Serial bus controller";
        }
    case 0x0d:
        switch (sub) {
        case 0x00: return "iRDA controller";
        case 0x11: return "Bluetooth controller";
        case 0x12: return "Broadband controller";
        case 0x20: return "802.11a controller";
        case 0x21: return "802.11b controller";
        default:   return "Wireless controller";
        }
    case 0x0e: return "Intelligent controller";
    case 0x0f: return "Satellite communications controller";
    case 0x10: return "Encryption controller";
    case 0x11:
        switch (sub) {
        case 0x00: return "DPIO module";
        case 0x01: return "Performance counters";
        default:   return "Signal processing controller";
        }
    default: return NULL;
    }
}

static int
_pci_class_to_iana(long class_val)
{
    int base = (int)((class_val >> 16) & 0xFF);
    int sub  = (int)((class_val >>  8) & 0xFF);

    switch (base) {
    case 0x02:                          /* Network controller */
    case 0x0d:                          /* Wireless controller */
        return IANA_PHYS_MODULE;
    case 0x06:                          /* Bridge */
        if (sub == 0x00)
            return IANA_PHYS_BACKPLANE; /* Host bridge / root complex */
        return IANA_PHYS_CONTAINER;     /* PCI-PCI, CardBus, etc. */
    case 0x0b:                          /* Processor */
        return IANA_PHYS_CPU;
    default:
        return IANA_PHYS_MODULE;
    }
}

static int
_pci_class_is_network(long class_val)
{
    int base = (int)((class_val >> 16) & 0xFF);

    return base == 0x02 || base == 0x0d;
}

typedef struct pci_entity_map_s {
    char bdf[16];
    char key[128];
    int idx;
    char real_path[PATH_MAX];
} pci_entity_map;

static int
_pci_find_idx(pci_entity_map *map, int nmap, const char *bdf)
{
    int i;

    for (i = 0; i < nmap; i++)
        if (strcmp(map[i].bdf, bdf) == 0)
            return map[i].idx;
    return 0;
}

static int
_pci_function0_idx(pci_entity_map *map, int nmap, const char *bdf)
{
    char func0[16];
    unsigned int domain, bus, device, function;

    if (!_pci_bdf_parts(bdf, &domain, &bus, &device, &function))
        return 0;
    snprintf(func0, sizeof(func0), "%04x:%02x:%02x.0", domain, bus, device);
    return _pci_find_idx(map, nmap, func0);
}

static int
_pci_canonical_idx(pci_entity_map *map, int nmap, int idx)
{
    int i, func0_idx;
    netsnmp_entity_info *e;

    e = netsnmp_entity_get_byIdx(idx);
    if (!e || !e->hidden)
        return idx;

    for (i = 0; i < nmap; i++) {
        if (map[i].idx != idx)
            continue;
        func0_idx = _pci_function0_idx(map, nmap, map[i].bdf);
        return func0_idx ? func0_idx : idx;
    }
    return idx;
}

static int
_pci_find_parent_idx(pci_entity_map *map, int nmap, int child)
{
    int i, parent_idx, best_len;
    size_t child_len;

    parent_idx = 0;
    best_len = 0;
    if (!map[child].real_path[0])
        return 0;

    child_len = strlen(map[child].real_path);
    for (i = 0; i < nmap; i++) {
        int len;

        if (i == child || !map[i].real_path[0])
            continue;
        len = strlen(map[i].real_path);
        if ((size_t)len >= child_len || len <= best_len)
            continue;
        if (strncmp(map[child].real_path, map[i].real_path, len) == 0 &&
            map[child].real_path[len] == '/') {
            best_len = len;
            parent_idx = _pci_canonical_idx(map, nmap, map[i].idx);
        }
    }
    return parent_idx;
}

/* Find the deepest PCI node matching or containing `path`.
 * Class devices can resolve either to the PCI function itself (net) or to a
 * child below it (PTP, storage, TPM, etc.). */
static int
_pci_find_idx_by_path(pci_entity_map *map, int nmap, const char *path)
{
    int i, best_idx = 0, best_len = 0;
    size_t plen = strlen(path);

    for (i = 0; i < nmap; i++) {
        int mlen = (int)strlen(map[i].real_path);
        if (mlen <= best_len || (size_t)mlen > plen)
            continue;
        if (strncmp(path, map[i].real_path, mlen) == 0 &&
            (path[mlen] == '\0' || path[mlen] == '/')) {
            best_len = mlen;
            best_idx = _pci_canonical_idx(map, nmap, map[i].idx);
        }
    }
    return best_idx;
}

/* Ordered highest speed first so truncated descriptions keep the best modes.
 * Sentinel: bit == -1.  Works with both ETHTOOL_GLINKSETTINGS and the
 * legacy ETHTOOL_GSET fallback (bits 0-30 fit in the u32 supported field). */
static const struct { int bit; const char *name; } _nic_link_modes[] = {
    { ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT,       "200000baseKR4/Full"    },
    { ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT,       "200000baseSR4/Full"    },
    { ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT, "200000baseLR4_ER4_FR4/Full" },
    { ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT,       "200000baseDR4/Full"    },
    { ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT,       "200000baseCR4/Full"    },
    { ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT,       "100000baseKR4/Full"    },
    { ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT,       "100000baseSR4/Full"    },
    { ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT,       "100000baseCR4/Full"    },
    { ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT,   "100000baseLR4_ER4/Full"},
    { ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT,       "100000baseKR2/Full"    },
    { ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT,       "100000baseSR2/Full"    },
    { ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT,       "100000baseCR2/Full"    },
    { ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT, "100000baseLR2_ER2_FR2/Full" },
    { ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT,       "100000baseDR2/Full"    },
    { ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT,        "56000baseKR4/Full"     },
    { ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT,        "56000baseCR4/Full"     },
    { ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT,        "56000baseSR4/Full"     },
    { ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT,        "56000baseLR4/Full"     },
    { ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT,        "50000baseCR2/Full"     },
    { ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT,        "50000baseKR2/Full"     },
    { ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT,        "50000baseSR2/Full"     },
    { ETHTOOL_LINK_MODE_50000baseKR_Full_BIT,         "50000baseKR/Full"      },
    { ETHTOOL_LINK_MODE_50000baseSR_Full_BIT,         "50000baseSR/Full"      },
    { ETHTOOL_LINK_MODE_50000baseCR_Full_BIT,         "50000baseCR/Full"      },
    { ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT,   "50000baseLR_ER_FR/Full"},
    { ETHTOOL_LINK_MODE_50000baseDR_Full_BIT,         "50000baseDR/Full"      },
    { ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT,        "40000baseKR4/Full"     },
    { ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,        "40000baseCR4/Full"     },
    { ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT,        "40000baseSR4/Full"     },
    { ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT,        "40000baseLR4/Full"     },
    { ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,         "25000baseCR/Full"      },
    { ETHTOOL_LINK_MODE_25000baseKR_Full_BIT,         "25000baseKR/Full"      },
    { ETHTOOL_LINK_MODE_25000baseSR_Full_BIT,         "25000baseSR/Full"      },
    { ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT,       "20000baseMLD2/Full"    },
    { ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT,        "20000baseKR2/Full"     },
    { ETHTOOL_LINK_MODE_10000baseT_Full_BIT,          "10000baseT/Full"       },
    { ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT,        "10000baseKX4/Full"     },
    { ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,         "10000baseKR/Full"      },
    { ETHTOOL_LINK_MODE_10000baseCR_Full_BIT,         "10000baseCR/Full"      },
    { ETHTOOL_LINK_MODE_10000baseSR_Full_BIT,         "10000baseSR/Full"      },
    { ETHTOOL_LINK_MODE_10000baseLR_Full_BIT,         "10000baseLR/Full"      },
    { ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT,        "10000baseLRM/Full"     },
    { ETHTOOL_LINK_MODE_10000baseER_Full_BIT,         "10000baseER/Full"      },
    { ETHTOOL_LINK_MODE_5000baseT_Full_BIT,           "5000baseT/Full"        },
    { ETHTOOL_LINK_MODE_2500baseX_Full_BIT,           "2500baseX/Full"        },
    { ETHTOOL_LINK_MODE_2500baseT_Full_BIT,           "2500baseT/Full"        },
    { ETHTOOL_LINK_MODE_1000baseT_Full_BIT,           "1000baseT/Full"        },
    { ETHTOOL_LINK_MODE_1000baseT_Half_BIT,           "1000baseT/Half"        },
    { ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,          "1000baseKX/Full"       },
    { ETHTOOL_LINK_MODE_1000baseX_Full_BIT,           "1000baseX/Full"        },
    { ETHTOOL_LINK_MODE_100baseT_Full_BIT,            "100baseT/Full"         },
    { ETHTOOL_LINK_MODE_100baseT_Half_BIT,            "100baseT/Half"         },
    { ETHTOOL_LINK_MODE_10baseT_Full_BIT,             "10baseT/Full"          },
    { ETHTOOL_LINK_MODE_10baseT_Half_BIT,             "10baseT/Half"          },
    { -1, NULL }
};

static const char *
_arphrd_descr(int arphrd)
{
    switch (arphrd) {
    case 1:   return "Ethernet interface";          /* ARPHRD_ETHER */
    case 24:  return "IEEE1394 interface";          /* ARPHRD_IEEE1394 */
    case 32:  return "InfiniBand interface";        /* ARPHRD_INFINIBAND */
    case 256: return "SLIP interface";              /* ARPHRD_SLIP */
    case 512: return "PPP interface";               /* ARPHRD_PPP */
    case 768: return "IP tunnel interface";         /* ARPHRD_TUNNEL */
    case 769: return "IPv6 tunnel interface";       /* ARPHRD_TUNNEL6 */
    case 772: return "Loopback network interface";  /* ARPHRD_LOOPBACK */
    case 774: return "FDDI interface";              /* ARPHRD_FDDI */
    case 776: return "IPv6-in-IPv4 interface";      /* ARPHRD_SIT */
    case 783: return "IRDA interface";              /* ARPHRD_IRDA */
    default:  return NULL;
    }
}

static void
_nic_scan_ethtool(netsnmp_entity_info *e, const char *ifname, int sfp_idx)
{
    int fd;
    struct ifreq ifr;
    struct ethtool_drvinfo drvinfo;
    struct ethtool_cmd ecmd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return;

    /* Firmware version and driver info */
    memset(&drvinfo, 0, sizeof(drvinfo));
    drvinfo.cmd = ETHTOOL_GDRVINFO;
    memset(&ifr, 0, sizeof(ifr));
    strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
    ifr.ifr_data = (void *)&drvinfo;
    if (ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
        if (drvinfo.fw_version[0]) {
            char tmp[sizeof(e->fw_rev)];
            strlcpy(tmp, drvinfo.fw_version, sizeof(tmp));
            _trim_trailing(tmp);
            if (tmp[0])
                strlcpy(e->fw_rev, tmp, sizeof(e->fw_rev));
        }
        if (drvinfo.driver[0]) {
            if (drvinfo.version[0])
                snprintf(e->sw_rev, sizeof(e->sw_rev), "%s %s",
                         drvinfo.driver, drvinfo.version);
            else
                strlcpy(e->sw_rev, drvinfo.driver, sizeof(e->sw_rev));
        }
    }

    /* Port type and supported link modes appended to description.
     * Try ETHTOOL_GLINKSETTINGS (extended bitmask) first, fall back to
     * the legacy ETHTOOL_GSET which exposes only bits 0-30. */
    {
        struct {
            struct ethtool_link_settings s;
            __u32 buf[3 * 8]; /* 8 words × 32 bits = 256 mode bits per mask */
        } req;
        const __u32 *sup_words;
        int sup_nwords;
        __u8 port;
        const char *port_s;
        char modes_buf[192];
        int first;

        sup_words  = NULL;
        sup_nwords = 0;
        port       = PORT_OTHER;
        port_s     = NULL;
        modes_buf[0] = '\0';
        first = 1;

        /* Probe: kernel returns negated required nwords */
        memset(&req, 0, sizeof(req));
        req.s.cmd = ETHTOOL_GLINKSETTINGS;
        memset(&ifr, 0, sizeof(ifr));
        strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
        ifr.ifr_data = (void *)&req;
        if (ioctl(fd, SIOCETHTOOL, &ifr) == 0 &&
            req.s.link_mode_masks_nwords < 0) {
            __s8 n = -req.s.link_mode_masks_nwords;
            if (n > 0 && n <= 8) {
                req.s.cmd = ETHTOOL_GLINKSETTINGS;
                req.s.link_mode_masks_nwords = n;
                memset(&ifr, 0, sizeof(ifr));
                strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
                ifr.ifr_data = (void *)&req;
                if (ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
                    sup_words  = req.buf; /* supported is first nwords */
                    sup_nwords = n;
                    port       = req.s.port;
                }
            }
        }

        /* Legacy fallback: pack the u32 bitmask into buf[0] */
        if (!sup_words) {
            memset(&ecmd, 0, sizeof(ecmd));
            ecmd.cmd = ETHTOOL_GSET;
            memset(&ifr, 0, sizeof(ifr));
            strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
            ifr.ifr_data = (void *)&ecmd;
            if (ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
                req.buf[0] = ecmd.supported;
                sup_words  = req.buf;
                sup_nwords = 1;
                port       = ecmd.port;
            }
        }

        if (sup_words) {
            char base[sizeof(e->descr)];
            int mi;
            switch (port) {
            case PORT_TP:    port_s = "twisted pair";  break;
            case PORT_AUI:   port_s = "AUI";           break;
            case PORT_MII:   port_s = "MII";           break;
            case PORT_FIBRE: port_s = "fibre";         break;
            case PORT_BNC:   port_s = "BNC";           break;
            case PORT_DA:    port_s = "direct attach"; break;
            default:         break;
            }

            for (mi = 0; _nic_link_modes[mi].bit >= 0; mi++) {
                int bit  = _nic_link_modes[mi].bit;
                int word = bit / 32;
                if (word >= sup_nwords)
                    continue;
                if (!((sup_words[word] >> (bit % 32)) & 1u))
                    continue;
                if (!first)
                    strlcat(modes_buf, " ", sizeof(modes_buf));
                strlcat(modes_buf, _nic_link_modes[mi].name, sizeof(modes_buf));
                first = 0;
            }

            if (port_s) {
                if (e->model_name[0]) {
                    strlcat(e->model_name, " (", sizeof(e->model_name));
                    strlcat(e->model_name, port_s, sizeof(e->model_name));
                    strlcat(e->model_name, ")", sizeof(e->model_name));
                } else {
                    strlcpy(e->model_name, port_s, sizeof(e->model_name));
                }
            }

            strlcpy(base, e->descr, sizeof(base));
            if (modes_buf[0])
                snprintf(e->descr, sizeof(e->descr), "%s (%s)", base, modes_buf);
        }
    }

    /* SFP/transceiver submodule */
    {
        struct ethtool_modinfo modinfo;
        struct {
            __u32 cmd;
            __u32 magic;
            __u32 offset;
            __u32 len;
            __u8  data[256];
        } eeeprom;

        memset(&modinfo, 0, sizeof(modinfo));
        modinfo.cmd = ETHTOOL_GMODULEINFO;
        memset(&ifr, 0, sizeof(ifr));
        strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
        ifr.ifr_data = (void *)&modinfo;
        if (ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
            __u32 elen = modinfo.eeprom_len;
            if (elen > 256) elen = 256;

            memset(&eeeprom, 0, sizeof(eeeprom));
            eeeprom.cmd    = ETHTOOL_GMODULEEEPROM;
            eeeprom.offset = 0;
            eeeprom.len    = elen;
            memset(&ifr, 0, sizeof(ifr));
            strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);
            ifr.ifr_data = (void *)&eeeprom;

            if (ioctl(fd, SIOCETHTOOL, &ifr) == 0) {
                netsnmp_entity_info *sfp;
                sfp = netsnmp_entity_create(sfp_idx);
                if (sfp) {
                    const char *id_s, *conn_s = NULL;
                    char part[17], sfpdescr[80];
                    const __u8 *d = eeeprom.data;

                    sfp->iana_class = IANA_PHYS_MODULE;
                    sfp->parent_idx = e->idx;
                    sfp->is_fru     = TV_TRUE;

                    switch (d[0]) {         /* identifier byte */
                    case 0x02: id_s = "SFP";    break;
                    case 0x03: id_s = "SFP+";   break;
                    case 0x0c: id_s = "QSFP";   break;
                    case 0x0d: id_s = "QSFP+";  break;
                    case 0x11: id_s = "QSFP28"; break;
                    default:   id_s = "module";  break;
                    }

                    switch (d[2]) {         /* connector byte */
                    case 0x01: conn_s = "SC";             break;
                    case 0x07: conn_s = "LC";             break;
                    case 0x0b: conn_s = "optical pigtail"; break;
                    case 0x21: conn_s = "copper pigtail"; break;
                    case 0x22: conn_s = "RJ45";           break;
                    case 0x23: conn_s = "non-separable";  break;
                    }

                    if (conn_s)
                        snprintf(sfpdescr, sizeof(sfpdescr),
                                 "%s transceiver (%s)", id_s, conn_s);
                    else
                        snprintf(sfpdescr, sizeof(sfpdescr),
                                 "%s transceiver", id_s);
                    strlcpy(sfp->descr, sfpdescr, sizeof(sfp->descr));

                    /* Part number: bytes 40-55, ASCII space-padded */
                    memcpy(part, d + 40, 16);
                    part[16] = '\0';
                    _trim_trailing(part);
                    if (part[0])
                        strlcpy(sfp->model_name, part, sizeof(sfp->model_name));

                    /* Wavelength (nm) in hw_rev if non-zero (copper DAC = 0) */
                    {
                        int wl = ((int)d[60] << 8) | d[61];
                        if (wl > 0) {
                            char wl_s[16];
                            snprintf(wl_s, sizeof(wl_s), "%dnm", wl);
                            strlcpy(sfp->hw_rev, wl_s, sizeof(sfp->hw_rev));
                        }
                    }
                }
            }
        }
    }

    close(fd);
}

static void
_load_pci(pci_entity_map **map_out, int *nmap_out)
{
    DIR *dir;
    struct dirent *de;
    char path[512], val[256];
    char **bdfs = NULL, **tmp;
    int   nbdfs = 0, cap = 0, i;
    pci_entity_map *map;
    netsnmp_entity_info *e;
#ifdef HAVE_PCI_LOOKUP_NAME
    char namebuf[256];
    struct pci_access *pacc;
#endif

    *map_out = NULL;
    *nmap_out = 0;

    dir = opendir(PCI_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir))) {
        if (de->d_name[0] == '.')
            continue;
        if (strlen(de->d_name) != 12)
            continue;

        if (nbdfs >= cap) {
            cap = cap ? cap * 2 : 64;
            tmp = (char **)realloc(bdfs, cap * sizeof(char *));
            if (!tmp) break;
            bdfs = tmp;
        }
        bdfs[nbdfs] = strdup(de->d_name);
        if (bdfs[nbdfs]) nbdfs++;
    }
    closedir(dir);

    if (!nbdfs) {
        free(bdfs);
        return;
    }

    qsort(bdfs, nbdfs, sizeof(bdfs[0]), _cmp_bdf);

    map = (pci_entity_map *)calloc(nbdfs, sizeof(*map));
    if (!map)
        goto free_bdfs;

#ifdef HAVE_PCI_LOOKUP_NAME
    pacc = pci_alloc();
    if (pacc)
        pci_init(pacc);
#endif

    for (i = 0; i < nbdfs; i++) {
        long         class_val;
        unsigned int vid, did;
        int          idx, slot_idx;
#ifdef HAVE_PCI_LOOKUP_NAME
        char        *lname;
#endif

        class_val = 0;
        vid = did = 0;
        slot_idx = 0;
        idx = IDX_PCI_BASE + i + 1;

        strlcpy(map[i].bdf, bdfs[i], sizeof(map[i].bdf));
        map[i].idx = idx;
        snprintf(path, sizeof(path), "%s/%s", PCI_PATH, bdfs[i]);
        if (!realpath(path, map[i].real_path))
            map[i].real_path[0] = '\0';

        snprintf(path, sizeof(path), "%s/%s/class", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            class_val = strtol(val, NULL, 16);

        if (_pci_class_is_network(class_val)) {
            snprintf(map[i].key, sizeof(map[i].key), "pcislot:%.*s",
                     10, bdfs[i]);
            slot_idx = _entity_index_alloc(map[i].key);
            if (slot_idx > 0)
                idx = slot_idx;
        } else {
            snprintf(map[i].key, sizeof(map[i].key), "pci:%s", bdfs[i]);
        }

        map[i].idx = idx;

        e = netsnmp_entity_get_byIdx(idx);
        if (!e) {
            e = netsnmp_entity_create(idx);
            if (!e) goto free_bdf;

            e->iana_class = IANA_PHYS_MODULE;
            e->parent_idx = IDX_BASEBOARD;
            strlcpy(e->name, bdfs[i], sizeof(e->name));
            strlcpy(e->descr, bdfs[i], sizeof(e->descr));
        }

        if (slot_idx == 0 && class_val)
            e->iana_class = _pci_class_to_iana(class_val);

        snprintf(path, sizeof(path), "%s/%s", PCI_PATH, bdfs[i]);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        if (map[i].real_path[0] && strcmp(map[i].real_path, path) != 0)
            _append_file_uri(e->uris, sizeof(e->uris), map[i].real_path);
        _append_uri(e->uris, sizeof(e->uris), map[i].key);

        snprintf(path, sizeof(path), "%s/%s/vendor", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            vid = (unsigned int)strtoul(val, NULL, 16);

        snprintf(path, sizeof(path), "%s/%s/device", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            did = (unsigned int)strtoul(val, NULL, 16);

        /* Vendor name */
        if (vid) {
#ifdef HAVE_PCI_LOOKUP_NAME
            lname = pacc ? pci_lookup_name(pacc, namebuf, sizeof(namebuf),
                                           PCI_LOOKUP_VENDOR |
                                           PCI_LOOKUP_NO_NUMBERS,
                                           vid) : NULL;
            if (lname && lname[0])
                strlcpy(e->mfg_name, lname, sizeof(e->mfg_name));
            else
#endif
                snprintf(e->mfg_name, sizeof(e->mfg_name), "0x%04x", vid);
        }

        /* Device / product name */
        if (vid && did) {
#ifdef HAVE_PCI_LOOKUP_NAME
            lname = pacc ? pci_lookup_name(pacc, namebuf, sizeof(namebuf),
                                           PCI_LOOKUP_DEVICE |
                                           PCI_LOOKUP_NO_NUMBERS,
                                           vid, did) : NULL;
            if (lname && lname[0])
                strlcpy(e->model_name, lname, sizeof(e->model_name));
            else
#endif
                snprintf(e->model_name, sizeof(e->model_name), "0x%04x", did);
        }

        /* Description: PCI class name, with full PCI product retained in model_name. */
        if (class_val) {
            const char *descr = NULL;
#ifdef HAVE_PCI_LOOKUP_NAME
            int cls_sub = (int)((class_val >> 8) & 0xFFFF);
            lname = pacc ? pci_lookup_name(pacc, namebuf, sizeof(namebuf),
                                           PCI_LOOKUP_CLASS |
                                           PCI_LOOKUP_NO_NUMBERS,
                                           cls_sub) : NULL;
            if (lname) {
                /* trim libpci result — some builds return whitespace on miss */
                while (*lname == ' ' || *lname == '\t')
                    lname++;
                if (lname[0])
                    descr = lname;
            }
#endif
            if (!descr)
                descr = _pci_class_descr(class_val);
            if (descr)
                strlcpy(e->descr, descr, sizeof(e->descr));
        }

        /* Revision */
        snprintf(path, sizeof(path), "%s/%s/revision", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            strlcpy(e->hw_rev, val, sizeof(e->hw_rev));

        /* PCIe link speed and width appended to the concise description. */
        {
            char speed[64] = "", width[16] = "";
            snprintf(path, sizeof(path), "%s/%s/current_link_speed",
                     PCI_PATH, bdfs[i]);
            _sysfs_read(path, speed, sizeof(speed));
            snprintf(path, sizeof(path), "%s/%s/current_link_width",
                     PCI_PATH, bdfs[i]);
            _sysfs_read(path, width, sizeof(width));
            if (speed[0] && width[0]) {
                char base[sizeof(e->descr)];
                strlcpy(base, e->descr, sizeof(base));
                if (base[0])
                    snprintf(e->descr, sizeof(e->descr), "%s, x%s %s",
                             base, width, speed);
                else
                    snprintf(e->descr, sizeof(e->descr), "x%s %s",
                             width, speed);
            }
        }

        /* Bound driver → sw_rev */
        {
            char link[512];
            ssize_t llen;
            snprintf(path, sizeof(path), "%s/%s/driver", PCI_PATH, bdfs[i]);
            llen = readlink(path, link, sizeof(link) - 1);
            if (llen > 0) {
                char *drv;
                link[llen] = '\0';
                drv = strrchr(link, '/');
                strlcpy(e->sw_rev, drv ? drv + 1 : link, sizeof(e->sw_rev));
            }
        }

free_bdf:
        free(bdfs[i]);
    }

    for (i = 0; i < nbdfs; i++) {
        int parent_idx;
        unsigned int domain, bus, device, function;

        e = netsnmp_entity_get_byIdx(map[i].idx);
        if (!e)
            continue;

        if (_pci_bdf_parts(map[i].bdf, &domain, &bus, &device, &function) &&
            function > 0) {
            parent_idx = _pci_function0_idx(map, nbdfs, map[i].bdf);
            if (parent_idx > 0 && parent_idx != map[i].idx) {
                e->hidden = 1;
                e->parent_idx = parent_idx;
                e->parent_rel_pos = (int)function;
                continue;
            }
        }

        parent_idx = _pci_find_parent_idx(map, nbdfs, i);
        if (!parent_idx && strncmp(map[i].bdf + 5, "00:", 3) == 0 &&
            strcmp(map[i].bdf + 8, "00.0") != 0) {
            char root_bdf[16];

            snprintf(root_bdf, sizeof(root_bdf), "%.4s:00:00.0", map[i].bdf);
            parent_idx = _pci_find_idx(map, nbdfs, root_bdf);
        }
        if (!parent_idx) {
            int node = _numa_pci_node(map[i].bdf);

            if (node >= 0)
                parent_idx = _numa_node_idx(node);
        }
        e->parent_idx = parent_idx ? parent_idx : IDX_BASEBOARD;
        e->parent_rel_pos = _pci_path_parent_function_rel_pos(map[i].real_path);
        if (e->parent_rel_pos < 0)
            e->parent_rel_pos = _pci_bdf_parent_rel_pos(map[i].bdf);
    }

#ifdef HAVE_PCI_LOOKUP_NAME
    if (pacc)
        pci_cleanup(pacc);
#endif

    *map_out = map;
    *nmap_out = nbdfs;
    free(bdfs);
    return;

free_bdfs:
    for (i = 0; i < nbdfs; i++)
        free(bdfs[i]);
    free(bdfs);
}

static void
_usb_class_info(const char *name, int *class_out, int *sub_out, int *prot_out)
{
    char path[512], val[16];
    int cls, sub, prot;
    DIR *dir;
    struct dirent *de;

    cls = -1;
    sub = 0;
    prot = 0;

    /* Read bDeviceClass; 0x00 means class is defined per-interface */
    snprintf(path, sizeof(path), "%s/%s/bDeviceClass", USB_PATH, name);
    _sysfs_read(path, val, sizeof(val));
    cls = val[0] ? (int)strtol(val, NULL, 16) : -1;

    snprintf(path, sizeof(path), "%s/%s/bDeviceSubClass", USB_PATH, name);
    _sysfs_read(path, val, sizeof(val));
    sub = val[0] ? (int)strtol(val, NULL, 16) : 0;

    snprintf(path, sizeof(path), "%s/%s/bDeviceProtocol", USB_PATH, name);
    _sysfs_read(path, val, sizeof(val));
    prot = val[0] ? (int)strtol(val, NULL, 16) : 0;

    if (cls == 0x00) {
        /* Scan for the first interface entry and use its class tuple. */
        snprintf(path, sizeof(path), "%s", USB_PATH);
        dir = opendir(path);
        if (dir) {
            size_t nlen = strlen(name);

            while ((de = readdir(dir))) {
                /* Interface entries look like "1-2:1.0" */
                if (strncmp(de->d_name, name, nlen) == 0 &&
                    de->d_name[nlen] == ':') {
                    snprintf(path, sizeof(path), "%s/%s/bInterfaceClass",
                             USB_PATH, de->d_name);
                    _sysfs_read(path, val, sizeof(val));
                    if (val[0]) {
                        cls = (int)strtol(val, NULL, 16);
                        snprintf(path, sizeof(path),
                                 "%s/%s/bInterfaceSubClass", USB_PATH,
                                 de->d_name);
                        _sysfs_read(path, val, sizeof(val));
                        sub = val[0] ? (int)strtol(val, NULL, 16) : 0;
                        snprintf(path, sizeof(path),
                                 "%s/%s/bInterfaceProtocol", USB_PATH,
                                 de->d_name);
                        _sysfs_read(path, val, sizeof(val));
                        prot = val[0] ? (int)strtol(val, NULL, 16) : 0;
                        closedir(dir);
                        goto done;
                    }
                }
            }
            closedir(dir);
        }
    }

done:
    if (class_out)
        *class_out = cls;
    if (sub_out)
        *sub_out = sub;
    if (prot_out)
        *prot_out = prot;
}

static int
_usb_iana_class(const char *name)
{
    int cls;

    _usb_class_info(name, &cls, NULL, NULL);
    switch (cls) {
    case 0x09: return IANA_PHYS_CONTAINER;  /* Hub          */
    default:   return IANA_PHYS_OTHER;
    }
}

static void
_usb_speed_descr(const char *speed, char *buf, size_t bufsz)
{
    int spd;

    if (bufsz > 0)
        buf[0] = '\0';
    if (!speed || !speed[0] || bufsz == 0)
        return;

    spd = atoi(speed);
    if (spd <= 0)
        return;

    if (spd >= 1000 && spd % 1000 == 0)
        snprintf(buf, bufsz, "%d Gbit/s", spd / 1000);
    else
        snprintf(buf, bufsz, "%d Mbit/s", spd);
}

static int
_usb_parent_idx_from_path(const char *rp)
{
    char path[PATH_MAX], *saveptr, *part;
    int after_usb_host, parent_idx;

    if (!rp || !rp[0])
        return 0;

    strlcpy(path, rp, sizeof(path));
    after_usb_host = 0;
    parent_idx = 0;
    for (part = strtok_r(path, "/", &saveptr); part;
         part = strtok_r(NULL, "/", &saveptr)) {
        char key[128];

        if (after_usb_host && strchr(part, '-') && !strchr(part, ':')) {
            snprintf(key, sizeof(key), "usb:%s", part);
            parent_idx = _entity_index_alloc(key);
        }
        after_usb_host = strncmp(part, "usb", 3) == 0 &&
            isdigit((unsigned char)part[3]);
    }
    return parent_idx;
}

static int
_usb_parent_idx_from_name(const char *name, const char *busnum)
{
    char parent[128], key[128], *dot;

    if (!name || !name[0])
        return 0;

    strlcpy(parent, name, sizeof(parent));
    dot = strrchr(parent, '.');
    if (dot && strchr(parent, '-')) {
        *dot = '\0';
        snprintf(key, sizeof(key), "usb:%s", parent);
        return _entity_index_alloc(key);
    }

    if (busnum && busnum[0]) {
        snprintf(key, sizeof(key), "usbhost:%s", busnum);
        return _entity_index_alloc(key);
    }

    return 0;
}

static int
_usb_parent_rel_pos_from_name(const char *name, const char *busnum)
{
    char path[512], devnum[32];
    const char *p;

    if (!name || !name[0])
        return ENTITY_PARENT_REL_POS_AUTO;

    if (strncmp(name, "usb", 3) == 0 && isdigit((unsigned char)name[3]))
        return atoi(name + 3);

    snprintf(path, sizeof(path), "%s/%s/devnum", USB_PATH, name);
    _sysfs_read(path, devnum, sizeof(devnum));
    if (devnum[0])
        return atoi(devnum);

    p = strrchr(name, '.');
    if (!p)
        p = strrchr(name, '-');
    if (p && isdigit((unsigned char)p[1]))
        return atoi(p + 1);

    return busnum && busnum[0] ? atoi(busnum) : ENTITY_PARENT_REL_POS_AUTO;
}

static const char *
_usb_class_descr(const char *name)
{
    int cls, sub, prot;

    _usb_class_info(name, &cls, &sub, &prot);
    switch (cls) {
    case 0x01:
        return "Audio device";
    case 0x02:
        if (sub == 0x02)
            return "Modem";
        return "Communication device";
    case 0x03:
        if ((sub == 0x00 || sub == 0x01) && prot == 0x01)
            return "Keyboard";
        if ((sub == 0x00 || sub == 0x01) && prot == 0x02)
            return "Mouse";
        return "Human interface device";
    case 0x07:
        return "Printer";
    case 0x08:
        return "Mass storage device";
    case 0x09:
        return "USB hub";
    case 0x0b:
        return "Smart card reader";
    case 0x0e:
        return "Video";
    case 0xe0:
        if (sub == 0x01 && prot == 0x01)
            return "Bluetooth wireless interface";
        return "Wireless interface";
    default:
        return "Generic USB device";
    }
}

/* ---- Phase 5: ATA ports -------------------------------------------------- */

static void
_load_ata_ports(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    const struct dirent *de;
    char path[512], rp[PATH_MAX];

    dir = opendir("/sys/class/ata_port");
    if (!dir)
        return;

    while ((de = readdir(dir))) {
        netsnmp_entity_info *e;
        int port, pci_idx;

        if (strncmp(de->d_name, "ata", 3) != 0)
            continue;
        port = atoi(de->d_name + 3);
        if (port <= 0)
            continue;

        e = netsnmp_entity_create(IDX_ATA_BASE + port);
        if (!e)
            continue;

        snprintf(path, sizeof(path), "/sys/class/ata_port/%s", de->d_name);
        pci_idx = realpath(path, rp) ? _pci_find_idx_by_path(pci_map, pci_map_n, rp) : 0;

        e->iana_class = IANA_PHYS_OTHER;
        e->is_fru     = TV_FALSE;
        e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;
        strlcpy(e->name, de->d_name, sizeof(e->name));

        {
            char spd[32];
            const char *type;
            FILE *fp;

            snprintf(path, sizeof(path),
                     "/sys/class/ata_link/link%d/sata_spd", port);
            fp = fopen(path, "r");
            if (fp) {
                type = "SATA";
                if (fgets(spd, sizeof(spd), fp)) {
                    spd[strcspn(spd, "\n")] = '\0';
                } else {
                    spd[0] = '\0';
                }
                fclose(fp);
            } else {
                type = "ATA";
                spd[0] = '\0';
            }

            if (spd[0] && strcmp(spd, "<unknown>") != 0)
                snprintf(e->descr, sizeof(e->descr),
                         "%s port %d (%s)", type, port, spd);
            else
                snprintf(e->descr, sizeof(e->descr), "%s port %d", type, port);
        }

        snprintf(path, sizeof(path), "ata:%d", port);
        _append_uri(e->uris, sizeof(e->uris), path);
    }
    closedir(dir);
}

/* ---- Phase 6: USB devices ------------------------------------------------ */

static void
_load_usb(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    const struct dirent *de;
    char path[512], val[256], rp[PATH_MAX];

    dir = opendir(USB_PATH);
    if (!dir)
        return;

    /* Pass 1: create root hub (usbhost) container entities */
    while ((de = readdir(dir))) {
        netsnmp_entity_info *e;
        const char *name = de->d_name;
        char ver[16], spd_s[16], spd_descr[32], key[128];
        int idx, pci_idx, i;

        if (name[0] == '.')
            continue;
        if (strncmp(name, "usb", 3) != 0 || !isdigit((unsigned char)name[3]))
            continue;

        snprintf(path, sizeof(path), "%s/%s", USB_PATH, name);
        if (!realpath(path, rp))
            continue;

        snprintf(key, sizeof(key), "usbhost:%s", name + 3);
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        pci_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        snprintf(path, sizeof(path), "%s/%s/version", USB_PATH, name);
        _sysfs_read(path, ver, sizeof(ver));
        snprintf(path, sizeof(path), "%s/%s/speed", USB_PATH, name);
        _sysfs_read(path, spd_s, sizeof(spd_s));
        _usb_speed_descr(spd_s, spd_descr, sizeof(spd_descr));

        e->iana_class = IANA_PHYS_CONTAINER;
        e->is_fru     = TV_FALSE;
        e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;
        e->parent_rel_pos = _usb_parent_rel_pos_from_name(name, name + 3);
        strlcpy(e->name, name, sizeof(e->name));

        if (ver[0] && spd_descr[0]) {
            snprintf(e->descr, sizeof(e->descr), "USB %s host, %s",
                     ver, spd_descr);
        } else {
            strlcpy(e->descr, "USB host", sizeof(e->descr));
        }

        snprintf(path, sizeof(path), "usb:%s", name);
        _append_uri(e->uris, sizeof(e->uris), path);
        for (i = 0; i < pci_map_n; i++) {
            if (pci_map[i].idx != pci_idx)
                continue;
            snprintf(path, sizeof(path), "%s/%s/%s", PCI_PATH,
                     pci_map[i].bdf, name);
            _append_file_uri(e->uris, sizeof(e->uris), path);
            break;
        }
    }
    rewinddir(dir);

    /* Pass 2: create USB device entities as children of their root hub */
    while ((de = readdir(dir))) {
        netsnmp_entity_info *e;
        const char *name = de->d_name;
        const char *class_descr;
        char devname[128], speed[64], speed_descr[32], removable[64];
        char key[128], busnum[16];
        int idx, hub_idx;

        if (name[0] == '.')
            continue;
        if (strchr(name, ':'))
            continue;
        if (strncmp(name, "usb", 3) == 0 && isdigit((unsigned char)name[3]))
            continue;

        snprintf(path, sizeof(path), "%s/%s", USB_PATH, name);
        if (!realpath(path, rp))
            continue;

        snprintf(key, sizeof(key), "usb:%s", name);
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s/busnum", USB_PATH, name);
        _sysfs_read(path, busnum, sizeof(busnum));
        hub_idx = _usb_parent_idx_from_name(name, busnum);

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        e->iana_class = _usb_iana_class(name);
        e->is_fru     = TV_FALSE;
        e->parent_idx = hub_idx ? hub_idx : IDX_BASEBOARD;
        e->parent_rel_pos = _usb_parent_rel_pos_from_name(name, busnum);

        snprintf(path, sizeof(path), "%s/%s/uevent", USB_PATH, name);
        _sysfs_read_key(path, "DEVNAME", devname, sizeof(devname));
        strlcpy(e->name, devname[0] ? _strip_dev_prefix(devname) : name,
                sizeof(e->name));

        snprintf(path, sizeof(path), "%s/%s/speed", USB_PATH, name);
        _sysfs_read(path, speed, sizeof(speed));
        _usb_speed_descr(speed, speed_descr, sizeof(speed_descr));
        snprintf(path, sizeof(path), "%s/%s/removable", USB_PATH, name);
        _sysfs_read(path, removable, sizeof(removable));
        if (strcmp(removable, "removable") == 0)
            e->is_fru = TV_TRUE;
        class_descr = _usb_class_descr(name);
        if (speed_descr[0])
            snprintf(e->descr, sizeof(e->descr), "%s, %s",
                     class_descr, speed_descr);
        else
            strlcpy(e->descr, class_descr, sizeof(e->descr));
        if (e->is_fru == TV_TRUE)
            strncat(e->descr, ", removable",
                    sizeof(e->descr) - strlen(e->descr) - 1);

        snprintf(path, sizeof(path), "%s/%s/product", USB_PATH, name);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            strlcpy(e->model_name, val, sizeof(e->model_name));

        snprintf(path, sizeof(path), "%s/%s/manufacturer", USB_PATH, name);
        _sysfs_read(path, val, sizeof(val));
        _set_if_valid(e->mfg_name, sizeof(e->mfg_name), val);

        snprintf(path, sizeof(path), "%s/%s/serial", USB_PATH, name);
        _sysfs_read(path, val, sizeof(val));
        _set_if_valid(e->serial, sizeof(e->serial), val);

        /* Device version (BCD, e.g. "02.00") */
        snprintf(path, sizeof(path), "%s/%s/bcdDevice", USB_PATH, name);
        _sysfs_read(path, val, sizeof(val));
        _set_if_valid(e->hw_rev, sizeof(e->hw_rev), val);

        _usb_append_uris(e, name);
    }
    closedir(dir);
}

static void
_load_net_devices(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX], val[256];

    dir = opendir(NET_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        netsnmp_entity_info *existing;
        const char *ifname = de->d_name;
        const char *ifdescr;
        char key[128], address[64];
        int idx, ifindex, arphrd, parent_idx;

        if (ifname[0] == '.')
            continue;
        if (strcmp(ifname, "lo") == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s/ifindex", NET_PATH, ifname);
        ifindex = _sysfs_read_int(path);
        if (ifindex > 0) {
            for (existing = netsnmp_entity_get_first(); existing;
                 existing = netsnmp_entity_get_next(existing)) {
                if (existing->ifindex == ifindex)
                    break;
            }
            if (existing)
                continue;
        }

        snprintf(path, sizeof(path), "%s/%s/device", NET_PATH, ifname);
        rp[0] = '\0';
        if (!realpath(path, rp))
            continue;
        if (strstr(rp, "/virtual/"))
            continue;

        snprintf(path, sizeof(path), "%s/%s/address", NET_PATH, ifname);
        _sysfs_read(path, address, sizeof(address));
        snprintf(key, sizeof(key), "net:%s", rp[0] ? rp : ifname);

        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        parent_idx = _usb_parent_idx_from_path(rp);
        if (!parent_idx && rp[0])
            parent_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_PORT;
        e->is_fru     = TV_FALSE;
        e->parent_idx = parent_idx ? parent_idx : IDX_BASEBOARD;
        strlcpy(e->name, ifname, sizeof(e->name));
        strlcpy(e->serial, address, sizeof(e->serial));
        if (ifindex > 0) {
            e->ifindex = ifindex;
            snprintf(e->alias, sizeof(e->alias), "ifIndex.%d", ifindex);
        }

        snprintf(path, sizeof(path), "%s/%s/type", NET_PATH, ifname);
        arphrd = _sysfs_read_int(path);
        ifdescr = _arphrd_descr(arphrd);
        if (arphrd == 1 /* ARPHRD_ETHER */) {
            snprintf(path, sizeof(path), "%s/%s/wireless", NET_PATH, ifname);
            if (access(path, F_OK) == 0)
                ifdescr = "Wireless interface";
        }
        strlcpy(e->descr, ifdescr ? ifdescr : ifname, sizeof(e->descr));

        snprintf(path, sizeof(path), "%s/%s/ifalias", NET_PATH, ifname);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            strlcpy(e->alias, val, sizeof(e->alias));

        snprintf(path, sizeof(path), "%s/%s", NET_PATH, ifname);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        if (rp[0])
            _append_file_uri(e->uris, sizeof(e->uris), rp);

        _nic_scan_ethtool(e, ifname,
                          IDX_SFP_BASE + 1000 + (ifindex > 0 ? ifindex : 0));
    }

    closedir(dir);
}

static void
_block_size_descr(unsigned long long sectors, char *buf, size_t bufsz)
{
    unsigned long long bytes, unit;
    const char *suffix;
    unsigned long long whole, frac;

    if (bufsz > 0)
        buf[0] = '\0';
    if (!sectors || bufsz == 0)
        return;

    bytes = sectors * 512ULL;
    if (bytes >= (1ULL << 40)) {
        unit = 1ULL << 40;
        suffix = "TiB";
    } else {
        unit = 1ULL << 30;
        suffix = "GiB";
    }

    whole = bytes / unit;
    frac = ((bytes % unit) * 10ULL + unit / 2ULL) / unit;
    if (frac >= 10) {
        whole++;
        frac = 0;
    }

    if (frac)
        snprintf(buf, bufsz, "%llu.%llu%s", whole, frac, suffix);
    else
        snprintf(buf, bufsz, "%llu%s", whole, suffix);
}

static void
_block_disk_descr(const char *kind, const char *block_name,
                  char *buf, size_t bufsz)
{
    char path[512], val[64], size_str[32];
    unsigned long long sectors = 0;

    if (bufsz > 0)
        buf[0] = '\0';
    snprintf(path, sizeof(path), "%s/%s/size", BLOCK_PATH, block_name);
    _sysfs_read(path, val, sizeof(val));
    if (val[0])
        sectors = strtoull(val, NULL, 10);

    _block_size_descr(sectors, size_str, sizeof(size_str));
    if (size_str[0])
        snprintf(buf, bufsz, "%s (%s)", kind, size_str);
    else
        strlcpy(buf, kind, bufsz);
}

static void
_nvme_block_descr(const char *ctrl_name, char *buf, size_t bufsz)
{
    DIR *dir;
    struct dirent *de;

    if (bufsz > 0)
        buf[0] = '\0';

    dir = opendir(BLOCK_PATH);
    if (!dir) {
        strlcpy(buf, "NVMe device", bufsz);
        return;
    }

    while ((de = readdir(dir))) {
        size_t len = strlen(ctrl_name);

        if (strncmp(de->d_name, ctrl_name, len) != 0)
            continue;
        if (de->d_name[len] != 'n')
            continue;
        if (!isdigit((unsigned char)de->d_name[len + 1]))
            continue;

        _block_disk_descr("NVMe solid-state disk", de->d_name, buf, bufsz);
        closedir(dir);
        return;
    }

    closedir(dir);
    strlcpy(buf, "NVMe device", bufsz);
}

static void
_load_scsi_disks(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], val[256], rp[PATH_MAX];

    dir = opendir(BLOCK_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir))) {
        netsnmp_entity_info *e;
        int idx, pci_idx = 0, usb_idx = 0;
        const char *p;
        char key[128];

        if (de->d_name[0] == '.')
            continue;

        /* Accept 'sd' disks and 'sr' optical drives only */
        {
            int is_sd = strncmp(de->d_name, "sd", 2) == 0;
            int is_sr = strncmp(de->d_name, "sr", 2) == 0;
            if (!is_sd && !is_sr)
                continue;
            /* Skip partitions on sd devices (e.g. sda1) */
            if (is_sd) {
                for (p = de->d_name + 2; *p && !isdigit((unsigned char)*p); p++)
                    ;
                if (*p)
                    continue;
            }
        }

        /* Resolve device symlink to get full sysfs path */
        snprintf(path, sizeof(path), "%s/%s/device", BLOCK_PATH, de->d_name);
        if (!realpath(path, rp))
            continue;

        /* Use the HCTL string (basename of realpath) as a fallback key */
        p = strrchr(rp, '/');
        if (!p)
            continue;
        p++;  /* e.g. "0:0:0:0" */

        snprintf(path, sizeof(path), "%s/%s/device/wwid", BLOCK_PATH, de->d_name);
        _sysfs_read(path, key, sizeof(key));
        if (!key[0])
            _block_stable_key(rp, p, de->d_name, key, sizeof(key));
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        {
            int ata_port = _sysfs_path_ata_port(rp);

            if (ata_port > 0 && netsnmp_entity_get_byIdx(IDX_ATA_BASE + ata_port))
                e->parent_idx = IDX_ATA_BASE + ata_port;
            else {
                usb_idx = _usb_parent_idx_from_path(rp);
                if (usb_idx && netsnmp_entity_get_byIdx(usb_idx))
                    e->parent_idx = usb_idx;
                else {
                    pci_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);
                    e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;
                }
            }
        }

        e->iana_class = IANA_PHYS_STORAGE;
        e->is_fru     = TV_TRUE;
        strlcpy(e->name, de->d_name, sizeof(e->name));
        strlcpy(e->descr, "Block disk", sizeof(e->descr));

        snprintf(path, sizeof(path), "%s/%s/device/model", BLOCK_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _trim_trailing(val);
        if (val[0])
            strlcpy(e->model_name, val, sizeof(e->model_name));

        snprintf(path, sizeof(path), "%s/%s/device/vendor", BLOCK_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _trim_trailing(val);
        _set_if_valid(e->mfg_name, sizeof(e->mfg_name), val);

        snprintf(path, sizeof(path), "%s/%s/device/rev", BLOCK_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _set_if_valid(e->fw_rev, sizeof(e->fw_rev), val);

        if (strncmp(de->d_name, "sd", 2) == 0) {
            /* Serial from VPD page 0x80: header is 4 bytes, rest is ASCII */
            FILE *f;

            snprintf(path, sizeof(path), "%s/%s/device/vpd_pg80",
                     BLOCK_PATH, de->d_name);
            f = fopen(path, "rb");
            if (f) {
                unsigned char vpd[256];
                size_t nr;
                nr = fread(vpd, 1, sizeof(vpd), f);
                fclose(f);
                if (nr > 4 && vpd[1] == 0x80) {
                    size_t slen = (vpd[2] << 8) | vpd[3];
                    if (slen > nr - 4)
                        slen = nr - 4;
                    if (slen > 0 && slen < sizeof(e->serial)) {
                        memcpy(e->serial, vpd + 4, slen);
                        e->serial[slen] = '\0';
                        while (slen > 0 && e->serial[slen-1] == ' ')
                            e->serial[--slen] = '\0';
                    }
                }
            }

            /* Size and media type in description */
            {
                char rot = '1';
                const char *kind;

                snprintf(path, sizeof(path), "%s/%s/queue/rotational",
                         BLOCK_PATH, de->d_name);
                _sysfs_read(path, val, sizeof(val));
                if (val[0])
                    rot = val[0];

                kind = rot == '0' ? "Solid-state disk" : "Hard disk";
                _block_disk_descr(kind, de->d_name, e->descr, sizeof(e->descr));
            }
        } else {
            strlcpy(e->descr, "Optical drive", sizeof(e->descr));
        }

        _block_append_uris(e, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), rp);
        _block_append_stable_key_uris(e, rp, p, key);
    }
    closedir(dir);
}

static void
_load_mmc_disks(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], val[256], rp[PATH_MAX];

    dir = opendir(BLOCK_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        char key[128];
        const char *np;
        int idx, pci_idx;

        if (strncmp(de->d_name, "mmcblk", 6) != 0)
            continue;
        np = de->d_name + 6;
        while (*np && isdigit((unsigned char)*np))
            np++;
        if (*np)
            continue;

        snprintf(path, sizeof(path), "%s/%s/device", BLOCK_PATH, de->d_name);
        rp[0] = '\0';
        if (!realpath(path, rp))
            rp[0] = '\0';

        snprintf(path, sizeof(path), "%s/%s/device/serial", BLOCK_PATH,
                 de->d_name);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            snprintf(key, sizeof(key), "mmc:%s", val);
        else
            snprintf(key, sizeof(key), "block:%s", de->d_name);

        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        pci_idx = rp[0] ? _pci_find_idx_by_path(pci_map, pci_map_n, rp) : 0;
        e->iana_class = IANA_PHYS_STORAGE;
        e->is_fru     = TV_TRUE;
        e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;
        strlcpy(e->name, de->d_name, sizeof(e->name));
        strlcpy(e->mfg_name, "MMC", sizeof(e->mfg_name));
        _set_if_valid(e->serial, sizeof(e->serial), val);

        snprintf(path, sizeof(path), "%s/%s/device/name", BLOCK_PATH,
                 de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _set_if_valid(e->model_name, sizeof(e->model_name), val);

        _block_disk_descr("MMC/SD card", de->d_name, e->descr,
                          sizeof(e->descr));
        _block_append_uris(e, de->d_name);
        _append_uri(e->uris, sizeof(e->uris), key);
    }

    closedir(dir);
}

static void
_load_nvme(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], val[256];

    dir = opendir(NVME_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir))) {
        netsnmp_entity_info *e;
        int idx, pci_idx;
        char key[128];

        if (de->d_name[0] == '.')
            continue;

        snprintf(path, sizeof(path), "%s/%s/address", NVME_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        pci_idx = val[0] ? _pci_find_idx(pci_map, pci_map_n, val) : 0;

        if (pci_idx) {
            e = netsnmp_entity_get_byIdx(pci_idx);
            idx = pci_idx;
        } else {
            char ns_name[64];

            _nvme_first_ns(de->d_name, ns_name, sizeof(ns_name));
            key[0] = '\0';
            if (ns_name[0]) {
                snprintf(path, sizeof(path), "%s/%s/%s/wwid",
                         NVME_PATH, de->d_name, ns_name);
                _sysfs_read(path, key, sizeof(key));
            }
            if (!key[0])
                snprintf(key, sizeof(key), "nvme:%s", de->d_name);
            idx = _entity_index_alloc(key);
            if (idx <= 0)
                continue;
            e = netsnmp_entity_create(idx);
        }
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_STORAGE;
        e->is_fru     = TV_FALSE;
        strlcpy(e->name,  de->d_name, sizeof(e->name));
        _nvme_block_descr(de->d_name, e->descr, sizeof(e->descr));
        if (!e->parent_idx)
            e->parent_idx = IDX_BASEBOARD;

        snprintf(path, sizeof(path), "%s/%s/model", NVME_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _trim_trailing(val);
        _set_if_valid(e->model_name, sizeof(e->model_name), val);

        snprintf(path, sizeof(path), "%s/%s/serial", NVME_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _trim_trailing(val);
        _set_if_valid(e->serial, sizeof(e->serial), val);

        snprintf(path, sizeof(path), "%s/%s/firmware_rev",
                 NVME_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _set_if_valid(e->fw_rev, sizeof(e->fw_rev), val);

        snprintf(path, sizeof(path), "%s/%s/uuid", NVME_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        if (val[0] && strcmp(val, "00000000-0000-0000-0000-000000000000") != 0) {
            if (_parse_uuid(val, e->uuid))
                e->uuid_len = 16;
        }

        _nvme_append_uris(e, de->d_name);
    }
    closedir(dir);
}

/* ---- Phase 6: ACPI system, buses, and thermal zones ----------------------- */

static int
_entity_find_deepest_file_uri_prefix(const char *path, int idx_min, int idx_max)
{
    netsnmp_entity_info *e;
    int best_idx = 0, best_len = 0;

    if (!path || !path[0])
        return 0;

    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e)) {
        const char *p;

        if (e->idx < idx_min || e->idx > idx_max)
            continue;

        for (p = e->uris; p && *p; ) {
            const char *end;
            size_t tok_len;
            int file_len;

            while (isspace((unsigned char)*p))
                p++;
            if (!*p)
                break;

            end = strchr(p, ' ');
            tok_len = end ? (size_t)(end - p) : strlen(p);
            if (tok_len > 7 && strncmp(p, "file://", 7) == 0) {
                file_len = (int)(tok_len - 7);
                if (file_len > best_len &&
                    strncmp(path, p + 7, (size_t)file_len) == 0 &&
                    (path[file_len] == '\0' || path[file_len] == '/')) {
                    best_len = file_len;
                    best_idx = e->idx;
                }
            }

            p = end ? end + 1 : NULL;
        }
    }

    return best_idx;
}

static void
_load_acpi(void)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX], val[128];

    snprintf(path, sizeof(path), "%s/LNXSYSTM:00", ACPI_PATH);
    if (realpath(path, rp)) {
        netsnmp_entity_info *e = netsnmp_entity_create(IDX_ACPI_SYSTEM);

        if (e) {
            e->iana_class = IANA_PHYS_CONTAINER;
            e->parent_idx = IDX_BASEBOARD;
            e->parent_rel_pos = -1;
            strlcpy(e->name, "LNXSYSTM:00", sizeof(e->name));
            strlcpy(e->descr, "ACPI system", sizeof(e->descr));
            _append_file_uri(e->uris, sizeof(e->uris), path);
            _append_file_uri(e->uris, sizeof(e->uris), rp);
            _append_uri(e->uris, sizeof(e->uris), "acpi:LNXSYSTM:00");
        }
    }

    dir = opendir(ACPI_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        int bus_no, idx, parent_idx;

        if (sscanf(de->d_name, "LNXSYBUS:%x", &bus_no) != 1)
            continue;
        if (bus_no >= IDX_THERMAL_ZONE_BASE - IDX_ACPI_BUS_BASE)
            continue;

        idx = IDX_ACPI_BUS_BASE + bus_no;
        snprintf(path, sizeof(path), "%s/%s", ACPI_PATH, de->d_name);
        if (!realpath(path, rp))
            strlcpy(rp, path, sizeof(rp));

        parent_idx = _entity_find_deepest_file_uri_prefix(rp,
                         IDX_ACPI_SYSTEM, IDX_ACPI_BUS_BASE - 1);

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_BACKPLANE;
        e->parent_idx = parent_idx ? parent_idx : IDX_BASEBOARD;
        e->parent_rel_pos = bus_no;
        strlcpy(e->name, de->d_name, sizeof(e->name));
        snprintf(path, sizeof(path), "%s/path", rp);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            snprintf(e->descr, sizeof(e->descr), "ACPI system bus %s", val);
        else
            strlcpy(e->descr, "ACPI system bus", sizeof(e->descr));
        snprintf(path, sizeof(path), "%s/%s", ACPI_PATH, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        _append_file_uri(e->uris, sizeof(e->uris), rp);
        snprintf(path, sizeof(path), "acpi:%s", de->d_name);
        _append_uri(e->uris, sizeof(e->uris), path);
    }

    closedir(dir);
}

static void
_load_thermal_zones(void)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX], dev_rp[PATH_MAX], val[128];

    dir = opendir(THERMAL_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        int zone_no, idx, parent_idx;

        if (sscanf(de->d_name, "thermal_zone%d", &zone_no) != 1)
            continue;

        idx = IDX_THERMAL_ZONE_BASE + zone_no;
        snprintf(path, sizeof(path), "%s/%s", THERMAL_PATH, de->d_name);
        if (!realpath(path, rp))
            strlcpy(rp, path, sizeof(rp));

        snprintf(path, sizeof(path), "%s/%s/device", THERMAL_PATH, de->d_name);
        if (!realpath(path, dev_rp))
            dev_rp[0] = '\0';

        parent_idx = _entity_find_deepest_file_uri_prefix(dev_rp,
                         IDX_ACPI_SYSTEM, IDX_THERMAL_ZONE_BASE - 1);
        if (!parent_idx)
            continue;

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_OTHER;
        e->parent_idx = parent_idx;
        e->parent_rel_pos = zone_no;
        strlcpy(e->name, de->d_name, sizeof(e->name));

        snprintf(path, sizeof(path), "%s/%s/type", THERMAL_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        if (val[0]) {
            snprintf(e->descr, sizeof(e->descr), "ACPI thermal zone %d (%s)",
                     zone_no, val);
            strlcpy(e->model_name, val, sizeof(e->model_name));
        } else {
            snprintf(e->descr, sizeof(e->descr), "ACPI thermal zone %d",
                     zone_no);
        }

        snprintf(path, sizeof(path), "%s/%s", THERMAL_PATH, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        _append_file_uri(e->uris, sizeof(e->uris), rp);
        if (dev_rp[0])
            _append_file_uri(e->uris, sizeof(e->uris), dev_rp);
        snprintf(path, sizeof(path), "thermal:%s", de->d_name);
        _append_uri(e->uris, sizeof(e->uris), path);
    }

    closedir(dir);
}

/* ---- Phase 7: hwmon chips and sensors ------------------------------------ */

typedef struct hwmon_entry_s {
    char dir[32];
    char name[128];
} hwmon_entry;

static int
_cmp_hwmon_entry(const void *a, const void *b)
{
    const hwmon_entry *ha = (const hwmon_entry *)a;
    const hwmon_entry *hb = (const hwmon_entry *)b;
    int rc;

    rc = strcmp(ha->name, hb->name);
    if (rc != 0)
        return rc;
    return strcmp(ha->dir, hb->dir);
}

static int
_i2cdev_parent_idx_from_path(const char *rp)
{
    char path[PATH_MAX], *saveptr, *part;
    int bus;

    if (!rp || !rp[0])
        return 0;

    strlcpy(path, rp, sizeof(path));
    bus = -1;
    for (part = strtok_r(path, "/", &saveptr); part;
         part = strtok_r(NULL, "/", &saveptr)) {
        int part_bus;
        unsigned int addr;

        if (sscanf(part, "i2c-%d", &part_bus) == 1) {
            bus = part_bus;
            continue;
        }
        if (bus >= 0 && sscanf(part, "%d-%x", &part_bus, &addr) == 2 &&
            part_bus == bus) {
            char key[128];
            int idx;

            snprintf(key, sizeof(key), "i2cdev:%s", part);
            idx = _entity_index_alloc(key);
            if (idx > 0 && netsnmp_entity_get_byIdx(idx))
                return idx;
            return 0;
        }
    }
    return 0;
}

static int
_hwmon_parent_idx(const char *name, const char *rp,
                  pci_entity_map *pci_map, int pci_map_n)
{
    netsnmp_entity_info *parent;
    int parent_idx;

    parent_idx = _entity_find_deepest_file_uri_prefix(rp,
                     IDX_THERMAL_ZONE_BASE, IDX_SENSOR_BASE - 1);
    if (parent_idx)
        return parent_idx;

    parent_idx = _i2cdev_parent_idx_from_path(rp);
    if (parent_idx)
        return parent_idx;

    parent_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);
    if (parent_idx)
        return parent_idx;

    if (strcmp(name, "coretemp") == 0 || strcmp(name, "cpu_thermal") == 0) {
        parent = netsnmp_entity_get_byIdx(IDX_CPU_BASE);
        return parent ? parent->idx : IDX_BASEBOARD;
    }
    if (strcmp(name, "nvme") == 0) {
        parent = _find_first_name_prefix("nvme");
        return parent ? parent->idx : IDX_BASEBOARD;
    }
    if (strncmp(name, "iwlwifi", 7) == 0) {
        parent = _find_first_by_class(IANA_PHYS_PORT);
        return parent ? parent->idx : IDX_BASEBOARD;
    }

    return IDX_BASEBOARD;
}

static int
_hwmon_class(const char *name)
{
    return IANA_PHYS_OTHER;
}

static void
_load_hwmon(pci_entity_map *pci_map, int pci_map_n)
{
    static const char *prefixes[] = { "temp", "fan", "in", "curr", "power", "energy", "humidity", NULL };
    DIR *dir;
    struct dirent *de;
    char path[512];
    hwmon_entry *chips, *tmp;
    int  pi, chip_count, chip_cap, ci;
    char used[HWMON_BUCKETS];

    memset(used, 0, sizeof(used));

    dir = opendir(HWMON_PATH);
    if (!dir)
        return;

    chips = NULL;
    chip_count = 0;
    chip_cap = 0;

    while ((de = readdir(dir))) {
        if (de->d_name[0] == '.')
            continue;
        if (strncmp(de->d_name, "hwmon", 5) != 0)
            continue;

        if (chip_count >= chip_cap) {
            chip_cap = chip_cap ? chip_cap * 2 : 16;
            tmp = (hwmon_entry *)realloc(chips, chip_cap * sizeof(*chips));
            if (!tmp)
                break;
            chips = tmp;
        }

        strlcpy(chips[chip_count].dir, de->d_name,
                sizeof(chips[chip_count].dir));
        snprintf(path, sizeof(path), "%s/%s/name", HWMON_PATH, de->d_name);
        _sysfs_read(path, chips[chip_count].name,
                    sizeof(chips[chip_count].name));
        if (!chips[chip_count].name[0])
            strlcpy(chips[chip_count].name, de->d_name,
                    sizeof(chips[chip_count].name));
        chip_count++;
    }
    closedir(dir);

    qsort(chips, chip_count, sizeof(chips[0]), _cmp_hwmon_entry);

    for (ci = 0; ci < chip_count; ci++) {
        netsnmp_entity_info *e;
        int chip_base, slot, sensor_seq, n;
        char rp[PATH_MAX], key[PATH_MAX + 32];

        /* Build a stable key from the realpath of the hwmon dir */
        snprintf(path, sizeof(path), "%s/%s", HWMON_PATH, chips[ci].dir);
        if (!realpath(path, rp))
            strlcpy(rp, path, sizeof(rp));
        snprintf(key, sizeof(key), "%s|%s", chips[ci].name, rp);

        slot = _hash_alloc_slot(key, used, HWMON_BUCKETS);
        if (slot < 0)
            continue;

        chip_base = IDX_SENSOR_BASE + slot * HWMON_SLOT_SZ;
        e = netsnmp_entity_create(chip_base);
        if (!e)
            continue;

        e->iana_class = _hwmon_class(chips[ci].name);
        e->parent_idx = _hwmon_parent_idx(chips[ci].name, rp,
                                          pci_map, pci_map_n);
        e->parent_rel_pos = -1;
        strlcpy(e->name,  chips[ci].dir, sizeof(e->name));
        strlcpy(e->descr, chips[ci].name, sizeof(e->descr));
        strlcpy(e->model_name, chips[ci].name, sizeof(e->model_name));
        snprintf(path, sizeof(path), "%s/%s", HWMON_PATH, chips[ci].dir);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        if (strcmp(rp, path) != 0)
            _append_file_uri(e->uris, sizeof(e->uris), rp);

        sensor_seq = 1;
        for (pi = 0; prefixes[pi]; pi++) {
            const char *pfx = prefixes[pi];
            for (n = 1; n <= 32; n++) {
                netsnmp_entity_info *se;
                char sensor_name[64], label[64];

                snprintf(path, sizeof(path), "%s/%s/%s%d_input",
                         HWMON_PATH, chips[ci].dir, pfx, n);
                if (access(path, F_OK) != 0)
                    break;

                if (sensor_seq >= HWMON_SLOT_SZ)
                    break;  /* no more slots for this chip */

                snprintf(sensor_name, sizeof(sensor_name), "%s%d", pfx, n);
                se = netsnmp_entity_create(chip_base + sensor_seq);
                sensor_seq++;
                if (!se) continue;

                se->iana_class = IANA_PHYS_SENSOR;
                se->parent_idx = chip_base;
                strlcpy(se->name,  sensor_name, sizeof(se->name));
                strlcpy(se->descr, sensor_name, sizeof(se->descr));
                snprintf(path, sizeof(path), "%s/%s/%s%d_input",
                         HWMON_PATH, chips[ci].dir, pfx, n);
                _append_file_uri(se->uris, sizeof(se->uris), path);
                if (rp[0]) {
                    snprintf(path, sizeof(path), "%s/%s%d_input", rp, pfx, n);
                    _append_file_uri(se->uris, sizeof(se->uris), path);
                }

                snprintf(path, sizeof(path), "%s/%s/%s%d_label",
                         HWMON_PATH, chips[ci].dir, pfx, n);
                _sysfs_read(path, label, sizeof(label));
                if (label[0])
                    strlcpy(se->descr, label, sizeof(se->descr));
            }
        }
    }

    free(chips);
}

/* ---- Phase 8: enrich hwmon power-supply entities from /sys/class/power_supply */

static void
_load_power_supply(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    const struct dirent *de;
    char path[512], rp[PATH_MAX];

    dir = opendir(PSY_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir))) {
        netsnmp_entity_info *e;
        char mfg[128], model[128], serial[64], tech[64], type[32];
        char key[128];
        int idx, parent_idx;

        if (de->d_name[0] == '.')
            continue;

        snprintf(path, sizeof(path), "%s/%s/type", PSY_PATH, de->d_name);
        _sysfs_read(path, type, sizeof(type));
        if (strcmp(type, "Battery") != 0)
            continue;

        /* Find the hwmon entity whose model_name matches this PSY name */
        for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e)) {
            if (strcmp(e->model_name, de->d_name) == 0)
                break;
        }
        if (!e) {
            snprintf(key, sizeof(key), "psy:%s", de->d_name);
            idx = _entity_index_alloc(key);
            if (idx <= 0)
                continue;

            parent_idx = 0;
            snprintf(path, sizeof(path), "%s/%s/device", PSY_PATH, de->d_name);
            rp[0] = '\0';
            if (realpath(path, rp))
                parent_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);

            e = netsnmp_entity_create(idx);
            if (!e)
                continue;

            e->iana_class = IANA_PHYS_POWERSUPPLY;
            e->is_fru     = TV_FALSE;
            e->parent_idx = parent_idx ? parent_idx : IDX_BASEBOARD;
            strlcpy(e->name, de->d_name, sizeof(e->name));
            _append_uri(e->uris, sizeof(e->uris), key);
            snprintf(path, sizeof(path), "%s/%s", PSY_PATH, de->d_name);
            _append_file_uri(e->uris, sizeof(e->uris), path);
            if (rp[0])
                _append_file_uri(e->uris, sizeof(e->uris), rp);
        }

        snprintf(path, sizeof(path), "%s/%s/manufacturer", PSY_PATH, de->d_name);
        _sysfs_read(path, mfg, sizeof(mfg));

        snprintf(path, sizeof(path), "%s/%s/model_name", PSY_PATH, de->d_name);
        _sysfs_read(path, model, sizeof(model));

        snprintf(path, sizeof(path), "%s/%s/serial_number", PSY_PATH, de->d_name);
        _sysfs_read(path, serial, sizeof(serial));

        snprintf(path, sizeof(path), "%s/%s/technology", PSY_PATH, de->d_name);
        _sysfs_read(path, tech, sizeof(tech));

        if (mfg[0])
            strlcpy(e->mfg_name, mfg, sizeof(e->mfg_name));
        if (model[0])
            strlcpy(e->model_name, model, sizeof(e->model_name));
        if (serial[0])
            strlcpy(e->serial, serial, sizeof(e->serial));

        if (tech[0])
            snprintf(e->descr, sizeof(e->descr), "Battery (%s)", tech);
        else
            strlcpy(e->descr, "Battery", sizeof(e->descr));
    }
    closedir(dir);
}

/* ---- Phase 9: RTC devices ------------------------------------------------- */

static void
_load_rtc(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX], val[128];
    int idx = IDX_RTC_BASE;

    dir = opendir(RTC_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        char *sp;
        int parent_idx;

        if (strncmp(de->d_name, "rtc", 3) != 0 || !isdigit((unsigned char)de->d_name[3]))
            continue;

        e = netsnmp_entity_create(idx++);
        if (!e)
            continue;

        snprintf(path, sizeof(path), "%s/%s", RTC_PATH, de->d_name);
        rp[0] = '\0';
        if (realpath(path, rp))
            parent_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);
        else
            parent_idx = 0;

        e->iana_class = IANA_PHYS_MODULE;
        e->parent_idx = parent_idx ? parent_idx : IDX_BASEBOARD;
        if (!parent_idx)
            e->parent_rel_pos = -1;
        strlcpy(e->name, de->d_name, sizeof(e->name));

        snprintf(path, sizeof(path), "%s/%s/name", RTC_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        /* sysfs name may have extra tokens (e.g. "rtc_cmos 00:00") — keep first word */
        if ((sp = strchr(val, ' ')) != NULL)
            *sp = '\0';

        if (val[0]) {
            strlcpy(e->descr,      "System CMOS/Real Time Clock",
                    sizeof(e->descr));
            strlcpy(e->model_name, val, sizeof(e->model_name));
        } else {
            strlcpy(e->descr,      "System CMOS/Real Time Clock",
                    sizeof(e->descr));
            strlcpy(e->model_name, de->d_name, sizeof(e->model_name));
        }

        snprintf(path, sizeof(path), "%s/%s", RTC_PATH, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        if (rp[0])
            _append_file_uri(e->uris, sizeof(e->uris), rp);
        snprintf(path, sizeof(path), "rtc:%s", de->d_name);
        _append_uri(e->uris, sizeof(e->uris), path);
    }
    closedir(dir);
}

/* ---- Phase 10: Precision Time Protocol clocks ---------------------------- */

static int
_ptp_clock_name_is_model(const char *name)
{
    char path[PATH_MAX];
    const char *cp;
    int hex_digits, separators, non_zero;

    if (!name || !name[0])
        return 0;

    snprintf(path, sizeof(path), "%s/%s", NET_PATH, name);
    if (access(path, F_OK) == 0)
        return 0;

    if (strncmp(name, "eth", 3) == 0 || strncmp(name, "eno", 3) == 0 ||
        strncmp(name, "ens", 3) == 0 || strncmp(name, "enp", 3) == 0 ||
        strncmp(name, "enx", 3) == 0 || strncmp(name, "wlan", 4) == 0 ||
        strncmp(name, "wlp", 3) == 0 || strncmp(name, "ib", 2) == 0)
        return 0;

    hex_digits = 0;
    separators = 0;
    non_zero = 0;
    for (cp = name; *cp; cp++) {
        if (isxdigit((unsigned char)*cp)) {
            hex_digits++;
            if (*cp != '0')
                non_zero = 1;
        } else if (*cp == ':' || *cp == '-') {
            separators++;
        } else {
            return 1;
        }
    }

    if (hex_digits == 12 && (separators == 0 || separators == 5))
        return 0;
    if (!non_zero)
        return 0;
    return 1;
}

static int
_net_port_idx_by_name(const char *ifname)
{
    netsnmp_entity_info *e;

    if (!ifname || !ifname[0])
        return 0;
    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e)) {
        if (e->iana_class == IANA_PHYS_PORT && strcmp(e->name, ifname) == 0)
            return e->idx;
    }
    return 0;
}

static int
_ptp_net_port_idx(const char *ptp_name)
{
    DIR *dir;
    struct dirent *de;
    char path[512];
    int idx;

    snprintf(path, sizeof(path), "%s/%s/device/net", PTP_PATH, ptp_name);
    dir = opendir(path);
    if (!dir)
        return 0;

    idx = 0;
    while ((de = readdir(dir)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        idx = _net_port_idx_by_name(de->d_name);
        if (idx > 0)
            break;
    }
    closedir(dir);
    return idx;
}

static void
_load_ptp(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX], val[128];

    dir = opendir(PTP_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        char key[128], clock_name[128], max_adj[64], pps[16], devname[128];
        int idx, parent_idx;

        if (strncmp(de->d_name, "ptp", 3) != 0 ||
            !isdigit((unsigned char)de->d_name[3]))
            continue;

        snprintf(path, sizeof(path), "%s/%s", PTP_PATH, de->d_name);
        if (!realpath(path, rp))
            continue;

        snprintf(key, sizeof(key), "ptp:%s", de->d_name);
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        parent_idx = _ptp_net_port_idx(de->d_name);
        if (!parent_idx)
            parent_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        snprintf(path, sizeof(path), "%s/%s/clock_name", PTP_PATH, de->d_name);
        _sysfs_read(path, clock_name, sizeof(clock_name));
        snprintf(path, sizeof(path), "%s/%s/max_adjustment", PTP_PATH,
                 de->d_name);
        _sysfs_read(path, max_adj, sizeof(max_adj));
        snprintf(path, sizeof(path), "%s/%s/pps_available", PTP_PATH,
                 de->d_name);
        _sysfs_read(path, pps, sizeof(pps));

        e->iana_class = IANA_PHYS_OTHER;
        e->is_fru     = TV_FALSE;
        e->parent_idx = parent_idx ? parent_idx : IDX_BASEBOARD;
        e->parent_rel_pos = -1;
        strlcpy(e->name, de->d_name, sizeof(e->name));
        strlcpy(e->descr, "Precision Time Protocol clock", sizeof(e->descr));
        if (_ptp_clock_name_is_model(clock_name))
            strlcpy(e->model_name, clock_name, sizeof(e->model_name));

        if (max_adj[0]) {
            snprintf(val, sizeof(val), ", max adjustment %s ppb", max_adj);
            strncat(e->descr, val, sizeof(e->descr) - strlen(e->descr) - 1);
        }
        if (strcmp(pps, "1") == 0)
            strncat(e->descr, ", PPS", sizeof(e->descr) - strlen(e->descr) - 1);

        snprintf(path, sizeof(path), "ptp:%s", de->d_name);
        _append_uri(e->uris, sizeof(e->uris), path);
        snprintf(path, sizeof(path), "%s/%s", PTP_PATH, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        _append_file_uri(e->uris, sizeof(e->uris), rp);

        snprintf(path, sizeof(path), "%s/%s/uevent", PTP_PATH, de->d_name);
        _sysfs_read_key(path, "DEVNAME", devname, sizeof(devname));
        snprintf(path, sizeof(path), "/dev/%s",
                 devname[0] ? _strip_dev_prefix(devname) : de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
    }
    closedir(dir);
}

/* ---- Phase 11: Trusted Platform Modules ---------------------------------- */

static void
_load_tpm(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX];

    dir = opendir(TPM_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        char key[128], driver[128], modalias[128], val[128], devname[128];
        int idx, pci_idx;

        if (strncmp(de->d_name, "tpm", 3) != 0 ||
            !isdigit((unsigned char)de->d_name[3]))
            continue;

        snprintf(path, sizeof(path), "%s/%s", TPM_PATH, de->d_name);
        if (!realpath(path, rp))
            continue;

        snprintf(key, sizeof(key), "tpm:%s", de->d_name);
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        pci_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        snprintf(path, sizeof(path), "%s/%s/device/uevent", TPM_PATH,
                 de->d_name);
        _sysfs_read_key(path, "DRIVER", driver, sizeof(driver));
        _sysfs_read_key(path, "MODALIAS", modalias, sizeof(modalias));

        e->iana_class = IANA_PHYS_MODULE;
        e->is_fru     = TV_FALSE;
        e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;
        if (!pci_idx)
            e->parent_rel_pos = -1;
        strlcpy(e->name, de->d_name, sizeof(e->name));
        strlcpy(e->descr, "Trusted Platform Module", sizeof(e->descr));

        if (driver[0])
            strlcpy(e->sw_rev, driver, sizeof(e->sw_rev));
        if (modalias[0])
            strlcpy(e->model_name, modalias, sizeof(e->model_name));

        snprintf(path, sizeof(path), "%s/%s/tpm_version_major", TPM_PATH,
                 de->d_name);
        _sysfs_read(path, val, sizeof(val));
        if (val[0]) {
            strncat(e->descr, " v", sizeof(e->descr) - strlen(e->descr) - 1);
            strncat(e->descr, val, sizeof(e->descr) - strlen(e->descr) - 1);
        }

        snprintf(path, sizeof(path), "tpm:%s", de->d_name);
        _append_uri(e->uris, sizeof(e->uris), path);
        snprintf(path, sizeof(path), "%s/%s", TPM_PATH, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        _append_file_uri(e->uris, sizeof(e->uris), rp);

        snprintf(path, sizeof(path), "%s/%s/uevent", TPM_PATH, de->d_name);
        _sysfs_read_key(path, "DEVNAME", devname, sizeof(devname));
        snprintf(path, sizeof(path), "/dev/%s",
                 devname[0] ? _strip_dev_prefix(devname) : de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);

        snprintf(path, sizeof(path), "%s/%s/device/tpmrm/tpmrm%s", TPM_PATH,
                 de->d_name, de->d_name + 3);
        if (access(path, F_OK) == 0) {
            snprintf(path, sizeof(path), "/dev/tpmrm%s", de->d_name + 3);
            _append_file_uri(e->uris, sizeof(e->uris), path);
        }
    }
    closedir(dir);
}

/* ---- Phase 12: Input devices --------------------------------------------- */

static void
_load_input(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX];

    dir = opendir(INPUT_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        char key[128], val[128], devname[128];
        int idx, parent_idx;

        if ((strncmp(de->d_name, "js", 2) != 0 ||
             !isdigit((unsigned char)de->d_name[2])) &&
            (strncmp(de->d_name, "mouse", 5) != 0 ||
             !isdigit((unsigned char)de->d_name[5])))
            continue;

        snprintf(path, sizeof(path), "%s/%s", INPUT_PATH, de->d_name);
        if (!realpath(path, rp))
            continue;

        snprintf(key, sizeof(key), "input:%s", de->d_name);
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        parent_idx = _usb_parent_idx_from_path(rp);
        if (!parent_idx)
            parent_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_OTHER;
        e->is_fru     = TV_FALSE;
        e->parent_idx = parent_idx ? parent_idx : IDX_BASEBOARD;
        strlcpy(e->name, de->d_name, sizeof(e->name));
        if (strncmp(de->d_name, "mouse", 5) == 0)
            strlcpy(e->descr, "Mouse input device", sizeof(e->descr));
        else
            strlcpy(e->descr, "Keyboard input device", sizeof(e->descr));

        snprintf(path, sizeof(path), "%s/%s/device/name", INPUT_PATH,
                 de->d_name);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            strlcpy(e->model_name, val, sizeof(e->model_name));

        snprintf(path, sizeof(path), "%s/%s/device/uniq", INPUT_PATH,
                 de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _set_if_valid(e->serial, sizeof(e->serial), val);

        snprintf(path, sizeof(path), "%s/%s/device/modalias", INPUT_PATH,
                 de->d_name);
        _sysfs_read(path, val, sizeof(val));
        if (val[0] && !e->model_name[0])
            strlcpy(e->model_name, val, sizeof(e->model_name));

        snprintf(path, sizeof(path), "input:%s", de->d_name);
        _append_uri(e->uris, sizeof(e->uris), path);
        snprintf(path, sizeof(path), "%s/%s", INPUT_PATH, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        _append_file_uri(e->uris, sizeof(e->uris), rp);

        snprintf(path, sizeof(path), "%s/%s/uevent", INPUT_PATH, de->d_name);
        _sysfs_read_key(path, "DEVNAME", devname, sizeof(devname));
        if (devname[0])
            snprintf(path, sizeof(path), "/dev/%s", _strip_dev_prefix(devname));
        else
            snprintf(path, sizeof(path), "/dev/input/%s", de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
    }
    closedir(dir);
}

/* ---- Phase 13: Framebuffer graphics devices ------------------------------- */

static void
_load_graphics(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX];

    dir = opendir(GRAPHICS_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        char key[128], name[128], mode[128], size[64], bpp[32], devname[128];
        int idx, pci_idx;

        if (strncmp(de->d_name, "fb", 2) != 0 ||
            !isdigit((unsigned char)de->d_name[2]))
            continue;

        snprintf(key, sizeof(key), "graphics:%s", de->d_name);
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", GRAPHICS_PATH, de->d_name);
        if (!realpath(path, rp))
            rp[0] = '\0';
        pci_idx = rp[0] ? _pci_find_idx_by_path(pci_map, pci_map_n, rp) : 0;

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_OTHER;
        e->is_fru     = TV_FALSE;
        e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;
        strlcpy(e->name, de->d_name, sizeof(e->name));

        snprintf(path, sizeof(path), "%s/%s/name", GRAPHICS_PATH, de->d_name);
        _sysfs_read(path, name, sizeof(name));
        _set_if_valid(e->model_name, sizeof(e->model_name), name);

        snprintf(path, sizeof(path), "%s/%s/modes", GRAPHICS_PATH, de->d_name);
        _sysfs_read(path, mode, sizeof(mode));
        snprintf(path, sizeof(path), "%s/%s/virtual_size", GRAPHICS_PATH,
                 de->d_name);
        _sysfs_read(path, size, sizeof(size));
        snprintf(path, sizeof(path), "%s/%s/bits_per_pixel", GRAPHICS_PATH,
                 de->d_name);
        _sysfs_read(path, bpp, sizeof(bpp));

        if (name[0] && mode[0] && bpp[0])
            snprintf(e->descr, sizeof(e->descr), "%s framebuffer %s, %s bpp",
                     name, mode, bpp);
        else if (name[0] && size[0] && bpp[0])
            snprintf(e->descr, sizeof(e->descr), "%s framebuffer %s, %s bpp",
                     name, size, bpp);
        else if (name[0])
            snprintf(e->descr, sizeof(e->descr), "%s framebuffer", name);
        else
            strlcpy(e->descr, "Framebuffer graphics device", sizeof(e->descr));

        snprintf(path, sizeof(path), "%s/%s", GRAPHICS_PATH, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        if (rp[0])
            _append_file_uri(e->uris, sizeof(e->uris), rp);

        snprintf(path, sizeof(path), "%s/%s/uevent", GRAPHICS_PATH,
                 de->d_name);
        _sysfs_read_key(path, "DEVNAME", devname, sizeof(devname));
        snprintf(path, sizeof(path), "/dev/%s",
                 devname[0] ? _strip_dev_prefix(devname) : de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        _append_uri(e->uris, sizeof(e->uris), key);
    }

    closedir(dir);
}

/* ---- Phase 14: GPIO controllers ------------------------------------------ */

static void
_load_gpio(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX];
    int have_chip_aliases;

    dir = opendir(GPIO_PATH);
    if (!dir)
        return;

    have_chip_aliases = 0;
    while ((de = readdir(dir)) != NULL) {
        if (strncmp(de->d_name, "chip", 4) == 0 &&
            isdigit((unsigned char)de->d_name[4])) {
            have_chip_aliases = 1;
            break;
        }
    }
    rewinddir(dir);

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        char key[128], label[128], ngpio[32];
        int idx, pci_idx;

        if (de->d_name[0] == '.')
            continue;
        if (have_chip_aliases) {
            if (strncmp(de->d_name, "chip", 4) != 0 ||
                !isdigit((unsigned char)de->d_name[4]))
                continue;
        } else if (strncmp(de->d_name, "gpiochip", 8) != 0 ||
                   !isdigit((unsigned char)de->d_name[8])) {
            continue;
        }

        snprintf(path, sizeof(path), "%s/%s", GPIO_PATH, de->d_name);
        if (!realpath(path, rp))
            rp[0] = '\0';
        if (strstr(rp, "soc:firmware") || strstr(rp, "virtgpio") ||
            strstr(rp, "expgpio"))
            continue;

        snprintf(path, sizeof(path), "%s/%s/label", GPIO_PATH, de->d_name);
        _sysfs_read(path, label, sizeof(label));
        snprintf(key, sizeof(key), "gpio:%s", label[0] ? label : de->d_name);
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        pci_idx = rp[0] ? _pci_find_idx_by_path(pci_map, pci_map_n, rp) : 0;
        e->iana_class = IANA_PHYS_MODULE;
        e->is_fru     = TV_FALSE;
        e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;
        if (!pci_idx)
            e->parent_rel_pos = -1;
        strlcpy(e->name, de->d_name, sizeof(e->name));
        _set_if_valid(e->model_name, sizeof(e->model_name), label);

        snprintf(path, sizeof(path), "%s/%s/ngpio", GPIO_PATH, de->d_name);
        _sysfs_read(path, ngpio, sizeof(ngpio));
        if (label[0] && ngpio[0])
            snprintf(e->descr, sizeof(e->descr), "GPIO controller %s, %s lines",
                     label, ngpio);
        else if (label[0])
            snprintf(e->descr, sizeof(e->descr), "GPIO controller %s", label);
        else
            strlcpy(e->descr, "GPIO controller", sizeof(e->descr));

        snprintf(path, sizeof(path), "%s/%s", GPIO_PATH, de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);
        if (rp[0])
            _append_file_uri(e->uris, sizeof(e->uris), rp);
        _append_uri(e->uris, sizeof(e->uris), key);
    }

    closedir(dir);
}

/* ---- Phase 13: I2C adapters and devices ---------------------------------- */

static void
_load_i2c(pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], rp[PATH_MAX], adapter_rp[PATH_MAX];

    dir = opendir(I2C_DEV_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        DIR *dev_dir;
        struct dirent *dev_de;
        char key[128], val[128];
        int bus, idx, pci_idx;

        if (sscanf(de->d_name, "i2c-%d", &bus) != 1)
            continue;

        snprintf(path, sizeof(path), "%s/%s", I2C_DEV_PATH, de->d_name);
        if (!realpath(path, rp))
            continue;
        strlcpy(adapter_rp, rp, sizeof(adapter_rp));
        snprintf(path, sizeof(path), "/i2c-dev/%s", de->d_name);
        if (strlen(adapter_rp) > strlen(path) &&
            strcmp(adapter_rp + strlen(adapter_rp) - strlen(path), path) == 0)
            adapter_rp[strlen(adapter_rp) - strlen(path)] = '\0';

        snprintf(key, sizeof(key), "i2c:%s", de->d_name);
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        pci_idx = _pci_find_idx_by_path(pci_map, pci_map_n, adapter_rp);

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_BACKPLANE;
        e->is_fru     = TV_FALSE;
        e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;
        e->parent_rel_pos = bus;
        strlcpy(e->name, de->d_name, sizeof(e->name));

        snprintf(path, sizeof(path), "%s/%s/name", I2C_DEV_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        if (val[0]) {
            snprintf(e->descr, sizeof(e->descr), "I^2C bus: %s", val);
            strlcpy(e->model_name, val, sizeof(e->model_name));
        } else {
            strlcpy(e->descr, "I^2C bus", sizeof(e->descr));
        }

        snprintf(path, sizeof(path), "i2c:%s", de->d_name);
        _append_uri(e->uris, sizeof(e->uris), path);
        _append_file_uri(e->uris, sizeof(e->uris), adapter_rp);
        snprintf(path, sizeof(path), "/dev/%s", de->d_name);
        _append_file_uri(e->uris, sizeof(e->uris), path);

        snprintf(path, sizeof(path), "%s/%s/device", I2C_DEV_PATH,
                 de->d_name);
        dev_dir = opendir(path);
        if (!dev_dir)
            continue;

        while ((dev_de = readdir(dev_dir)) != NULL) {
            netsnmp_entity_info *ce;
            char child_path[512], child_rp[PATH_MAX];
            char child_name[128], modalias[128], driver[128];
            int child_idx, child_bus;
            unsigned int addr;

            if (sscanf(dev_de->d_name, "%d-%x", &child_bus, &addr) != 2)
                continue;
            if (child_bus != bus)
                continue;

            snprintf(child_path, sizeof(child_path), "%s/%s/device/%s",
                     I2C_DEV_PATH, de->d_name, dev_de->d_name);
            if (!realpath(child_path, child_rp))
                strlcpy(child_rp, child_path, sizeof(child_rp));

            snprintf(path, sizeof(path), "%s/name", child_rp);
            _sysfs_read(path, child_name, sizeof(child_name));
            snprintf(path, sizeof(path), "%s/modalias", child_rp);
            _sysfs_read(path, modalias, sizeof(modalias));
            snprintf(path, sizeof(path), "%s/uevent", child_rp);
            _sysfs_read_key(path, "DRIVER", driver, sizeof(driver));
            if (strcmp(child_name, "dummy") == 0 ||
                strcmp(modalias, "i2c:dummy") == 0 ||
                strcmp(driver, "dummy") == 0)
                continue;

            snprintf(key, sizeof(key), "i2cdev:%s", dev_de->d_name);
            child_idx = _entity_index_alloc(key);
            if (child_idx <= 0)
                continue;

            ce = netsnmp_entity_create(child_idx);
            if (!ce)
                continue;

            ce->iana_class = IANA_PHYS_MODULE;
            ce->is_fru     = TV_FALSE;
            ce->parent_idx = idx;
            ce->parent_rel_pos = (int)addr;
            strlcpy(ce->name, dev_de->d_name, sizeof(ce->name));

            if (child_name[0]) {
                strlcpy(ce->descr, child_name, sizeof(ce->descr));
                strlcpy(ce->model_name, child_name, sizeof(ce->model_name));
            } else {
                strlcpy(ce->descr, "I2C device", sizeof(ce->descr));
            }

            snprintf(path, sizeof(path), "i2c:%s", dev_de->d_name);
            _append_uri(ce->uris, sizeof(ce->uris), path);
            _append_file_uri(ce->uris, sizeof(ce->uris), child_rp);
        }
        closedir(dev_dir);
    }
    closedir(dir);
}

/* ---- Phase 14: UCD-DISKIO aliases ----------------------------------------- */

/*
 * Map disk entities (sda, sr0, nvme0 …) to UCD-DISKIO-MIB diskIOEntry rows.
 * diskIOIndex is the 1-based position of the device in /proc/diskstats.
 * For NVMe: entity name is "nvme0" but diskstats lists "nvme0n1" (namespace).
 *   We match "nvme{N}n{M}" to entity "nvme{N}" and use the first namespace seen.
 */
static void
_alias_diskio(void)
{
    /* diskIOEntry.diskIOIndex: 1.3.6.1.4.1.2021.13.15.1.1.1 */
    static const oid diskio_base[] = { 1,3,6,1,4,1,2021,13,15,1,1,1 };
    FILE *f;
    char line[256];
    int diskio_idx = 0;

    f = fopen("/proc/diskstats", "r");
    if (!f)
        return;

    while (fgets(line, sizeof(line), f)) {
        int major, minor;
        char devname[64];
        const netsnmp_entity_info *e;
        oid target[OID_LENGTH(diskio_base) + 1];

        if (sscanf(line, " %d %d %63s", &major, &minor, devname) != 3)
            continue;
        diskio_idx++;

        /* Direct match: sda, sr0, etc. */
        e = NULL;
        {
            netsnmp_entity_info *ep;
            for (ep = netsnmp_entity_get_first(); ep;
                 ep = netsnmp_entity_get_next(ep)) {
                if (strcmp(ep->name, devname) == 0) {
                    e = ep;
                    break;
                }
            }
        }

        /* NVMe namespace: "nvme0n1" → match entity "nvme0" (first ns only) */
        if (!e && strncmp(devname, "nvme", 4) == 0) {
            const char *p = devname + 4;
            while (*p && isdigit((unsigned char)*p)) p++;
            if (*p == 'n') {
                char base[64];
                netsnmp_entity_info *ep;
                int ctrl_len = (int)(p - devname);

                snprintf(base, sizeof(base), "%.*s", ctrl_len, devname);
                for (ep = netsnmp_entity_get_first(); ep;
                     ep = netsnmp_entity_get_next(ep)) {
                    if (strcmp(ep->name, base) == 0) {
                        /* Only bind on the first namespace (avoid duplicates) */
                        e = ep;
                        break;
                    }
                }
            }
        }

        if (!e)
            continue;

        /* Skip if this entity already received a diskio alias */
        {
            int n;
            int already = 0;
            for (n = 0; n < netsnmp_entity_alias_count(); n++) {
                const netsnmp_entity_alias_row *r = netsnmp_entity_alias_get(n);
                if (r && r->phys_idx == e->idx &&
                    r->target_oid_len > 0 &&
                    r->target_oid[r->target_oid_len - 2] ==
                        diskio_base[OID_LENGTH(diskio_base) - 2]) {
                    already = 1;
                    break;
                }
            }
            if (already)
                continue;
        }

        memcpy(target, diskio_base, sizeof(diskio_base));
        target[OID_LENGTH(diskio_base)] = (oid)diskio_idx;
        netsnmp_entity_alias_add_oid(e->idx, 0,
                                      target, OID_LENGTH(diskio_base) + 1);
    }
    fclose(f);
}

/* ---- Phase 10: LM-SENSORS aliases ---------------------------------------- */

/* OID bases shared by both implementations */
static const oid _lm_temp_base[] = { 1,3,6,1,4,1,2021,13,16,2,1,1 };
static const oid _lm_fan_base[]  = { 1,3,6,1,4,1,2021,13,16,3,1,1 };
static const oid _lm_volt_base[] = { 1,3,6,1,4,1,2021,13,16,4,1,1 };
#define LM_BASE_LEN OID_LENGTH(_lm_temp_base)

#if defined(HAVE_SENSORS_SENSORS_H) && defined(NETSNMP_USE_SENSORS_V3)

/*
 * libsensors v3 implementation.
 *
 * Enumerate chips via sensors_get_detected_chips(), which follows the same
 * sensors.conf discovery order used by the lmsensors_v3 module.  For each
 * chip, match features with an _input subfeature (the only ones lmsensors_v3
 * counts) to the corresponding entity sensor by (hwmon_num, feature_name).
 * This produces entAliasMappingIdentifier OIDs that agree with the actual
 * lmTempSensors / lmFanSensors / lmVoltSensors row indices.
 */
static void
_alias_lm_sensors(void)
{
    static int sensors_ready = 0;
    const sensors_chip_name *chip;
    const sensors_feature   *feat;
    int chip_nr = 0, feat_nr;
    int temp_count = 0, fan_count = 0, volt_count = 0;

    if (!sensors_ready) {
        if (sensors_init(NULL) != 0)
            return;
        sensors_ready = 1;
    }

    while ((chip = sensors_get_detected_chips(NULL, &chip_nr))) {
        const char *p;
        int hwmon_num;

        /* chip->path ends with ".../hwmon/hwmonN" — extract N */
        p = strrchr(chip->path, '/');
        if (!p || strncmp(p + 1, "hwmon", 5) != 0)
            continue;
        hwmon_num = atoi(p + 6);

        feat_nr = 0;
        while ((feat = sensors_get_features(chip, &feat_nr))) {
            int sf_type;
            const sensors_subfeature *sub;
            netsnmp_entity_info *e;
            const netsnmp_entity_info *parent;
            oid target[LM_BASE_LEN + 1];
            int idx_1based = 0;
            const char *type_descr;

            switch (feat->type) {
            case SENSORS_FEATURE_TEMP:
                sf_type    = SENSORS_SUBFEATURE_TEMP_INPUT;
                type_descr = "Temperature sensor";
                break;
            case SENSORS_FEATURE_FAN:
                sf_type    = SENSORS_SUBFEATURE_FAN_INPUT;
                type_descr = "Fan sensor";
                break;
            case SENSORS_FEATURE_IN:
                sf_type    = SENSORS_SUBFEATURE_IN_INPUT;
                type_descr = "Voltage sensor";
                break;
            case SENSORS_FEATURE_POWER:
                sf_type    = SENSORS_SUBFEATURE_POWER_INPUT;
                type_descr = "Power sensor";
                break;
            case SENSORS_FEATURE_CURR:
                sf_type    = SENSORS_SUBFEATURE_CURR_INPUT;
                type_descr = "Current sensor";
                break;
            case SENSORS_FEATURE_ENERGY:
                sf_type    = SENSORS_SUBFEATURE_ENERGY_INPUT;
                type_descr = "Energy sensor";
                break;
            case SENSORS_FEATURE_HUMIDITY:
                sf_type    = SENSORS_SUBFEATURE_HUMIDITY_INPUT;
                type_descr = "Humidity sensor";
                break;
            default:
                continue;
            }

            /* Only count features that have a readable _input value —
             * mirrors the counting in lmsensors_v3.c exactly */
            sub = sensors_get_subfeature(chip, feat, sf_type);
            if (!sub)
                continue;

            /* OID aliasing only for the three types tracked by lmSensors MIB */
            switch (feat->type) {
            case SENSORS_FEATURE_TEMP:
                idx_1based = ++temp_count;
                memcpy(target, _lm_temp_base, sizeof(_lm_temp_base));
                break;
            case SENSORS_FEATURE_FAN:
                idx_1based = ++fan_count;
                memcpy(target, _lm_fan_base, sizeof(_lm_fan_base));
                break;
            case SENSORS_FEATURE_IN:
                idx_1based = ++volt_count;
                memcpy(target, _lm_volt_base, sizeof(_lm_volt_base));
                break;
            default:
                break;
            }
            if (idx_1based)
                target[LM_BASE_LEN] = (oid)idx_1based;

            /* Find the entity sensor whose parent chip is this hwmon device
             * and whose sysfs name matches the libsensors feature name */
            for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e)) {
                char *lm_label;

                if (e->iana_class != IANA_PHYS_SENSOR)
                    continue;
                parent = netsnmp_entity_get_byIdx(e->parent_idx);
                if (!parent || strncmp(parent->name, "hwmon", 5) != 0)
                    continue;
                if (atoi(parent->name + 5) != hwmon_num)
                    continue;
                if (strcmp(e->name, feat->name) != 0)
                    continue;

                /* Enrich description with libsensors label */
                lm_label = sensors_get_label(chip, feat);
                if (lm_label) {
                    snprintf(e->descr, sizeof(e->descr), "%s: %s",
                             type_descr, lm_label);
                    free(lm_label);
                } else {
                    strlcpy(e->descr, type_descr, sizeof(e->descr));
                }

                if (idx_1based)
                    netsnmp_entity_alias_add_oid(e->idx, 0, target,
                                                 LM_BASE_LEN + 1);
                break;
            }
        }
    }
}

#else  /* no libsensors v3 — fall back to hwmon-number sort */

/*
 * Fallback implementation (no libsensors).
 *
 * Sort sensor entities by (sensor_type, hwmon_number, sensor_number) and
 * assign sequential 1-based indices.  This matches lmSensors index order
 * only when the kernel hwmon device numbering happens to agree with the
 * sensors.conf chip discovery order.
 */

typedef struct {
    int phys_idx;
    int hwmon_num;
    int sensor_num;
    int sensor_type; /* 0=temp, 1=fan, 2=volt */
} _lm_sensor_entry;

static int
_cmp_lm_sensor(const void *a, const void *b)
{
    const _lm_sensor_entry *sa = (const _lm_sensor_entry *)a;
    const _lm_sensor_entry *sb = (const _lm_sensor_entry *)b;

    if (sa->sensor_type != sb->sensor_type)
        return sa->sensor_type - sb->sensor_type;
    if (sa->hwmon_num != sb->hwmon_num)
        return sa->hwmon_num - sb->hwmon_num;
    return sa->sensor_num - sb->sensor_num;
}

static void
_alias_lm_sensors(void)
{
    _lm_sensor_entry *arr = NULL;
    int n = 0, cap = 0;
    netsnmp_entity_info *e;
    int temp_count = 0, fan_count = 0, volt_count = 0;
    int i;

    for (e = netsnmp_entity_get_first(); e; e = netsnmp_entity_get_next(e)) {
        int sensor_type, sensor_num, hwmon_num;
        const netsnmp_entity_info *parent;
        const char *np;
        _lm_sensor_entry *tmp;

        if (e->iana_class != IANA_PHYS_SENSOR)
            continue;

        if (strncmp(e->name, "temp", 4) == 0)
            sensor_type = 0;
        else if (strncmp(e->name, "fan", 3) == 0)
            sensor_type = 1;
        else if (strncmp(e->name, "in", 2) == 0)
            sensor_type = 2;
        else
            continue;

        np = e->name;
        while (*np && !isdigit((unsigned char)*np)) np++;
        sensor_num = *np ? atoi(np) : 0;

        parent = netsnmp_entity_get_byIdx(e->parent_idx);
        if (!parent)
            continue;
        hwmon_num = 0;
        if (strncmp(parent->name, "hwmon", 5) == 0)
            hwmon_num = atoi(parent->name + 5);

        if (n >= cap) {
            cap = cap ? cap * 2 : 64;
            tmp = (_lm_sensor_entry *)realloc(arr, cap * sizeof(*arr));
            if (!tmp) { free(arr); return; }
            arr = tmp;
        }
        arr[n].phys_idx    = e->idx;
        arr[n].hwmon_num   = hwmon_num;
        arr[n].sensor_num  = sensor_num;
        arr[n].sensor_type = sensor_type;
        n++;
    }

    if (!n) { free(arr); return; }

    qsort(arr, n, sizeof(arr[0]), _cmp_lm_sensor);

    for (i = 0; i < n; i++) {
        oid target[LM_BASE_LEN + 1];
        int idx_1based;

        switch (arr[i].sensor_type) {
        case 0:
            idx_1based = ++temp_count;
            memcpy(target, _lm_temp_base, sizeof(_lm_temp_base));
            break;
        case 1:
            idx_1based = ++fan_count;
            memcpy(target, _lm_fan_base, sizeof(_lm_fan_base));
            break;
        case 2:
            idx_1based = ++volt_count;
            memcpy(target, _lm_volt_base, sizeof(_lm_volt_base));
            break;
        default:
            continue;
        }

        target[LM_BASE_LEN] = (oid)idx_1based;
        netsnmp_entity_alias_add_oid(arr[i].phys_idx, 0,
                                      target, LM_BASE_LEN + 1);
    }

    free(arr);
}

#endif /* HAVE_SENSORS_SENSORS_H && NETSNMP_USE_SENSORS_V3 */
#undef LM_BASE_LEN

/* ---- Persistent hash and last-change time -------------------------------- */

#define ENTITY_STATE_FILE "entity_state"
#define ENTITY_CONFIG_CHANGE_THROTTLE 5

static uint32_t _saved_hash = 0;
static time_t _last_config_change_notify = 0;
static unsigned int _config_change_alarm = 0;
static int _config_change_pending = 0;

static void
_send_ent_config_change(void)
{
    static oid snmptrap_oid[] = { 1,3,6,1,6,3,1,1,4,1,0 };
    static oid ent_config_change_oid[] = { 1,3,6,1,2,1,47,2,0,1 };
    netsnmp_variable_list *vars = NULL;

    snmp_varlist_add_variable(&vars,
                              snmptrap_oid, OID_LENGTH(snmptrap_oid),
                              ASN_OBJECT_ID,
                              (u_char *)ent_config_change_oid,
                              sizeof(ent_config_change_oid));
    send_v2trap(vars);
    snmp_free_varbind(vars);
    _last_config_change_notify = time(NULL);
}

static void
_send_pending_ent_config_change(unsigned int clientreg, void *clientarg)
{
    (void)clientreg;
    (void)clientarg;

    _config_change_alarm = 0;
    if (!_config_change_pending)
        return;

    _config_change_pending = 0;
    _send_ent_config_change();
}

static void
_notify_ent_config_change(void)
{
    time_t now, notify_at;
    unsigned int wait;

    now = time(NULL);
    notify_at = _last_config_change_notify + ENTITY_CONFIG_CHANGE_THROTTLE;

    if (_last_config_change_notify == 0 || now >= notify_at) {
        _config_change_pending = 0;
        _send_ent_config_change();
        return;
    }

    _config_change_pending = 1;
    if (_config_change_alarm != 0)
        return;

    wait = (unsigned int)(notify_at - now);
    if (wait == 0)
        wait = 1;
    _config_change_alarm = snmp_alarm_register(
        wait, 0, _send_pending_ent_config_change, NULL);
    if (_config_change_alarm == 0)
        snmp_log(LOG_ERR, "entity: cannot schedule entConfigChange notification\n");
}

static void
_read_entity_state(void)
{
    char path[512];
    unsigned int h = 0;
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s",
             get_persistent_directory(), ENTITY_STATE_FILE);
    f = fopen(path, "r");
    if (!f)
        return;
    if (fscanf(f, "%x", &h) == 1)
        _saved_hash = (uint32_t)h;
    fclose(f);
}

static void
_write_entity_state(void)
{
    char path[512];
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s",
             get_persistent_directory(), ENTITY_STATE_FILE);
    f = fopen(path, "w");
    if (!f) {
        snmp_log(LOG_ERR, "entity: cannot write %s: %s\n",
                 path, strerror(errno));
        return;
    }
    fprintf(f, "%08x\n", (unsigned)_saved_hash);
    fclose(f);
}

/* ---- Top-level load ------------------------------------------------------ */

int
netsnmp_entity_arch_load(netsnmp_cache *cache, void *magic)
{
    pci_entity_map *pci_map = NULL;
    netsnmp_entity_info *old_entities = NULL;
    int pci_map_n = 0;
    uint32_t hash_before, hash_after;
    static int first_load = 1;

    if (first_load) {
        _read_entity_state();
        hash_before = _saved_hash;
        first_load  = 0;
    } else {
        hash_before = _entity_list_hash();
        old_entities = _entity_list_clone();
    }
    netsnmp_entity_free_list();
    _entity_index_alloc_load();

    _load_dmi();
    _load_numa_nodes();
    _load_cpus();
    _load_caches();
    _load_dimms();
    _load_pci(&pci_map, &pci_map_n);
    _load_ata_ports(pci_map, pci_map_n);
    _load_usb(pci_map, pci_map_n);
    _load_net_devices(pci_map, pci_map_n);
    _load_scsi_disks(pci_map, pci_map_n);
    _load_mmc_disks(pci_map, pci_map_n);
    _load_nvme(pci_map, pci_map_n);
    _load_i2c(pci_map, pci_map_n);
    _load_acpi();
    _load_thermal_zones();
    _load_hwmon(pci_map, pci_map_n);
    _load_power_supply(pci_map, pci_map_n);
    _load_ptp(pci_map, pci_map_n);
    _load_tpm(pci_map, pci_map_n);
    _load_input(pci_map, pci_map_n);
    _load_graphics(pci_map, pci_map_n);
    _load_gpio(pci_map, pci_map_n);
    _load_rtc(pci_map, pci_map_n);

    free(pci_map);
    _numa_fix_top_level_parents();
    netsnmp_entity_parent_rel_pos_rebuild();
    netsnmp_entity_contains_rebuild();
    netsnmp_entity_logical_load();
    netsnmp_entity_alias_rebuild();
    _alias_diskio();
    _alias_lm_sensors();
    netsnmp_entity_alias_sort();

    hash_after = _entity_list_hash();
    if (hash_after != hash_before) {
        entity_last_change = netsnmp_get_agent_uptime();
        _saved_hash        = hash_after;
        _log_entity_topology_diff(old_entities, hash_before, hash_after);
        _notify_ent_config_change();
        _write_entity_state();
    }
    if (hash_after != hash_before || _idx_alloc_dirty)
        _entity_indexes_write();

    _entity_list_clone_free(old_entities);

    return 0;
}

void init_entity_linux(void)
{
}
