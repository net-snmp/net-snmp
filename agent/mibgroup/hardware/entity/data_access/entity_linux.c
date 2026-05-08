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
#define PCI_PATH    "/sys/bus/pci/devices"
#define USB_PATH    "/sys/bus/usb/devices"
#define NET_PATH    "/sys/class/net"
#define NVME_PATH   "/sys/class/nvme"
#define BLOCK_PATH  "/sys/block"
#define HWMON_PATH  "/sys/class/hwmon"
#define PSY_PATH    "/sys/class/power_supply"
#define RTC_PATH    "/sys/class/rtc"

#define IDX_CHASSIS      1
#define IDX_BASEBOARD   10
#define IDX_BIOS        20
#define IDX_MEMORY     100
#define IDX_DIMM_BASE  110
#define IDX_CPU_BASE    200
#define IDX_CACHE_BASE  300   /* 10 slots per CPU package: 300-309, 310-319, … */
#define IDX_PCI_BASE   1000
#define IDX_ATA_BASE   1500
#define IDX_RTC_BASE   2400
#define IDX_SENSOR_BASE 4000
#define IDX_SFP_BASE   10000
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

    if (!uri || !uri[0] || urisz == 0)
        return;

    uri_len = strlen(uri);
    len = strlen(uris);
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
    _dmi_field("product_uuid", val, sizeof(val));
    if (_parse_uuid(val, e->uuid))
        e->uuid_len = 16;

    e = netsnmp_entity_create(IDX_BASEBOARD);
    if (!e) return;
    e->iana_class = IANA_PHYS_MODULE;
    e->parent_idx = IDX_CHASSIS;
    e->is_fru     = TV_TRUE;
    strlcpy(e->name,  "baseboard", sizeof(e->name));
    strlcpy(e->descr, "Baseboard", sizeof(e->descr));
    snprintf(e->uris, sizeof(e->uris), "file://%s", DMI_PATH);
    _dmi_field("board_vendor",  e->mfg_name,   sizeof(e->mfg_name));
    _dmi_field("board_name",    e->model_name, sizeof(e->model_name));
    _dmi_field("board_serial",  e->serial,     sizeof(e->serial));
    _dmi_field("board_version", e->hw_rev,     sizeof(e->hw_rev));

    e = netsnmp_entity_create(IDX_BIOS);
    if (!e) return;
    e->iana_class = IANA_PHYS_OTHER;
    e->parent_idx = IDX_BASEBOARD;
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

static void
_load_cpus(void)
{
    FILE *fp;
    char buf[512], descr[256], *p;
    int  phys_id, tmp, seen[64];
    netsnmp_entity_info *e;

    phys_id = -1;
    descr[0] = '\0';
    memset(seen, 0, sizeof(seen));

    fp = fopen("/proc/cpuinfo", "r");
    if (!fp)
        return;

    while (fgets(buf, sizeof(buf), fp)) {
        if (sscanf(buf, "physical id : %d", &tmp) == 1) {
            phys_id = tmp;
        } else if (sscanf(buf, "model name : %254[^\n]", descr) == 1) {
            p = descr;
            while (*p == ' ' || *p == '\t') p++;
            if (p != descr) memmove(descr, p, strlen(p) + 1);
        } else if (buf[0] == '\n' && phys_id >= 0) {
            if (phys_id < 64 && !seen[phys_id]) {
                seen[phys_id] = 1;
                e = netsnmp_entity_create(IDX_CPU_BASE + phys_id);
                if (e) {
                    e->iana_class     = IANA_PHYS_CPU;
                    e->parent_idx     = IDX_BASEBOARD;
                    e->is_fru         = TV_TRUE;
                    snprintf(e->name, sizeof(e->name), "cpu%d", phys_id);
                    snprintf(e->uris, sizeof(e->uris),
                             "file:///sys/devices/system/cpu/cpu%d", phys_id);
                    if (descr[0])
                        strlcpy(e->descr, descr, sizeof(e->descr));
                    else
                        snprintf(e->descr, sizeof(e->descr),
                                 "CPU package %d", phys_id);
                }
            }
            phys_id = -1;
        }
    }
    if (phys_id >= 0 && phys_id < 64 && !seen[phys_id]) {
        e = netsnmp_entity_create(IDX_CPU_BASE + phys_id);
        if (e) {
            e->iana_class     = IANA_PHYS_CPU;
            e->parent_idx     = IDX_BASEBOARD;
            e->is_fru         = TV_TRUE;
            snprintf(e->name, sizeof(e->name), "cpu%d", phys_id);
            snprintf(e->uris, sizeof(e->uris),
                     "file:///sys/devices/system/cpu/cpu%d", phys_id);
            if (descr[0])
                strlcpy(e->descr, descr, sizeof(e->descr));
        }
    }
    fclose(fp);
}

/* ---- Phase 3: DIMM slots via dmidecode ----------------------------------- */

static void
_load_dimms(void)
{
    FILE *fp;
    char buf[512], field[128], value[256];
    int  in_mem_device, slot;
    netsnmp_entity_info *e;

    in_mem_device = 0;
    slot = 0;
    e = NULL;

    e = netsnmp_entity_create(IDX_MEMORY);
    if (e) {
        e->iana_class = IANA_PHYS_CONTAINER;
        e->parent_idx = IDX_BASEBOARD;
        strlcpy(e->name, "memory", sizeof(e->name));
        strlcpy(e->descr, "System Memory", sizeof(e->descr));
        snprintf(e->uris, sizeof(e->uris), "file:///sys/devices/system/memory");
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
                e->iana_class = IANA_PHYS_MODULE;
                e->parent_idx = IDX_MEMORY;
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
    char path[512], val[64];
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
        _sysfs_read(path, val, sizeof(val));
        if (!val[0])
            continue;
        phys_id = atoi(val);
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
            _sysfs_read(path, val, sizeof(val));
            // cppcheck-suppress identicalConditionAfterEarlyExit
            if (!val[0])
                continue;
            level = atoi(val);

            snprintf(path, sizeof(path), "%s/%s/type", cache_path, cache_de->d_name);
            _sysfs_read(path, type, sizeof(type));

            snprintf(path, sizeof(path), "%s/%s/size", cache_path, cache_de->d_name);
            _sysfs_read(path, size, sizeof(size));

            e = netsnmp_entity_create(IDX_CACHE_BASE + phys_id * 10 + cache_idx);
            if (!e)
                continue;

            e->iana_class = IANA_PHYS_MODULE;
            e->parent_idx = IDX_CPU_BASE + phys_id;
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
        return IANA_PHYS_PORT;
    case 0x06:                          /* Bridge */
        if (sub == 0x00)
            return IANA_PHYS_BACKPLANE; /* Host bridge / root complex */
        return IANA_PHYS_CONTAINER;     /* PCI-PCI, CardBus, etc. */
    case 0x0b:                          /* Processor */
        return IANA_PHYS_CPU;
    case 0x11:                          /* Signal processing (thermal, etc.) */
        return IANA_PHYS_SENSOR;
    default:
        return IANA_PHYS_MODULE;
    }
}

typedef struct pci_entity_map_s {
    char bdf[16];
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
            parent_idx = map[i].idx;
        }
    }
    return parent_idx;
}

/* Find the deepest PCI device whose realpath is a prefix of `path`.
 * Used to attach non-PCI devices (SCSI disks) to their controller. */
static int
_pci_find_idx_by_path(pci_entity_map *map, int nmap, const char *path)
{
    int i, best_idx = 0, best_len = 0;
    size_t plen = strlen(path);

    for (i = 0; i < nmap; i++) {
        int mlen = (int)strlen(map[i].real_path);
        if (mlen <= best_len || (size_t)mlen >= plen)
            continue;
        if (strncmp(path, map[i].real_path, mlen) == 0 && path[mlen] == '/')  {
            best_len = mlen;
            best_idx = map[i].idx;
        }
    }
    return best_idx;
}

/* Ordered by bit index (matches ethtool output order).
 * Sentinel: bit == -1.  Works with both ETHTOOL_GLINKSETTINGS and the
 * legacy ETHTOOL_GSET fallback (bits 0-30 fit in the u32 supported field). */
static const struct { int bit; const char *name; } _nic_link_modes[] = {
    { ETHTOOL_LINK_MODE_10baseT_Half_BIT,             "10baseT/Half"          },
    { ETHTOOL_LINK_MODE_10baseT_Full_BIT,             "10baseT/Full"          },
    { ETHTOOL_LINK_MODE_100baseT_Half_BIT,            "100baseT/Half"         },
    { ETHTOOL_LINK_MODE_100baseT_Full_BIT,            "100baseT/Full"         },
    { ETHTOOL_LINK_MODE_1000baseT_Half_BIT,           "1000baseT/Half"        },
    { ETHTOOL_LINK_MODE_1000baseT_Full_BIT,           "1000baseT/Full"        },
    { ETHTOOL_LINK_MODE_10000baseT_Full_BIT,          "10000baseT/Full"       },
    { ETHTOOL_LINK_MODE_2500baseX_Full_BIT,           "2500baseX/Full"        },
    { ETHTOOL_LINK_MODE_1000baseKX_Full_BIT,          "1000baseKX/Full"       },
    { ETHTOOL_LINK_MODE_10000baseKX4_Full_BIT,        "10000baseKX4/Full"     },
    { ETHTOOL_LINK_MODE_10000baseKR_Full_BIT,         "10000baseKR/Full"      },
    { ETHTOOL_LINK_MODE_20000baseMLD2_Full_BIT,       "20000baseMLD2/Full"    },
    { ETHTOOL_LINK_MODE_20000baseKR2_Full_BIT,        "20000baseKR2/Full"     },
    { ETHTOOL_LINK_MODE_40000baseKR4_Full_BIT,        "40000baseKR4/Full"     },
    { ETHTOOL_LINK_MODE_40000baseCR4_Full_BIT,        "40000baseCR4/Full"     },
    { ETHTOOL_LINK_MODE_40000baseSR4_Full_BIT,        "40000baseSR4/Full"     },
    { ETHTOOL_LINK_MODE_40000baseLR4_Full_BIT,        "40000baseLR4/Full"     },
    { ETHTOOL_LINK_MODE_56000baseKR4_Full_BIT,        "56000baseKR4/Full"     },
    { ETHTOOL_LINK_MODE_56000baseCR4_Full_BIT,        "56000baseCR4/Full"     },
    { ETHTOOL_LINK_MODE_56000baseSR4_Full_BIT,        "56000baseSR4/Full"     },
    { ETHTOOL_LINK_MODE_56000baseLR4_Full_BIT,        "56000baseLR4/Full"     },
    /* Extended modes (bits 31+, only visible via ETHTOOL_GLINKSETTINGS) */
    { ETHTOOL_LINK_MODE_25000baseCR_Full_BIT,         "25000baseCR/Full"      },
    { ETHTOOL_LINK_MODE_25000baseKR_Full_BIT,         "25000baseKR/Full"      },
    { ETHTOOL_LINK_MODE_25000baseSR_Full_BIT,         "25000baseSR/Full"      },
    { ETHTOOL_LINK_MODE_50000baseCR2_Full_BIT,        "50000baseCR2/Full"     },
    { ETHTOOL_LINK_MODE_50000baseKR2_Full_BIT,        "50000baseKR2/Full"     },
    { ETHTOOL_LINK_MODE_100000baseKR4_Full_BIT,       "100000baseKR4/Full"    },
    { ETHTOOL_LINK_MODE_100000baseSR4_Full_BIT,       "100000baseSR4/Full"    },
    { ETHTOOL_LINK_MODE_100000baseCR4_Full_BIT,       "100000baseCR4/Full"    },
    { ETHTOOL_LINK_MODE_100000baseLR4_ER4_Full_BIT,   "100000baseLR4_ER4/Full"},
    { ETHTOOL_LINK_MODE_50000baseSR2_Full_BIT,        "50000baseSR2/Full"     },
    { ETHTOOL_LINK_MODE_1000baseX_Full_BIT,           "1000baseX/Full"        },
    { ETHTOOL_LINK_MODE_10000baseCR_Full_BIT,         "10000baseCR/Full"      },
    { ETHTOOL_LINK_MODE_10000baseSR_Full_BIT,         "10000baseSR/Full"      },
    { ETHTOOL_LINK_MODE_10000baseLR_Full_BIT,         "10000baseLR/Full"      },
    { ETHTOOL_LINK_MODE_10000baseLRM_Full_BIT,        "10000baseLRM/Full"     },
    { ETHTOOL_LINK_MODE_10000baseER_Full_BIT,         "10000baseER/Full"      },
    { ETHTOOL_LINK_MODE_2500baseT_Full_BIT,           "2500baseT/Full"        },
    { ETHTOOL_LINK_MODE_5000baseT_Full_BIT,           "5000baseT/Full"        },
    { ETHTOOL_LINK_MODE_50000baseKR_Full_BIT,         "50000baseKR/Full"      },
    { ETHTOOL_LINK_MODE_50000baseSR_Full_BIT,         "50000baseSR/Full"      },
    { ETHTOOL_LINK_MODE_50000baseCR_Full_BIT,         "50000baseCR/Full"      },
    { ETHTOOL_LINK_MODE_50000baseLR_ER_FR_Full_BIT,   "50000baseLR_ER_FR/Full"},
    { ETHTOOL_LINK_MODE_50000baseDR_Full_BIT,         "50000baseDR/Full"      },
    { ETHTOOL_LINK_MODE_100000baseKR2_Full_BIT,       "100000baseKR2/Full"    },
    { ETHTOOL_LINK_MODE_100000baseSR2_Full_BIT,       "100000baseSR2/Full"    },
    { ETHTOOL_LINK_MODE_100000baseCR2_Full_BIT,       "100000baseCR2/Full"    },
    { ETHTOOL_LINK_MODE_100000baseLR2_ER2_FR2_Full_BIT, "100000baseLR2_ER2_FR2/Full" },
    { ETHTOOL_LINK_MODE_100000baseDR2_Full_BIT,       "100000baseDR2/Full"    },
    { ETHTOOL_LINK_MODE_200000baseKR4_Full_BIT,       "200000baseKR4/Full"    },
    { ETHTOOL_LINK_MODE_200000baseSR4_Full_BIT,       "200000baseSR4/Full"    },
    { ETHTOOL_LINK_MODE_200000baseLR4_ER4_FR4_Full_BIT, "200000baseLR4_ER4_FR4/Full" },
    { ETHTOOL_LINK_MODE_200000baseDR4_Full_BIT,       "200000baseDR4/Full"    },
    { ETHTOOL_LINK_MODE_200000baseCR4_Full_BIT,       "200000baseCR4/Full"    },
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

            strlcpy(base, e->descr, sizeof(base));
            if (port_s && modes_buf[0])
                snprintf(e->descr, sizeof(e->descr), "%s (%s: %s)",
                         base, port_s, modes_buf);
            else if (port_s)
                snprintf(e->descr, sizeof(e->descr), "%s (%s)", base, port_s);
            else if (modes_buf[0])
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
    char path[512], val[256], netpath[512];
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
    pci_init(pacc);
#endif

    for (i = 0; i < nbdfs; i++) {
        long         class_val;
        unsigned int vid, did;
        int          idx;
        DIR         *netdir;
        struct dirent *nde;
#ifdef HAVE_PCI_LOOKUP_NAME
        char        *lname;
#endif

        class_val = 0;
        vid = did = 0;
        idx = IDX_PCI_BASE + i + 1;

        strlcpy(map[i].bdf, bdfs[i], sizeof(map[i].bdf));
        map[i].idx = idx;
        snprintf(path, sizeof(path), "%s/%s", PCI_PATH, bdfs[i]);
        if (!realpath(path, map[i].real_path))
            map[i].real_path[0] = '\0';

        e = netsnmp_entity_create(idx);
        if (!e) goto free_bdf;

        e->iana_class = IANA_PHYS_MODULE;
        e->parent_idx = IDX_BASEBOARD;
        strlcpy(e->name,  bdfs[i], sizeof(e->name));
        strlcpy(e->descr, bdfs[i], sizeof(e->descr));
        snprintf(e->uris, sizeof(e->uris), "file://%s/%s",
                 PCI_PATH, bdfs[i]);

        snprintf(path, sizeof(path), "%s/%s/class", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0]) {
            class_val = strtol(val, NULL, 16);
            e->iana_class = _pci_class_to_iana(class_val);
        }

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
            lname = pci_lookup_name(pacc, namebuf, sizeof(namebuf),
                                    PCI_LOOKUP_VENDOR | PCI_LOOKUP_NO_NUMBERS,
                                    vid);
            if (lname && lname[0])
                strlcpy(e->mfg_name, lname, sizeof(e->mfg_name));
            else
#endif
                snprintf(e->mfg_name, sizeof(e->mfg_name), "0x%04x", vid);
        }

        /* Device / product name */
        if (vid && did) {
#ifdef HAVE_PCI_LOOKUP_NAME
            lname = pci_lookup_name(pacc, namebuf, sizeof(namebuf),
                                    PCI_LOOKUP_DEVICE | PCI_LOOKUP_NO_NUMBERS,
                                    vid, did);
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
            lname = pci_lookup_name(pacc, namebuf, sizeof(namebuf),
                                    PCI_LOOKUP_CLASS | PCI_LOOKUP_NO_NUMBERS,
                                    cls_sub);
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

        snprintf(netpath, sizeof(netpath), "%s/%s/net", PCI_PATH, bdfs[i]);
        netdir = opendir(netpath);
        if (netdir) {
            while ((nde = readdir(netdir))) {
                int ifindex;

                if (nde->d_name[0] == '.') continue;

                e->iana_class = IANA_PHYS_PORT;
                e->is_fru     = TV_FALSE;
                strlcpy(e->name,  nde->d_name, sizeof(e->name));

                {
                    char typepath[512];
                    int arphrd;
                    const char *ifdescr;

                    snprintf(typepath, sizeof(typepath), "%s/%s/type",
                             NET_PATH, nde->d_name);
                    arphrd = _sysfs_read_int(typepath);
                    ifdescr = _arphrd_descr(arphrd);
                    if (arphrd == 1 /* ARPHRD_ETHER */) {
                        snprintf(typepath, sizeof(typepath), "%s/%s/wireless",
                                 NET_PATH, nde->d_name);
                        if (access(typepath, F_OK) == 0)
                            ifdescr = "Wireless interface";
                    }
                    strlcpy(e->descr, ifdescr ? ifdescr : nde->d_name,
                            sizeof(e->descr));
                }

                snprintf(path, sizeof(path), "%s/%s/address",
                         NET_PATH, nde->d_name);
                _sysfs_read(path, e->serial, sizeof(e->serial));

                snprintf(path, sizeof(path), "%s/%s/ifalias",
                         NET_PATH, nde->d_name);
                _sysfs_read(path, e->alias, sizeof(e->alias));

                snprintf(path, sizeof(path), "%s/%s/ifindex",
                         NET_PATH, nde->d_name);
                ifindex = _sysfs_read_int(path);
                if (ifindex > 0) {
                    e->ifindex = ifindex;
                    if (!e->alias[0])
                        snprintf(e->alias, sizeof(e->alias),
                                 "ifIndex.%d", ifindex);
                }

                _nic_scan_ethtool(e, nde->d_name, IDX_SFP_BASE + i);

                break;
            }
            closedir(netdir);
        }

free_bdf:
        free(bdfs[i]);
    }

    for (i = 0; i < nbdfs; i++) {
        int parent_idx;

        e = netsnmp_entity_get_byIdx(map[i].idx);
        if (!e)
            continue;
        parent_idx = _pci_find_parent_idx(map, nbdfs, i);
        if (!parent_idx && strncmp(map[i].bdf + 5, "00:", 3) == 0 &&
            strcmp(map[i].bdf + 8, "00.0") != 0) {
            char root_bdf[16];

            snprintf(root_bdf, sizeof(root_bdf), "%.4s:00:00.0", map[i].bdf);
            parent_idx = _pci_find_idx(map, nbdfs, root_bdf);
        }
        e->parent_idx = parent_idx ? parent_idx : IDX_BASEBOARD;
    }

#ifdef HAVE_PCI_LOOKUP_NAME
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

static int
_usb_iana_class(const char *name)
{
    char path[512], val[16];
    int cls;
    DIR *dir;
    struct dirent *de;

    /* Read bDeviceClass; 0x00 means class is defined per-interface */
    snprintf(path, sizeof(path), "%s/%s/bDeviceClass", USB_PATH, name);
    _sysfs_read(path, val, sizeof(val));
    cls = val[0] ? (int)strtol(val, NULL, 16) : -1;

    if (cls == 0x00) {
        /* Scan for the first interface entry and use its bInterfaceClass */
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
                        closedir(dir);
                        goto map;
                    }
                }
            }
            closedir(dir);
        }
    }

map:
    switch (cls) {
    case 0x08: return IANA_PHYS_STORAGE;    /* Mass Storage */
    case 0x09: return IANA_PHYS_CONTAINER;  /* Hub          */
    default:   return IANA_PHYS_OTHER;
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

        e->iana_class = IANA_PHYS_CONTAINER;
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

    while ((de = readdir(dir))) {
        netsnmp_entity_info *e;
        int idx, pci_idx;
        const char *name = de->d_name;
        char devname[128], speed[64], removable[64], key[128];

        if (name[0] == '.')
            continue;
        /* Skip interface entries (e.g. "1-6:1.0") */
        if (strchr(name, ':'))
            continue;
        /* Skip root hub entries (e.g. "usb1") — already represented by PCI */
        if (strncmp(name, "usb", 3) == 0)
            continue;

        snprintf(path, sizeof(path), "%s/%s", USB_PATH, name);
        if (!realpath(path, rp))
            continue;

        snprintf(key, sizeof(key), "usb:%s", name);
        idx = _entity_index_alloc(key);
        if (idx <= 0)
            continue;

        pci_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);

        e = netsnmp_entity_create(idx);
        if (!e)
            continue;

        e->iana_class = _usb_iana_class(name);
        e->is_fru     = TV_FALSE;
        e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;

        snprintf(path, sizeof(path), "%s/%s/uevent", USB_PATH, name);
        _sysfs_read_key(path, "DEVNAME", devname, sizeof(devname));
        strlcpy(e->name, devname[0] ? _strip_dev_prefix(devname) : name,
                sizeof(e->name));

        snprintf(path, sizeof(path), "%s/%s/speed", USB_PATH, name);
        _sysfs_read(path, speed, sizeof(speed));
        snprintf(path, sizeof(path), "%s/%s/removable", USB_PATH, name);
        _sysfs_read(path, removable, sizeof(removable));
        if (strcmp(removable, "removable") == 0)
            e->is_fru = TV_TRUE;
        if (speed[0])
            snprintf(e->descr, sizeof(e->descr), "USB %sdevice, %s Mbit/s",
                     e->is_fru == TV_TRUE ? "removable " : "", speed);
        else
            snprintf(e->descr, sizeof(e->descr), "USB %sdevice",
                     e->is_fru == TV_TRUE ? "removable " : "");

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
        int idx, pci_idx = 0;
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
                pci_idx = _pci_find_idx_by_path(pci_map, pci_map_n, rp);
                e->parent_idx = pci_idx ? pci_idx : IDX_BASEBOARD;
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
        _block_append_stable_key_uris(e, rp, p, key);
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

/* ---- Phase 6: hwmon chips and sensors ------------------------------------ */

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
_hwmon_parent_idx(const char *name)
{
    netsnmp_entity_info *parent;

    if (strcmp(name, "coretemp") == 0) {
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
    if (strcmp(name, "AC") == 0 || strcmp(name, "BAT0") == 0 ||
        strncmp(name, "ucsi_source_psy_", 16) == 0)
        return IANA_PHYS_POWERSUPPLY;
    return IANA_PHYS_MODULE;
}

static void
_load_hwmon(void)
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
        e->parent_idx = _hwmon_parent_idx(chips[ci].name);
        strlcpy(e->name,  chips[ci].dir, sizeof(e->name));
        strlcpy(e->descr, chips[ci].name, sizeof(e->descr));
        strlcpy(e->model_name, chips[ci].name, sizeof(e->model_name));
        snprintf(e->uris, sizeof(e->uris), "file://%s/%s",
                 HWMON_PATH, chips[ci].dir);

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
                snprintf(se->uris, sizeof(se->uris), "file://%s/%s/%s%d_input",
                         HWMON_PATH, chips[ci].dir, pfx, n);

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
_load_power_supply(void)
{
    DIR *dir;
    const struct dirent *de;
    char path[512];

    dir = opendir(PSY_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir))) {
        netsnmp_entity_info *e;
        char mfg[128], model[128], serial[64], tech[64], type[32];

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
        if (!e)
            continue;

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
_load_rtc(void)
{
    DIR *dir;
    struct dirent *de;
    char path[512], val[128];
    int idx = IDX_RTC_BASE;

    dir = opendir(RTC_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir)) != NULL) {
        netsnmp_entity_info *e;
        char *sp;

        if (strncmp(de->d_name, "rtc", 3) != 0 || !isdigit((unsigned char)de->d_name[3]))
            continue;

        e = netsnmp_entity_create(idx++);
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_MODULE;
        e->parent_idx = IDX_BASEBOARD;
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

        snprintf(e->uris, sizeof(e->uris), "file://%s/%s", RTC_PATH, de->d_name);
    }
    closedir(dir);
}

/* ---- Phase 10: UCD-DISKIO aliases ----------------------------------------- */

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

static uint32_t _saved_hash = 0;

static void
_read_entity_state(void)
{
    char path[512];
    unsigned int h = 0;
    unsigned long t = 0;
    FILE *f;

    snprintf(path, sizeof(path), "%s/%s",
             get_persistent_directory(), ENTITY_STATE_FILE);
    f = fopen(path, "r");
    if (!f)
        return;
    if (fscanf(f, "%x %lu", &h, &t) == 2) {
        _saved_hash        = (uint32_t)h;
        entity_last_change = (u_long)t;
    }
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
    fprintf(f, "%08x %lu\n", (unsigned)_saved_hash,
            (unsigned long)entity_last_change);
    fclose(f);
}

/* ---- Top-level load ------------------------------------------------------ */

int
netsnmp_entity_arch_load(netsnmp_cache *cache, void *magic)
{
    pci_entity_map *pci_map = NULL;
    int pci_map_n = 0;
    uint32_t hash_before, hash_after;
    static int first_load = 1;

    if (first_load) {
        _read_entity_state();
        hash_before = _saved_hash;
        first_load  = 0;
    } else {
        hash_before = _entity_list_hash();
    }
    netsnmp_entity_free_list();
    _entity_index_alloc_load();

    _load_dmi();
    _load_cpus();
    _load_caches();
    _load_dimms();
    _load_pci(&pci_map, &pci_map_n);
    _load_ata_ports(pci_map, pci_map_n);
    _load_usb(pci_map, pci_map_n);
    _load_scsi_disks(pci_map, pci_map_n);
    _load_nvme(pci_map, pci_map_n);
    _load_hwmon();
    _load_power_supply();
    _load_rtc();

    free(pci_map);
    netsnmp_entity_parent_rel_pos_rebuild();
    netsnmp_entity_contains_rebuild();
    netsnmp_entity_logical_load();
    netsnmp_entity_alias_rebuild();
    _alias_diskio();
    _alias_lm_sensors();
    netsnmp_entity_alias_sort();

    hash_after = _entity_list_hash();
    if (hash_after != hash_before) {
        entity_last_change = (u_long)time(NULL);
        _saved_hash        = hash_after;
        _write_entity_state();
    }
    if (hash_after != hash_before || _idx_alloc_dirty)
        _entity_indexes_write();

    return 0;
}

void init_entity_linux(void)
{
}
