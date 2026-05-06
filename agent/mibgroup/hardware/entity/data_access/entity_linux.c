#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include "../entity.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>

#define DMI_PATH    "/sys/class/dmi/id"
#define PCI_PATH    "/sys/bus/pci/devices"
#define NET_PATH    "/sys/class/net"
#define NVME_PATH   "/sys/class/nvme"
#define BLOCK_PATH  "/sys/block"
#define HWMON_PATH  "/sys/class/hwmon"
#define PSY_PATH    "/sys/class/power_supply"

#define IDX_CHASSIS      1
#define IDX_BASEBOARD   10
#define IDX_BIOS        20
#define IDX_MEMORY     100
#define IDX_DIMM_BASE  110
#define IDX_CPU_BASE    200
#define IDX_CACHE_BASE  300   /* 10 slots per CPU package: 300-309, 310-319, … */
#define IDX_PCI_BASE   1000
#define IDX_NVME_BASE  3000
#define IDX_SENSOR_BASE 4000

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
    _dmi_field("sys_vendor",     e->mfg_name,   sizeof(e->mfg_name));
    _dmi_field("product_name",   e->model_name, sizeof(e->model_name));
    _dmi_field("product_serial", e->serial,     sizeof(e->serial));
    _dmi_field("product_version",e->hw_rev,     sizeof(e->hw_rev));
    _dmi_field("product_uuid", val, sizeof(val));
    if (_parse_uuid(val, e->uuid))
        e->uuid_len = 16;
    if (e->model_name[0])
        strlcpy(e->descr, e->model_name, sizeof(e->descr));

    e = netsnmp_entity_create(IDX_BASEBOARD);
    if (!e) return;
    e->iana_class = IANA_PHYS_MODULE;
    e->parent_idx = IDX_CHASSIS;
    e->is_fru     = TV_TRUE;
    strlcpy(e->name,  "baseboard", sizeof(e->name));
    strlcpy(e->descr, "Baseboard", sizeof(e->descr));
    _dmi_field("board_vendor",  e->mfg_name,   sizeof(e->mfg_name));
    _dmi_field("board_name",    e->model_name, sizeof(e->model_name));
    _dmi_field("board_serial",  e->serial,     sizeof(e->serial));
    _dmi_field("board_version", e->hw_rev,     sizeof(e->hw_rev));
    if (e->model_name[0])
        strlcpy(e->descr, e->model_name, sizeof(e->descr));

    e = netsnmp_entity_create(IDX_BIOS);
    if (!e) return;
    e->iana_class = IANA_PHYS_OTHER;
    e->parent_idx = IDX_BASEBOARD;
    strlcpy(e->name,  "bios", sizeof(e->name));
    strlcpy(e->descr, "BIOS", sizeof(e->descr));
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
            _set_if_valid(e->hw_rev, sizeof(e->hw_rev), value);
        }
    }
    pclose(fp);
}

/* ---- Phase 4: CPU caches ------------------------------------------------- */

static void
_load_caches(void)
{
    DIR *cpu_dir, *cache_dir;
    struct dirent *cpu_de, *cache_de;
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

    for (i = 0; i < nbdfs; i++) {
        long class_val;
        int  idx;
        DIR *netdir;
        struct dirent *nde;

        class_val = 0;
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

        snprintf(path, sizeof(path), "%s/%s/class", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0]) {
            class_val = strtol(val, NULL, 16);
            e->iana_class = _pci_class_to_iana(class_val);
        }

        snprintf(path, sizeof(path), "%s/%s/vendor", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            strlcpy(e->mfg_name, val, sizeof(e->mfg_name));

        snprintf(path, sizeof(path), "%s/%s/device", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            strlcpy(e->model_name, val, sizeof(e->model_name));

        snprintf(path, sizeof(path), "%s/%s/subsystem_vendor", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0]) {
            char subdev[32] = "";
            char tmp[64];
            snprintf(path, sizeof(path), "%s/%s/subsystem_device", PCI_PATH, bdfs[i]);
            _sysfs_read(path, subdev, sizeof(subdev));
            if (subdev[0])
                snprintf(tmp, sizeof(tmp), "%s:%s", val, subdev);
            else
                strlcpy(tmp, val, sizeof(tmp));
            strlcpy(e->sw_rev, tmp, sizeof(e->sw_rev));
        }

        snprintf(path, sizeof(path), "%s/%s/revision", PCI_PATH, bdfs[i]);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            strlcpy(e->hw_rev, val, sizeof(e->hw_rev));

        {
            char link[512];
            ssize_t llen;
            snprintf(path, sizeof(path), "%s/%s/driver", PCI_PATH, bdfs[i]);
            llen = readlink(path, link, sizeof(link) - 1);
            if (llen > 0) {
                char *drv;
                link[llen] = '\0';
                drv = strrchr(link, '/');
                strlcpy(e->descr, drv ? drv + 1 : link, sizeof(e->descr));
            } else {
                const char *cls_descr = _pci_class_descr(class_val);
                if (cls_descr)
                    strlcpy(e->descr, cls_descr, sizeof(e->descr));
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
                strlcpy(e->descr, nde->d_name, sizeof(e->descr));

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

    *map_out = map;
    *nmap_out = nbdfs;
    free(bdfs);
    return;

free_bdfs:
    for (i = 0; i < nbdfs; i++)
        free(bdfs[i]);
    free(bdfs);
}

/* ---- Phase 5: NVMe controllers and namespaces ---------------------------- */

static void
_load_nvme(int *next_nvme_idx, pci_entity_map *pci_map, int pci_map_n)
{
    DIR *dir;
    struct dirent *de;
    char path[512], val[256];

    dir = opendir(NVME_PATH);
    if (!dir)
        return;

    while ((de = readdir(dir))) {
        netsnmp_entity_info *e;
        int idx, pci_idx, ns_base;

        if (de->d_name[0] == '.')
            continue;

        snprintf(path, sizeof(path), "%s/%s/address", NVME_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        pci_idx = val[0] ? _pci_find_idx(pci_map, pci_map_n, val) : 0;

        ns_base = (*next_nvme_idx)++;
        if (pci_idx) {
            e = netsnmp_entity_get_byIdx(pci_idx);
            idx = pci_idx;
        } else {
            idx = IDX_NVME_BASE + ns_base;
            e = netsnmp_entity_create(idx);
        }
        if (!e)
            continue;

        e->iana_class = IANA_PHYS_MODULE;
        e->is_fru     = TV_FALSE;
        strlcpy(e->name,  de->d_name, sizeof(e->name));
        strlcpy(e->descr, de->d_name, sizeof(e->descr));
        if (!e->parent_idx)
            e->parent_idx = IDX_BASEBOARD;

        snprintf(path, sizeof(path), "%s/%s/model", NVME_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _trim_trailing(val);
        _set_if_valid(e->model_name, sizeof(e->model_name), val);
        if (val[0])
            strlcpy(e->descr, val, sizeof(e->descr));

        snprintf(path, sizeof(path), "%s/%s/serial", NVME_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _trim_trailing(val);
        _set_if_valid(e->serial, sizeof(e->serial), val);

        snprintf(path, sizeof(path), "%s/%s/firmware_rev",
                 NVME_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        _set_if_valid(e->fw_rev, sizeof(e->fw_rev), val);

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
_load_hwmon(int *next_hwmon_idx)
{
    static const char *prefixes[] = { "temp", "fan", "in", NULL };
    DIR *dir;
    struct dirent *de;
    char path[512];
    hwmon_entry *chips, *tmp;
    int  pi, chip_count, chip_cap, ci;

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
        int chip_idx, sensor_seq, n;

        chip_idx = (*next_hwmon_idx)++;
        e = netsnmp_entity_create(IDX_SENSOR_BASE + chip_idx * 20);
        if (!e)
            continue;

        e->iana_class = _hwmon_class(chips[ci].name);
        e->parent_idx = _hwmon_parent_idx(chips[ci].name);
        strlcpy(e->name,  chips[ci].dir, sizeof(e->name));
        strlcpy(e->descr, chips[ci].name, sizeof(e->descr));
        strlcpy(e->model_name, chips[ci].name, sizeof(e->model_name));

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

                snprintf(sensor_name, sizeof(sensor_name), "%s%d", pfx, n);
                se = netsnmp_entity_create(IDX_SENSOR_BASE +
                                           chip_idx * 20 + sensor_seq);
                sensor_seq++;
                if (!se) continue;

                se->iana_class = IANA_PHYS_SENSOR;
                se->parent_idx = IDX_SENSOR_BASE + chip_idx * 20;
                strlcpy(se->name,  sensor_name, sizeof(se->name));
                strlcpy(se->descr, sensor_name, sizeof(se->descr));

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
    struct dirent *de;
    char path[512], val[256];

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
        if (model[0]) {
            strlcpy(e->model_name, model, sizeof(e->model_name));
            strlcpy(e->descr,      model, sizeof(e->descr));
        }
        if (serial[0])
            strlcpy(e->serial, serial, sizeof(e->serial));

        if (tech[0] && model[0])
            snprintf(e->descr, sizeof(e->descr), "%s (%s)", model, tech);
        else if (tech[0])
            strlcpy(e->descr, tech, sizeof(e->descr));

        snprintf(path, sizeof(path), "%s/%s/capacity", PSY_PATH, de->d_name);
        _sysfs_read(path, val, sizeof(val));
        if (val[0])
            snprintf(e->alias, sizeof(e->alias), "capacity:%s%%", val);
    }
    closedir(dir);
}

/* ---- Top-level load ------------------------------------------------------ */

int
netsnmp_entity_arch_load(netsnmp_cache *cache, void *magic)
{
    int nvme_seq  = 0;
    int hwmon_seq = 0;
    pci_entity_map *pci_map = NULL;
    int pci_map_n = 0;

    netsnmp_entity_free_list();

    _load_dmi();
    _load_cpus();
    _load_caches();
    _load_dimms();
    _load_pci(&pci_map, &pci_map_n);
    _load_nvme(&nvme_seq, pci_map, pci_map_n);
    _load_hwmon(&hwmon_seq);
    _load_power_supply();

    free(pci_map);
    netsnmp_entity_parent_rel_pos_rebuild();
    netsnmp_entity_contains_rebuild();
    netsnmp_entity_alias_rebuild();
    entity_last_change = netsnmp_get_agent_uptime();
    return 0;
}

void init_entity_linux(void)
{
    /* Nothing: netsnmp_entity_arch_load() is called by the cache */
}
