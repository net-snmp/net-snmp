# ENTITY-MIB Hardware Module

This module implements the hardware-backed parts of ENTITY-MIB under
`1.3.6.1.2.1.47`.

It maintains one cached list of physical entities and uses that list to serve:

- `entPhysicalTable`
- `entPhysicalContainsTable`
- `entLogicalTable`
- `entAliasMappingTable`
- `entLastChangeTime`

## Data Model

Physical rows are represented by `netsnmp_entity_info` in `entity.h`.

Important fields:

- `idx`: `entPhysicalIndex`
- `parent_idx`: parent `entPhysicalIndex`
- `parent_rel_pos`: position among siblings of the same physical class
- `iana_class`: `IANAPhysicalClass`
- `ifindex`: mapped IF-MIB `ifIndex`, when known
- `name`, `descr`, `mfg_name`, `model_name`, `serial`: display metadata
- `uris`: stable URI used to identify the entity outside SNMP

The list is kept sorted by `idx` by `netsnmp_entity_create()`.

## Linux Index Allocation

Linux data collection lives in `data_access/entity_linux.c`.

Fixed index ranges are used for broad device classes:

- `1`: chassis
- `10`: baseboard
- `20`: BIOS
- `100`: memory container
- `110+`: DIMMs
- `200+`: CPUs
- `300+`: CPU caches
- `1000+`: PCI devices
- `2000+`: SCSI/SATA disks and optical drives
- `2200+`: USB devices
- `2400+`: RTC devices
- `3000+`: standalone NVMe devices
- `4000+`: hwmon chips and sensors
- `10000+`: SFP modules

SCSI/SATA block devices are not ordered by `/dev/sdX` name. The loader resolves
`/sys/block/<name>/device`, takes the SCSI HCTL basename such as `0:0:0:0`, and
hashes that string into the `2000+` range. This keeps indexes more stable across
Linux block-name changes.

## Cache Loading

`init_entity()` creates a `netsnmp_cache` for the ENTITY-MIB subtree. Table
handlers call `netsnmp_cache_check_and_reload(netsnmp_entity_get_cache())`
before walking data.

On Linux, `netsnmp_entity_arch_load()` rebuilds the physical list, contains
rows, logical rows, and alias rows. It also computes a hash of the loaded entity
data. If the hash changed, it updates `entLastChangeTime` and writes persistent
state.

Persistent state file:

```text
<persistentDir>/entity_state
```

## Lookup Helpers

Compiled MIB modules can use these helpers from `entity.h`:

```c
netsnmp_entity_info *netsnmp_entity_get_by_uri(const char *uri);
netsnmp_entity_info *netsnmp_entity_get_byIfIndex(int ifindex);
int                  netsnmp_entity_get_idx_by_uri(const char *uri);
int                  netsnmp_entity_get_idx_byIfIndex(int ifindex);
```

The URI and ifIndex helpers reload the entity cache before searching. They
return `NULL` or `0` if no matching entity exists.

Example:

```c
int phys_idx;

phys_idx = netsnmp_entity_get_idx_by_uri("file:///sys/block/sda");
if (phys_idx > 0) {
    /* phys_idx is the matching entPhysicalIndex */
}
```

## External Agent Lookup File

External agents, such as Python AgentX or pass-persist helpers, cannot call the
in-process C lookup helpers. For those agents, the Linux loader writes a local
mapping file when the entity hash changes:

```text
<persistentDir>/entity_indexes
```

The file is tab-separated:

```text
<index>\t<uri>\t<name>\t<vendor>\t<model>\t<descr>
```

Example:

```text
2029	file:///sys/block/sda	sda	ATA	SAMSUNG MZ7LH960	Solid-state disk (894.3GiB)
```

Python example:

```python
def find_entity_index(uri, path="/var/lib/net-snmp/entity_indexes"):
    with open(path, encoding="utf-8") as f:
        for line in f:
            idx, uris, name, vendor, model, descr = line.rstrip("\n").split("\t", 5)
            if uri in uris.split():
                return int(idx)
    return None
```

The file is written through a temporary file and `rename()` so readers see a
complete file.

## URI Convention

`entPhysicalUris` is the common key between SNMP and external agents. Multiple
URIs may be present in one row and are separated by whitespace, as defined by
ENTITY-MIB. Current Linux rows primarily use `file://` URIs pointing at sysfs
paths, for example:

- `file:///sys/block/sda`
- `file:///sys/bus/usb/devices/1-2`
- `file:///sys/class/nvme/nvme0`
- `file:///sys/class/hwmon/hwmon0/temp1_input`

Block devices also include alternative device-node URIs when available, for
example:

- `file:///dev/sda`
- `file:///dev/disk/by-id/ata-SAMSUNG_MZ7LH960...`

NVMe controller rows also include controller and namespace paths when available,
for example:

- `file:///dev/nvme0`
- `file:///sys/block/nvme0n1`
- `file:///dev/nvme0n1`
- `file:///dev/disk/by-id/nvme-Samsung_SSD...`

USB rows also include device-node and identity URIs when available, for example:

- `file:///dev/bus/usb/001/006`
- `usb://001/006`
- `usb:v046dp0825:SERIAL`

USB `entPhysicalName` uses the kernel `DEVNAME` value from the device `uevent`
file, such as `bus/usb/001/006`, when present. USB descriptions include link
speed when available, and devices with `removable` set to `removable` are marked
as FRUs.

External agents should use the same URI string when looking up an
`entPhysicalIndex`.
