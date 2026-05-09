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
- `200000+`: dynamically allocated SCSI/SATA, USB, and standalone NVMe devices
- `2400+`: RTC devices
- `4000+`: hwmon chips and sensors
- `10000+`: SFP modules

USB devices, SCSI/SATA block devices, and standalone NVMe devices use a
persistent dynamic allocator starting at `200000`. The allocator stores a
stable device key and full entity metadata in:

```text
<persistentDir>/entity_indexes
```

The file is tab-separated with seven columns:

```text
idx  key  uris  name  mfg_name  model_name  descr
```

- **idx** — `entPhysicalIndex`
- **key** — stable allocation key for dynamic devices (`eui.0025385b41447ba9`,
  `wwn-0x5000c5004b3e9e3b`, `usb:1-12`, …). Empty for static and PCI-backed devices.
- **uris** — space-separated URI list
- **name**, **mfg_name**, **model_name**, **descr** — entity metadata

Example:

```text
200000	eui.0025385b41447ba9	nvme:nvme0 file:///dev/nvme0	nvme0	Samsung	990EVO	NVMe Controller
200001	wwn-0x5000c5004b3e9e3b	file:///dev/sda	sda	WDC	WD10EZEX	Hard disk, 1000 GB
200002	usb:1-12	usb:1-12 file:///dev/bus/usb/001/012	usb1	Logitech	M100	USB Mouse
1000		pci:01:00.0	eth0	Intel	82599ES	Intel Ethernet Controller
```

Lines with a non-empty key are read back on startup to restore dynamic index
assignments. Lines with an empty key are static/PCI entities included for
external reference only.

Missing devices stay in the file as ghost entries (key and idx, empty
metadata) so reinserted devices keep their indexes. Delete the file to reset
all dynamic indexes, or delete selected lines to free selected mappings.

SCSI/SATA keys prefer the physical ATA port when the sysfs path contains one,
for example `/ata5/...` becomes `ata:5`. The SCSI HCTL basename, such as
`scsi:4:0:0:0`, is used as a fallback and is also exposed as an alternate URI.

The agent also writes:

```text
<persistentDir>/entity_state
```

which stores the last entity-list hash and `entLastChangeTime` timestamp across
restarts.

## Cache Loading

`init_entity()` creates a `netsnmp_cache` for the ENTITY-MIB subtree. Table
handlers call `netsnmp_cache_check_and_reload(netsnmp_entity_get_cache())`
before walking data.

On Linux, `netsnmp_entity_arch_load()` rebuilds the physical list, contains
rows, logical rows, and alias rows. It also computes a hash of the loaded entity
data. If the hash changed, it updates `entLastChangeTime` and writes persistent
state.

## Linux Discovery Model

Linux discovery treats `/sys/devices` realpaths as the hardware topology source.
Bus and class directories are used as views onto that topology:

- PCI devices are discovered from `/sys/bus/pci/devices` and form the parent map.
- PCI network functions use a slot-level key, `pcislot:<domain:bus:device>`, so
  multi-function NICs appear as one adapter/module.
- Network ports are emitted from `/sys/class/net` and parented to the matching
  PCI adapter through the class device realpath.
- PTP clocks, hwmon chips, power supplies, GPIO controllers, I2C buses, graphics
  devices, TPMs, and RTCs also parent through PCI realpath matching when their
  sysfs topology exposes a PCI ancestor.
- USB, block devices, and input devices intentionally keep their existing
  discovery paths for now.

Useful validation commands while changing Linux discovery:

```sh
make agent/mibgroup/hardware/entity/data_access/entity_linux.lo
make -f entity_subagent.mk entity_subagent
```

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
- `scsi:0:0:0:0`

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
