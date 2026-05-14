# ENTITY-MIB Hardware Module

This module implements the hardware-backed parts of ENTITY-MIB under
`1.3.6.1.2.1.47`.

It maintains one cached list of physical entities and uses that list to serve:

- `entPhysicalTable`
- `entPhysicalContainsTable`
- `entLogicalTable`
- `entAliasMappingTable`
- `entLastChangeTime`

Current limitations:

- `entPhysicalAlias` and `entPhysicalAssetID` are exposed as read-only values.
  ENTITY-MIB defines these columns as writable, but SET handling and persistence
  for operator-provided values are not implemented yet.
- `entLogicalTAddress` and `entLogicalTDomain` do not try to infer a listening
  transport endpoint. The module reports an empty address and `zeroDotZero`
  domain instead of publishing a guessed UDP/161 endpoint that may be wrong for
  AgentX, random test ports, IPv6, TCP, or multi-homed agents.

## Configuration

The module supports this `snmpd.conf` token:

```text
entitySensitiveData yes|no
```

The default is `yes`, preserving the full ENTITY-MIB view. Set it to `no` to
return empty values for potentially identifying fields exposed through SNMP:
`entPhysicalSerialNum`, `entPhysicalAlias`, `entPhysicalAssetID`,
`entPhysicalUris`, and `entPhysicalUUID`.

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
- `100`: memory container
- `110+`: DIMMs
- `200+`: CPUs
- `300+`: CPU caches
- `1000+`: PCI devices
- `200000+`: dynamically allocated SCSI/SATA, USB, and standalone NVMe devices
- `2400+`: RTC devices
- `2500+`: ACPI system, ACPI buses, and ACPI thermal zones
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

which stores the last entity-list hash across restarts. `entLastChangeTime` is a
`sysUpTime` TimeStamp and is not persisted because `sysUpTime` resets when the
agent restarts.

## Cache Loading

`init_entity()` creates a `netsnmp_cache` for the ENTITY-MIB subtree. Table
handlers call `netsnmp_cache_check_and_reload(netsnmp_entity_get_cache())`
before walking data.

On Linux, `netsnmp_entity_arch_load()` rebuilds the physical list, contains
rows, logical rows, and alias rows. It also computes a hash of the loaded entity
data. If the hash changed, it updates `entLastChangeTime` to the current
`sysUpTime` and writes persistent state.

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

## Performance

### Cache lifetime

The entity list is rebuilt by `netsnmp_entity_arch_load()` and held in a cache
with a 300-second (5-minute) lifetime. `NETSNMP_CACHE_AUTO_RELOAD` keeps the
cache warm by triggering a background reload before it expires, so SNMP queries
never block waiting for a cold rebuild.

### Phase timing

Each load phase is timed and logged. At `LOG_INFO` level (normal operation)
only the elapsed time is shown:

```
entity: phase dmi                              85 µs
entity: phase cpu_memory_topology            2167 µs
entity: phase pci                          488872 µs
entity: phase platform                      47326 µs
...
entity: arch_load complete: 554000 µs, 184 entities
```

With the entity debug token enabled (`-Dentity`), `LOG_DEBUG` output adds
entity count delta and heap growth per phase:

```
entity: phase dmi                              85 µs  +  2 entities  heap +2752 B
entity: phase cpu_memory_topology            2167 µs  + 16 entities  heap +22320 B
entity: phase pci                          488872 µs  + 30 entities  heap +176224 B
entity: phase platform                      47326 µs  + 74 entities  heap +638944 B
...
entity: arch_load complete: 554000 µs, 184 entities
```

### Cost centres

The `pci` phase dominates on most hardware. It reads `current_link_speed` and
`current_link_width` from sysfs for every PCI device to include link
information in the entity description. These reads are not simple file reads —
they trigger PCIe config-space accesses through the kernel. On some platforms
bridge devices (class `0x06`) and uncore devices (class `0xff`) each cost
10–350 ms, adding up to several hundred milliseconds for a system with many PCI
devices. On the example laptop above, the `pci` phase accounts for ~88 % of
total load time.

The `platform` phase scales with the number of platform devices. Each device
requires a sysfs uevent read; the phase uses a single-pass scan so every path
is opened at most once.

All other phases — `cpu_memory_topology`, `usb`, `hwmon`, `i2c`, and the rest
— are in the low single-digit millisecond range on all tested hardware.
`cpu_memory_topology` includes a `dmidecode -t memory` call for DIMM detection,
which typically adds 1–2 ms.

The PCI phase builds a sorted map of all PCI devices that is shared across the
rest of the load. Subsequent phases (`net_devices`, `hwmon`, `power_supply`,
etc.) use O(1) path-length lookup into that map to find a PCI parent without
re-scanning the PCI directory.

## Permissions

On Linux, `snmpd` typically runs as root, and the module assumes that where
necessary. Some data sources require elevated privileges:

**DIMM information (`entPhysicalTable` rows 110+)** is collected by running
`dmidecode -t memory`. `dmidecode` reads SMBIOS tables, which are exposed at
`/sys/firmware/dmi/tables/DMI`. That file is owned by root with mode `400` on
most distributions and recent kernels. Without read access to it, `dmidecode`
returns no output, the DIMM scan produces an empty list, and no DIMM rows are
added to the entity table.

To restore DIMM detection when `snmpd` runs as a non-root user:

```sh
# Option 1 – grant snmpd the capability to read root-owned files
sudo setcap cap_dac_read_search+ep /usr/sbin/snmpd

# Option 2 – make the DMI tables readable by all users (reset on reboot)
sudo chmod a+r /sys/firmware/dmi/tables/DMI /sys/firmware/dmi/tables/smbios_entry_point

# Option 3 – run snmpd as root (standard for production deployments)
```

All other data sources used by this module (`/sys/bus/pci`, `/sys/class/net`,
`/proc/cpuinfo`, sysfs hwmon, etc.) are readable without root.

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
