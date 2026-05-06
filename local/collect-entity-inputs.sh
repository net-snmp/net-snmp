#!/bin/sh

# Collect raw Linux hardware inventory inputs for ENTITY-MIB parser design.
# Run with sudo for complete DMI and dmidecode output.

set -u

section()
{
    printf '\n===== %s =====\n' "$1"
}

section_file()
{
    file=$1
    title=$2

    exec > "$OUTDIR/$file"
    section "$title"
}

read_file()
{
    file=$1
    [ -r "$file" ] || return 0
    value=$(sed -n '1{s/[[:cntrl:]]/ /g;p;q;}' "$file" 2>/dev/null) || return 0
    printf '%s=%s\n' "$file" "$value"
}

read_dir_files()
{
    dir=$1
    [ -d "$dir" ] || return 0

    for file in "$dir"/*; do
        [ -f "$file" ] || continue
        read_file "$file"
    done
}

read_link()
{
    path=$1
    [ -e "$path" ] || return 0
    target=$(readlink "$path" 2>/dev/null || true)
    [ -n "$target" ] && printf '%s -> %s\n' "$path" "$target"
}

OUTDIR=${1:-entity-inputs-$(date -u '+%Y%m%dT%H%M%SZ' 2>/dev/null || printf unknown)}
mkdir -p "$OUTDIR"

exec 3>&1

{
    printf '# ENTITY-MIB hardware input collection\n'
    printf '# output_dir=%s\n' "$OUTDIR"
    printf '# host=%s\n' "$(hostname 2>/dev/null || printf unknown)"
    printf '# kernel=%s\n' "$(uname -a 2>/dev/null || printf unknown)"
    printf '# date=%s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || printf unknown)"

    if [ "$(id -u)" -ne 0 ]; then
        printf '# warning=not running as root; dmidecode and some DMI fields may be missing\n'
    fi

    printf '\n# files\n'
    printf 'dmi.txt\n'
    printf 'cpuinfo.txt\n'
    printf 'memory-dmidecode.txt\n'
    printf 'pci-sysfs.txt\n'
    printf 'network-sysfs.txt\n'
    printf 'network-proc-dev.txt\n'
    printf 'network-proc-if-inet6.txt\n'
    printf 'network-ip-link.txt\n'
    printf 'network-ip-address.txt\n'
    printf 'nvme-sysfs.txt\n'
    printf 'nvme-block-sysfs.txt\n'
    printf 'sensors-hwmon.txt\n'
    printf 'block-sysfs.txt\n'
    printf 'reference-lsblk.txt\n'
    printf 'reference-lspci.txt\n'
    printf 'reference-lshw.txt\n'
} > "$OUTDIR/manifest.txt"

if [ "$(id -u)" -ne 0 ]; then
    printf 'warning: not running as root; dmidecode and some DMI fields may be missing\n' >&3
fi

section_file "dmi.txt" "DMI /sys/class/dmi/id"
read_dir_files /sys/class/dmi/id

section_file "cpuinfo.txt" "CPU /proc/cpuinfo"
if [ -r /proc/cpuinfo ]; then
    awk '
        /^processor[[:space:]]*:/ ||
        /^physical id[[:space:]]*:/ ||
        /^core id[[:space:]]*:/ ||
        /^cpu cores[[:space:]]*:/ ||
        /^model name[[:space:]]*:/ ||
        /^vendor_id[[:space:]]*:/ { print }
        /^$/ { print "" }
    ' /proc/cpuinfo
fi

section_file "memory-dmidecode.txt" "Memory dmidecode -t memory"
if command -v dmidecode >/dev/null 2>&1; then
    dmidecode -t memory 2>&1
else
    printf 'dmidecode: not found\n'
fi

section_file "pci-sysfs.txt" "PCI /sys/bus/pci/devices"
for dev in /sys/bus/pci/devices/*; do
    [ -d "$dev" ] || continue
    printf '\n[%s]\n' "$(basename "$dev")"
    for name in class vendor device subsystem_vendor subsystem_device revision irq numa_node driver_override; do
        read_file "$dev/$name"
    done
    read_link "$dev/driver"
    read_link "$dev/iommu_group"
    if [ -d "$dev/net" ]; then
        printf 'net_children='
        first=1
        for iface in "$dev"/net/*; do
            [ -e "$iface" ] || continue
            if [ "$first" -eq 0 ]; then
                printf ','
            fi
            first=0
            printf '%s' "$(basename "$iface")"
        done
        printf '\n'
    fi
done

section_file "network-sysfs.txt" "Network /sys/class/net"
for iface in /sys/class/net/*; do
    [ -d "$iface" ] || continue
    printf '\n[%s]\n' "$(basename "$iface")"
    for name in address addr_assign_type addr_len broadcast carrier dormant duplex flags ifalias ifindex iflink link_mode mtu name_assign_type operstate phys_port_id phys_port_name phys_switch_id proto_down speed testing type; do
        read_file "$iface/$name"
    done
    read_dir_files "$iface/statistics"
    read_link "$iface/device"
done

section_file "network-proc-dev.txt" "Network /proc/net/dev"
if [ -r /proc/net/dev ]; then
    sed -n '1,$p' /proc/net/dev
fi

section_file "network-proc-if-inet6.txt" "Network /proc/net/if_inet6"
if [ -r /proc/net/if_inet6 ]; then
    sed -n '1,$p' /proc/net/if_inet6
fi

section_file "network-ip-link.txt" "Network ip -details link"
if command -v ip >/dev/null 2>&1; then
    ip -details link show 2>&1
else
    printf 'ip: not found\n'
fi

section_file "network-ip-address.txt" "Network ip address"
if command -v ip >/dev/null 2>&1; then
    ip address show 2>&1
else
    printf 'ip: not found\n'
fi

section_file "nvme-sysfs.txt" "NVMe /sys/class/nvme"
for nvme in /sys/class/nvme/*; do
    [ -d "$nvme" ] || continue
    printf '\n[%s]\n' "$(basename "$nvme")"
    for name in model serial firmware_rev cntlid state address; do
        read_file "$nvme/$name"
    done
    read_link "$nvme/device"
done

section_file "nvme-block-sysfs.txt" "NVMe block /sys/block/nvme*"
for block in /sys/block/nvme*; do
    [ -d "$block" ] || continue
    printf '\n[%s]\n' "$(basename "$block")"
    for name in size removable ro queue/logical_block_size queue/physical_block_size queue/rotational device/model device/serial device/firmware_rev; do
        read_file "$block/$name"
    done
    read_link "$block/device"
done

section_file "sensors-hwmon.txt" "Sensors /sys/class/hwmon"
for hwmon in /sys/class/hwmon/hwmon*; do
    [ -d "$hwmon" ] || continue
    printf '\n[%s]\n' "$(basename "$hwmon")"
    read_file "$hwmon/name"
    read_link "$hwmon/device"
    for sensor in "$hwmon"/temp*_input "$hwmon"/temp*_label "$hwmon"/fan*_input "$hwmon"/fan*_label "$hwmon"/in*_input "$hwmon"/in*_label; do
        [ -f "$sensor" ] || continue
        read_file "$sensor"
    done
done

section_file "block-sysfs.txt" "Block devices /sys/block"
for block in /sys/block/*; do
    [ -d "$block" ] || continue
    case "$(basename "$block")" in
        loop*|ram*) continue ;;
    esac
    printf '\n[%s]\n' "$(basename "$block")"
    for name in size removable ro queue/logical_block_size queue/physical_block_size queue/rotational device/model device/vendor device/rev device/serial; do
        read_file "$block/$name"
    done
    read_link "$block/device"
done

section_file "reference-lsblk.txt" "Reference lsblk"
if command -v lsblk >/dev/null 2>&1; then
    lsblk -O 2>&1
else
    printf 'lsblk: not found\n'
fi

section_file "reference-lspci.txt" "Reference lspci"
if command -v lspci >/dev/null 2>&1; then
    lspci -D -nn -vv 2>&1
else
    printf 'lspci: not found\n'
fi

section_file "reference-lshw.txt" "Reference lshw"
if command -v lshw >/dev/null 2>&1; then
    lshw -sanitize 2>&1
else
    printf 'lshw: not found\n'
fi

exec >&3
printf 'wrote ENTITY-MIB input files to %s\n' "$OUTDIR"
